"""Find last-updated dates, newest news, and stale content."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, timedelta
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from watson.models import OWNER_EDITOR, UpdateRow

MONTHS = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}

_MONTH = (
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
    r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|"
    r"Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
)
DAY_MONTH_YEAR = re.compile(rf"\b(\d{{1,2}})\s+({_MONTH})\s+(20\d{{2}})\b", re.IGNORECASE)
MONTH_DAY_YEAR = re.compile(rf"\b({_MONTH})\s+(\d{{1,2}}),?\s+(20\d{{2}})\b", re.IGNORECASE)
ISO_DATE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")
COPYRIGHT_RE = re.compile(
    r"(?:©|\(c\)|copyright)\s*((?:20\d{2}\s*[-–—]\s*)*)(20\d{2})",
    re.IGNORECASE,
)
FILENAME_DATE = re.compile(r"(20\d{2})[-_](\d{2})[-_](\d{2})")
NEWSLETTER_HINT = re.compile(r"newsletter|gazette|bulletin|newsflash|e-?news", re.IGNORECASE)
NEWS_HINT = re.compile(r"\bnews\b", re.IGNORECASE)
PAST_CONTEXT = re.compile(r"past|archive|previous|historical", re.IGNORECASE)
PROMOTED_CONTEXT = re.compile(
    r"upcoming|event|what'?s on|featured|promot|don'?t miss",
    re.IGNORECASE,
)
LAST_UPDATED = re.compile(r"last\s+updated(?:\s+on)?|updated\s+on|date\s+modified", re.IGNORECASE)
CALENDAR_HINT = re.compile(r"calendar", re.IGNORECASE)


@dataclass
class FreshnessRules:
    newsletter_stale_weeks: int = 8
    copyright_grace_years: int = 0
    calendar_grace_days: int = 31


@dataclass
class FreshnessReport:
    rows: list[UpdateRow]
    newest_newsletter: str
    newest_news: str
    newest_event: str


def _safe_date(year: int, month: int, day: int) -> date | None:
    try:
        return date(year, month, day)
    except ValueError:
        return None


def _month_number(name: str) -> int | None:
    return MONTHS.get(name.lower())


def parse_dates(text: str) -> list[date]:
    """Pull concrete dates out of visible text. Invalid dates are skipped."""
    found: list[date] = []
    for year, month, day in ISO_DATE.findall(text or ""):
        parsed = _safe_date(int(year), int(month), int(day))
        if parsed:
            found.append(parsed)
    for day, month_name, year in DAY_MONTH_YEAR.findall(text or ""):
        month = _month_number(month_name)
        if month:
            parsed = _safe_date(int(year), month, int(day))
            if parsed:
                found.append(parsed)
    for month_name, day, year in MONTH_DAY_YEAR.findall(text or ""):
        month = _month_number(month_name)
        if month:
            parsed = _safe_date(int(year), month, int(day))
            if parsed:
                found.append(parsed)
    return found


def parse_datetime_attr(value: str) -> date | None:
    if not value:
        return None
    match = ISO_DATE.search(value)
    if match:
        parsed = _safe_date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        if parsed:
            return parsed
    dates = parse_dates(value)
    return dates[0] if dates else None


def is_past_calendar_year(year: int, today: date, grace_days: int = 31) -> bool:
    """True when a calendar year is already out of date.

    During the first `grace_days` of January, the previous calendar year is
    still accepted.
    """
    if year >= today.year:
        return False
    if year == today.year - 1 and today.timetuple().tm_yday <= max(grace_days, 0):
        return False
    return True


def _filename_date(url: str) -> date | None:
    match = FILENAME_DATE.search(urlparse(url).path)
    if not match:
        return None
    return _safe_date(int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _dates_in(element) -> list[date]:
    dated: list[date] = []
    for node in element.find_all("time"):
        parsed = parse_datetime_attr(node.get("datetime") or "")
        if parsed is None:
            parsed_dates = parse_dates(node.get_text(" ", strip=True))
            parsed = parsed_dates[0] if parsed_dates else None
        if parsed:
            dated.append(parsed)
    if dated:
        return dated
    return parse_dates(element.get_text(" ", strip=True))


def _is_calendar_page(url: str, soup: BeautifulSoup) -> bool:
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    heading = soup.h1.get_text(" ", strip=True) if soup.h1 else ""
    blob = f"{urlparse(url).path} {title} {heading}"
    return bool(CALENDAR_HINT.search(blob))


def _context(element) -> str | None:
    for parent in [element, *list(element.parents)[:8]]:
        name = getattr(parent, "name", None)
        if not name or name in {"body", "html", "[document]"}:
            break
        ident = " ".join(parent.get("class") or [])
        ident = f"{ident} {parent.get('id') or ''}"
        headings = [
            heading.get_text(" ", strip=True)
            for heading in parent.find_all(["h1", "h2", "h3"], recursive=False)
        ]
        blob = f"{ident} {' '.join(headings)}"
        if PAST_CONTEXT.search(blob):
            return "past"
        if PROMOTED_CONTEXT.search(blob):
            return "promoted"
    return None


def _copyright_year(soup: BeautifulSoup) -> int | None:
    scopes = []
    footer = soup.find("footer")
    if footer is not None:
        scopes.append(footer)
    scopes.append(soup)
    for scope in scopes:
        years = [int(year) for _prefix, year in COPYRIGHT_RE.findall(scope.get_text(" ", strip=True))]
        if years:
            return max(years)
    return None


def _last_updated(soup: BeautifulSoup) -> date | None:
    for node in soup.find_all("time"):
        parent = node.parent.get_text(" ", strip=True) if node.parent else ""
        if LAST_UPDATED.search(parent):
            parsed = parse_datetime_attr(node.get("datetime") or "")
            if parsed is None:
                dates = parse_dates(node.get_text(" ", strip=True))
                parsed = dates[0] if dates else None
            if parsed:
                return parsed
    text = soup.get_text(" ", strip=True)
    match = LAST_UPDATED.search(text)
    if not match:
        return None
    window = text[match.end() : match.end() + 48]
    dates = parse_dates(window)
    return dates[0] if dates else None


def _collect_kind_dates(soup: BeautifulSoup, url: str, *, kind: str) -> list[date]:
    hint = NEWSLETTER_HINT if kind == "newsletter" else NEWS_HINT
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    heading = soup.h1.get_text(" ", strip=True) if soup.h1 else ""
    dates: list[date] = []
    if hint.search(f"{url} {title} {heading}"):
        dates.extend(_dates_in(soup))
    for element in soup.find_all(True):
        ident = " ".join(element.get("class") or [])
        ident = f"{ident} {element.get('id') or ''}"
        own_heading = ""
        if element.name in {"h1", "h2", "h3"}:
            own_heading = element.get_text(" ", strip=True)
        if hint.search(f"{ident} {own_heading}"):
            # A news page should not also swallow a newsletter block.
            if kind == "news" and NEWSLETTER_HINT.search(f"{ident} {own_heading}"):
                continue
            dates.extend(_dates_in(element))
    if kind == "newsletter":
        for anchor in soup.find_all("a", href=True):
            raw = f"{anchor.get('href', '')} {anchor.get_text(' ', strip=True)}"
            if not hint.search(raw):
                continue
            named = _filename_date(urljoin(url, anchor["href"]))
            if named:
                dates.append(named)
            dates.extend(parse_dates(anchor.get_text(" ", strip=True)))
    return dates


def _promoted_event_dates(soup: BeautifulSoup) -> list[date]:
    found: list[date] = []
    for node in soup.find_all("time"):
        if _context(node) != "promoted":
            continue
        parsed = parse_datetime_attr(node.get("datetime") or "")
        if parsed is None:
            dates = parse_dates(node.get_text(" ", strip=True))
            parsed = dates[0] if dates else None
        if parsed:
            found.append(parsed)
    return found


def _describe(value: date | None) -> str:
    if value is None:
        return "None found"
    return value.isoformat()


def analyse_freshness(
    pages: list[tuple[str, str]],
    rules: FreshnessRules | None = None,
    today: date | None = None,
) -> FreshnessReport:
    """Read dates from crawled HTML and flag stale content.

    `pages` is a list of `(url, html)`. Details never copy page sentences,
    only the rule and the date Watson used.
    """
    rules = rules or FreshnessRules()
    today = today or date.today()
    rows: list[UpdateRow] = []
    newsletter_dates: list[tuple[date, str]] = []
    news_dates: list[tuple[date, str]] = []
    event_dates: list[tuple[date, str]] = []

    for url, html in pages:
        soup = BeautifulSoup(html or "", "html.parser")
        updated = _last_updated(soup)
        if updated:
            rows.append(
                UpdateRow(
                    kind="Last updated",
                    severity="Info",
                    page_url=url,
                    observed_date=updated.isoformat(),
                    detail="A last-updated date is shown on the page.",
                    fix="No action unless the date shows the page has been left behind.",
                )
            )
        for observed in _collect_kind_dates(soup, url, kind="newsletter"):
            newsletter_dates.append((observed, url))
        for observed in _collect_kind_dates(soup, url, kind="news"):
            news_dates.append((observed, url))
        for observed in _promoted_event_dates(soup):
            event_dates.append((observed, url))

        text = soup.get_text("\n", strip=True)
        if _is_calendar_page(url, soup):
            years = [int(year) for year in re.findall(r"\b(20\d{2})\b", text)]
            if years and is_past_calendar_year(max(years), today, rules.calendar_grace_days):
                latest = max(years)
                rows.append(
                    UpdateRow(
                        kind="Stale content",
                        severity="Medium",
                        page_url=url,
                        observed_date=str(latest),
                        detail=f"This calendar's latest year is {latest}, which is before {today.year}.",
                        fix="Update the calendar if it is still meant to describe the current year.",
                    )
                )
        copyright_year = _copyright_year(soup)
        if copyright_year is not None and copyright_year < today.year - rules.copyright_grace_years:
            rows.append(
                UpdateRow(
                    kind="Stale content",
                    severity="Low",
                    page_url=url,
                    observed_date=str(copyright_year),
                    detail=(
                        f"Footer copyright year is {copyright_year}; the current year is {today.year}."
                    ),
                    fix="Update the footer copyright year, or ask the host if the footer is shared.",
                )
            )

    newest_newsletter = max(newsletter_dates, default=None, key=lambda item: item[0])
    newest_news = max(news_dates, default=None, key=lambda item: item[0])
    newest_event = max(event_dates, default=None, key=lambda item: item[0])

    def _add_newest(kind: str, winner: tuple[date, str] | None, fix: str) -> None:
        if winner is None:
            rows.append(
                UpdateRow(
                    kind=kind,
                    severity="Info",
                    page_url="",
                    observed_date="",
                    detail="None found.",
                    fix=fix,
                )
            )
            return
        observed, page_url = winner
        rows.append(
            UpdateRow(
                kind=kind,
                severity="Info",
                page_url=page_url,
                observed_date=observed.isoformat(),
                detail=f"Newest dated item is {observed.isoformat()}.",
                fix=fix,
            )
        )

    _add_newest(
        "Newest newsletter",
        newest_newsletter,
        "Publish a newsletter if the site still sends one.",
    )
    _add_newest("Newest news", newest_news, "No action. This is the newest news date Watson could read.")
    _add_newest("Newest event", newest_event, "No action. This is the newest event date Watson could read.")

    if newest_newsletter is not None:
        observed, page_url = newest_newsletter
        age = today - observed
        limit = timedelta(weeks=rules.newsletter_stale_weeks)
        if age > limit:
            rows.append(
                UpdateRow(
                    kind="Stale content",
                    severity="Medium",
                    page_url=page_url,
                    observed_date=observed.isoformat(),
                    detail=(
                        f"Newest newsletter date is {observed.isoformat()}, "
                        f"which is older than {rules.newsletter_stale_weeks} weeks."
                    ),
                    fix="Publish a current newsletter, or stop describing this one as the latest.",
                )
            )

    flagged: set[tuple[str, str]] = set()
    for observed, page_url in event_dates:
        if observed >= today:
            continue
        key = (page_url, observed.isoformat())
        if key in flagged:
            continue
        flagged.add(key)
        rows.append(
            UpdateRow(
                kind="Stale content",
                severity="Medium",
                page_url=page_url,
                observed_date=observed.isoformat(),
                detail=f"A promoted event date ({observed.isoformat()}) is in the past.",
                fix="Move the event to an archive, or take it off the upcoming list.",
            )
        )

    return FreshnessReport(
        rows=rows,
        newest_newsletter=_describe(newest_newsletter[0] if newest_newsletter else None),
        newest_news=_describe(newest_news[0] if newest_news else None),
        newest_event=_describe(newest_event[0] if newest_event else None),
    )
