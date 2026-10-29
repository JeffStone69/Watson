"""Check links and embedded resources with HEAD, then a GET fallback."""

from __future__ import annotations

from urllib.robotparser import RobotFileParser

from watson.classify import (
    OK,
    Classification,
    classify_link,
    link_severity,
)
from watson.crawler import (
    allowed_by_robots,
    meta_refresh_target,
    page_title_and_heading,
    same_site,
)
from watson.http_client import FetchResult, Fetcher
from watson.models import OWNER_EDITOR, LinkResult, Page, Reference
from watson.redact import redact, redact_url

_FALLBACK_STATUSES = {400, 404, 405, 501}


def _present(classification: Classification) -> tuple[str, str]:
    return link_severity(classification)


def check_links(
    fetcher: Fetcher,
    references: list[Reference],
    pages: list[Page],
    *,
    start_url: str,
    home_url: str,
    robots: RobotFileParser | None,
    user_agent: str,
    no_external: bool,
    max_links: int,
) -> tuple[list[LinkResult], int]:
    """Return problem and ok rows, plus a count of external links that were skipped.

    OK rows are kept so the summary can count what was checked, and dropped
    from the written reports.
    """
    page_by_url = {page.url: page for page in pages}
    results: list[LinkResult] = []
    skipped = 0
    limited = references[:max_links]
    for reference in limited:
        if no_external and not same_site(reference.url, start_url):
            skipped += 1
            continue
        if same_site(reference.url, start_url) and not allowed_by_robots(robots, user_agent, reference.url):
            results.append(
                _row(
                    reference,
                    Classification(
                        "unverified",
                        "Not requested because robots.txt disallows this URL",
                        False,
                    ),
                    status=None,
                    error="robots",
                )
            )
            continue
        page = page_by_url.get(reference.url)
        if page is not None:
            title, heading = page_title_and_heading(page.html)
            location = meta_refresh_target(page.html, page.url)
            fetched = FetchResult(
                url=page.url,
                status=page.status,
                location=location,
                content_type=page.content_type,
            )
            title_text, heading_text = title, heading
        else:
            fetched = _head_then_get(fetcher, reference.url)
            title_text, heading_text = "", ""
            if fetched.body and "html" in (fetched.content_type or "").lower():
                title_text, heading_text = page_title_and_heading(fetched.body.decode("utf-8", "replace"))
        classification = classify_link(
            status=fetched.status,
            error=fetched.error,
            location=fetched.location,
            requested_url=reference.url,
            home_url=home_url,
            raw_href=reference.raw,
            title=title_text,
            heading=heading_text,
        )
        if classification.category == OK:
            continue
        results.append(
            _row(
                reference,
                classification,
                status=fetched.status,
                location=fetched.location,
                error=fetched.error or "",
            )
        )
    return results, skipped


def _head_then_get(fetcher: Fetcher, url: str) -> FetchResult:
    head = fetcher.head(url)
    if head.error:
        return head
    if head.status in _FALLBACK_STATUSES:
        fallback = fetcher.get(url, limit=8192)
        if fallback.error is None and fallback.status is not None:
            return fallback
        if fallback.error and head.status is None:
            return fallback
        if fallback.status is not None:
            return fallback
    return head


def _row(
    reference: Reference,
    classification: Classification,
    *,
    status: int | None,
    location: str = "",
    error: str = "",
) -> LinkResult:
    severity, fix = _present(classification)
    return LinkResult(
        url=redact_url(reference.url),
        source_url=redact_url(reference.source_url),
        link_text=redact(reference.text),
        category=classification.category,
        reason=redact(classification.reason, limit=300),
        status=status,
        location=redact_url(location),
        soft_404=classification.soft_404,
        error=error,
        severity=severity,
        owner=OWNER_EDITOR,
        fix=fix,
    )
