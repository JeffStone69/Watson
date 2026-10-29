"""Stale-date rules for calendars, events, newsletters, and copyright years."""

from datetime import date

from watson.freshness import (
    FreshnessRules,
    analyse_freshness,
    is_past_calendar_year,
    parse_dates,
)

TODAY = date(2026, 10, 29)
PAGE = "http://www.example.com/calendar.html"


def _details(html: str, url: str = PAGE, **rules):
    report = analyse_freshness([(url, html)], FreshnessRules(**rules), today=TODAY)
    return [row for row in report.rows if row.kind == "Stale content"], report


def test_parse_dates_skips_impossible_days():
    assert parse_dates("29 February 2024") == [date(2024, 2, 29)]
    assert parse_dates("29 February 2025") == []
    assert parse_dates("3 March 2023") == [date(2023, 3, 3)]


def test_january_grace_for_last_years_calendar():
    assert is_past_calendar_year(2025, date(2026, 1, 15), grace_days=31) is False
    assert is_past_calendar_year(2025, date(2026, 2, 1), grace_days=31) is True
    assert is_past_calendar_year(2024, TODAY, grace_days=31) is True
    assert is_past_calendar_year(2026, TODAY, grace_days=31) is False


def test_past_calendar_year_and_old_copyright():
    html = """
    <h1>Calendar</h1>
    <p>The public calendar still lists 22 January 2024.</p>
    <footer>Copyright 2018-2019</footer>
    """
    stale, _report = _details(html)
    text = " ".join(row.detail for row in stale)
    assert "2024" in text
    assert "before" in text
    assert "2019" in text
    assert "Example" not in text


def test_current_copyright_range_is_not_stale():
    html = "<footer>© 2019-2026</footer>"
    stale, _report = _details(html, url="http://www.example.com/")
    assert not any("copyright" in row.detail.lower() for row in stale)


def test_copyright_grace_year():
    html = "<footer>Copyright 2025</footer>"
    stale, _report = _details(html, url="http://www.example.com/", copyright_grace_years=1)
    assert not any("copyright" in row.detail.lower() for row in stale)


def test_promoted_past_event_is_flagged_and_archive_is_not():
    html = """
    <section class="upcoming-events">
      <h2>Upcoming events</h2>
      <article><time datetime="2024-08-20">20 August 2024</time></article>
    </section>
    <section class="past-events">
      <h2>Past events</h2>
      <article><time datetime="2020-02-02">2 February 2020</time></article>
    </section>
    """
    stale, report = _details(html, url="http://www.example.com/events.html")
    details = " ".join(row.detail for row in stale)
    assert "2024-08-20" in details
    assert "2020-02-02" not in details
    assert report.newest_event == "2024-08-20"


def test_stale_newsletter_and_newest_news():
    pages = [
        (
            "http://www.example.com/newsletter.html",
            """
            <title>Latest newsletter</title>
            <h1>Latest newsletter</h1>
            <time datetime="2024-06-03">3 June 2024</time>
            <a href="/docs/newsletter-2024-06-03.pdf">Download the latest newsletter</a>
            """,
        ),
        (
            "http://www.example.com/news.html",
            """
            <h1>News</h1>
            <article class="news-item"><time datetime="2026-10-01">1 October 2026</time></article>
            """,
        ),
    ]
    report = analyse_freshness(pages, FreshnessRules(newsletter_stale_weeks=8), today=TODAY)
    assert report.newest_newsletter == "2024-06-03"
    assert report.newest_news == "2026-10-01"
    assert any("older than 8 weeks" in row.detail for row in report.rows)


def test_numeric_dates_without_a_month_name_are_ignored():
    html = """
    <section class="upcoming-events">
      <h2>Upcoming events</h2>
      <p>28/03/2024</p>
    </section>
    """
    stale, _report = _details(html, url="http://www.example.com/notes")
    assert "2024-03-28" not in " ".join(row.detail for row in stale)