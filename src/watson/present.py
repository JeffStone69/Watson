"""Rows shared by the Excel, HTML, and JSON reports."""

from __future__ import annotations

from watson.classify import BROKEN, INSECURE, REDIRECT, UNVERIFIED
from watson.models import SEVERITY_ORDER, ScanResult


def _severity_count(result: ScanResult, level: str) -> int:
    return sum(1 for finding in result.findings if finding.severity == level)


def summary_rows(result: ScanResult) -> list[tuple[str, str]]:
    soft = sum(1 for item in result.links if item.soft_404)
    redirects = len(result.links_in(REDIRECT))
    stale = sum(1 for row in result.updates if row.kind == "Stale content")
    rows = [
        ("Report", "Watson passive website check"),
        ("Target", result.target),
        ("Started", result.started_at),
        ("Finished", result.finished_at),
        ("User-Agent", result.user_agent),
        ("Pages crawled", str(len(result.pages))),
        ("Links reported", str(len(result.links))),
        ("External links skipped", str(result.external_skipped)),
        ("Broken links", str(len(result.links_in(BROKEN)))),
        ("Couldn't verify", str(len(result.links_in(UNVERIFIED)))),
        ("Redirects (including soft 404s)", str(redirects)),
        ("Soft 404s", str(soft)),
        ("Insecure http links", str(len(result.links_in(INSECURE)))),
        ("Stale content items", str(stale)),
        ("Security High", str(_severity_count(result, "High"))),
        ("Security Medium", str(_severity_count(result, "Medium"))),
        ("Security Low", str(_severity_count(result, "Low"))),
        ("Security Info", str(_severity_count(result, "Info"))),
        ("Newest newsletter", result.newest_newsletter),
        ("Newest news", result.newest_news),
        ("Newest event", result.newest_event),
        ("Exit code", str(result.exit_code)),
        (
            "Passive checks",
            "GET and HEAD only, plus one TLS handshake to the same host. No logins, form posts, guessing of hidden pages, or port scans.",
        ),
        (
            "Privacy",
            "Email addresses, personal names, and document metadata values are not included. Counts and page locations only.",
        ),
    ]
    rows.extend(result.checklist)
    for note in result.notes:
        rows.append(("Note", note))
    return rows


def sort_findings(result: ScanResult):
    return sorted(
        result.findings,
        key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 9), finding.check, finding.url),
    )
