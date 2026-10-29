"""Self-contained HTML report. No external images, fonts, or scripts."""

from __future__ import annotations

from html import escape
from pathlib import Path

from watson import __version__
from watson.classify import BROKEN, INSECURE, REDIRECT, UNVERIFIED
from watson.models import ScanResult
from watson.present import sort_findings, summary_rows

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font-family: "Segoe UI", "Helvetica Neue", system-ui, sans-serif; color: #1f2933; background: #f4f6f8; line-height: 1.45; }
header, main { max-width: 1100px; margin: 0 auto; padding: 1.25rem; }
header { background: #1f4e79; color: #fff; max-width: none; }
header .inner { max-width: 1100px; margin: 0 auto; }
.eyebrow { letter-spacing: .04em; text-transform: uppercase; font-size: .78rem; margin: 0 0 .3rem; opacity: .85; }
h1 { font-size: 1.7rem; margin: 0 0 .4rem; }
h2 { font-size: 1.2rem; margin: 0 0 .6rem; }
a { color: #1f4e79; }
.notice { background: #fff8e8; border: 1px solid #e6d3a1; padding: .8rem 1rem; border-radius: 8px; margin: 1rem 0; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: .6rem; margin: 1rem 0; }
.card { background: #fff; border-radius: 8px; padding: .7rem .8rem; border: 1px solid #d9e2ec; }
.card span { display: block; font-size: .78rem; color: #52606d; }
.card strong { font-size: 1.15rem; }
section { background: #fff; border: 1px solid #d9e2ec; border-radius: 8px; padding: 1rem; margin: 0 0 1rem; }
table { width: 100%; border-collapse: collapse; font-size: .92rem; }
th, td { text-align: left; vertical-align: top; padding: .4rem .45rem; border-bottom: 1px solid #e4e7eb; word-break: break-word; }
th { background: #e4edf5; }
.badge { display: inline-block; padding: .05rem .4rem; border-radius: 999px; font-weight: 600; }
.High { background: #f8d0d0; }
.Medium { background: #fde7d0; }
.Low { background: #fff4cc; }
.Info { background: #e7eef8; }
nav a { margin-right: .8rem; }
footer { max-width: 1100px; margin: 0 auto; padding: 0 1.25rem 2rem; color: #52606d; font-size: .85rem; }
@media print {
  body { background: #fff; }
  header { background: #fff; color: #000; }
  section, .card { break-inside: avoid; }
  @page { size: A4 landscape; margin: 12mm; }
}
"""


def _esc(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _badge(severity: str) -> str:
    return f'<span class="badge {_esc(severity)}">{_esc(severity)}</span>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "<p>None found.</p>"
    head = "".join(f"<th scope=\"col\">{_esc(header)}</th>" for header in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{cell}</td>" for cell in row)
        body.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _link_rows(items) -> list[list[str]]:
    rows = []
    for item in items:
        status = "" if item.status is None else str(item.status)
        rows.append(
            [
                _esc(item.url),
                _badge(item.severity),
                _esc(item.reason),
                _esc(status),
                _esc(item.source_url),
                _esc(item.link_text),
                _esc(item.owner),
                _esc(item.fix),
            ]
        )
    return rows


def render_html(result: ScanResult) -> str:
    host = result.target
    counts = {item: value for item, value in summary_rows(result)}
    cards = [
        ("Broken links", counts.get("Broken links", "0")),
        ("Couldn't verify", counts.get("Couldn't verify", "0")),
        ("Redirects", counts.get("Redirects (including soft 404s)", "0")),
        ("Insecure http", counts.get("Insecure http links", "0")),
        ("Stale items", counts.get("Stale content items", "0")),
        ("Security High", counts.get("Security High", "0")),
    ]
    card_html = "".join(
        f'<div class="card"><span>{_esc(label)}</span><strong>{_esc(value)}</strong></div>'
        for label, value in cards
    )
    summary_table = _table(
        ["Item", "Value"],
        [[_esc(item), _esc(value)] for item, value in summary_rows(result)],
    )
    link_headers = ["URL", "Severity", "Problem", "Status", "Found on", "Link text", "Owner", "Suggested fix"]
    redirects = result.links_in(REDIRECT) + result.links_in(INSECURE)
    redirect_rows = []
    for item in redirects:
        kind = "Soft 404" if item.soft_404 else ("Insecure http" if item.category == INSECURE else "Redirect")
        status = "" if item.status is None else str(item.status)
        redirect_rows.append(
            [
                _esc(item.url),
                _badge(item.severity),
                _esc(kind),
                _esc(item.reason),
                _esc(status),
                _esc(item.location),
                _esc(item.source_url),
                _esc(item.link_text),
                _esc(item.owner),
                _esc(item.fix),
            ]
        )
    update_rows = [
        [
            _esc(item.kind),
            _badge(item.severity),
            _esc(item.page_url),
            _esc(item.observed_date),
            _esc(item.detail),
            _esc(item.owner),
            _esc(item.fix),
        ]
        for item in result.updates
    ]
    security_rows = [
        [
            _badge(item.severity),
            _esc(item.check),
            _esc(item.title),
            _esc(item.evidence),
            _esc(item.owner),
            _esc(item.fix),
            _esc(item.url),
        ]
        for item in sort_findings(result)
    ]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Watson report — {_esc(host)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <div class="inner">
    <p class="eyebrow">Watson {_esc(__version__)} · passive check only</p>
    <h1>{_esc(host)}</h1>
    <p>Checked { _esc(result.started_at) }. Watson sent normal page requests only. It did not log in, submit forms, guess hidden pages, or scan ports.</p>
  </div>
</header>
<main>
  <div class="notice">
    <strong>Keep this report inside the school.</strong>
    It lists page addresses and link text, which can be enough to recognise a page.
    It does not include email addresses, people's names from document properties, or metadata values.
    Do not publish it.
  </div>
  <nav>
    <a href="#summary">Summary</a>
    <a href="#broken">Broken links</a>
    <a href="#unverified">Couldn't verify</a>
    <a href="#redirects">Redirects and http</a>
    <a href="#updates">Updates and stale content</a>
    <a href="#security">Security</a>
  </nav>
  <div class="cards">{card_html}</div>
  <section id="summary">
    <h2>Summary</h2>
    {summary_table}
  </section>
  <section id="broken">
    <h2>Broken links</h2>
    <p>These returned 404 or 410, or the connection failed. A content editor can usually fix them.</p>
    {_table(link_headers, _link_rows(result.links_in(BROKEN)))}
  </section>
  <section id="unverified">
    <h2>Couldn't verify</h2>
    <p>Open these in a normal browser. A 401, 403, 429, or 5xx often means the other site blocked an automated check, or the page is not public.</p>
    {_table(link_headers, _link_rows(result.links_in(UNVERIFIED)))}
  </section>
  <section id="redirects">
    <h2>Redirects and http</h2>
    <p>Soft 404s send people to the home page or a generic not-found page. Insecure rows are links that were written as http://.</p>
    {_table(["URL", "Severity", "Kind", "Problem", "Status", "Redirects to", "Found on", "Link text", "Owner", "Suggested fix"], redirect_rows)}
  </section>
  <section id="updates">
    <h2>Updates and stale content</h2>
    <p>Newest newsletter: {_esc(result.newest_newsletter)}. Newest news: {_esc(result.newest_news)}. Newest event: {_esc(result.newest_event)}.</p>
    {_table(["Kind", "Severity", "Page", "Date", "Detail", "Owner", "Suggested fix"], update_rows)}
  </section>
  <section id="security">
    <h2>Security</h2>
    <p><strong>Platform/hosting provider</strong> means the department or the company that hosts the template: HTTPS, certificates, and site-wide headers. <strong>School content editor</strong> means a link, a page, an embed, or a document the school can change.</p>
    {_table(["Severity", "Check", "Title", "Evidence", "Owner", "Suggested fix", "Page"], security_rows)}
  </section>
</main>
<footer>
  <p>Watson {_esc(__version__)}. Generated on this computer. No telemetry. {_esc(result.user_agent)}</p>
</footer>
</body>
</html>
"""


def write_html(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result), encoding="utf-8")
