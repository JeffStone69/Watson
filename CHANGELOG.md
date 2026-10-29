# Changelog

## 0.1.0 — 2026-10-29

First public release.

- Polite same-host crawl that respects robots.txt, a configurable rate, and a User-Agent that names Watson.
- Link checks with HEAD and a GET fallback. Results are grouped as broken, couldn't verify, redirects (including soft 404s), and insecure http links.
- Stale-content checks for term dates and calendars, promoted events, newsletters, and copyright years, plus an optional Australian school-term ruleset.
- Passive security notes for HTTPS, TLS, HSTS, security headers, cookie flags, mixed content, insecure forms, outdated libraries, banners, security.txt, robots.txt and sitemaps, dangling link hosts, a count of visible email addresses, and document author metadata. Values of addresses and metadata are not written into the report.
- Excel, HTML, and JSON reports, and exit codes for scheduled runs.
- Built-in example site (`watson --demo`) so the tool can be tried without contacting a school.
- GitHub Actions runs the tests, and tagged releases build Windows and macOS executables.
