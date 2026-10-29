# Contributing to Watson

Watson is a small tool for school technicians. Changes should stay understandable, and they must stay passive.

## Passive only

Watson may send the same GET and HEAD requests a browser would send, plus one TLS handshake to the host it was asked to check. It may also, when someone opts in, send a library name and version to the public OSV API.

Do not add logins, form posts, cookies that start a session, fuzzing, directory brute-forcing, port scans, exploit payloads, or anything that tries to bypass access control. School sites are often run by a department. Intrusive testing is out of scope for this project.

## Privacy

Do not commit a real school's name, URL, crawl output, screenshot of a live site, or report. Tests and examples use `example.edu`, reserved names such as `.invalid` and `.example`, and the built-in fixture site.

Reports must not copy email addresses, people's names, or document metadata values. Counts and page locations are enough. If a change needs a new piece of page text in the report, redact addresses first and say why the text is required.

## Development

Python 3.10 or newer.

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

`watson --demo` scans the fixture on your own computer. Use that, or `http://127.0.0.1`, instead of a live school site, when you try a change.

Please add or update a unit test when you change the status classifier, soft-404 rules, stale-date rules, or header grading.

## Pull requests

Describe what the technician will see differently. Keep the README accurate if the command or the report changes.
