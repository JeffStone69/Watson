"""Run a passive scan and build a report model."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from watson import USER_AGENT
from watson.config import Config
from watson.crawler import (
    CrawlError,
    crawl,
    extract_references,
    parse_sitemap_locs,
    robots_from_text,
    same_site,
    sitemap_urls_from_robots,
)
from watson.freshness import FreshnessRules, analyse_freshness
from watson.http_client import Fetcher
from watson.links import check_links
from watson.metadata_docs import has_author_metadata
from watson.models import SEVERITY_ORDER, Finding, Page, ScanResult
from watson.security import (
    apply_osv,
    content_findings,
    dangling_domain_finding,
    document_metadata_finding,
    grade_banner,
    grade_certificate,
    grade_cookies,
    grade_headers,
    grade_https_enforcement,
    robots_sitemap_finding,
    security_txt_finding,
    sensitive_paths,
)
from watson.transport import inspect_tls

_OSV_PACKAGES = {
    "jQuery": ("npm", "jquery"),
    "jQuery UI": ("npm", "jquery-ui"),
    "Bootstrap": ("npm", "bootstrap"),
    "Lodash": ("npm", "lodash"),
    "Moment.js": ("npm", "moment"),
    "Handlebars": ("npm", "handlebars"),
    "Underscore": ("npm", "underscore"),
    "DOMPurify": ("npm", "dompurify"),
}
_LIBRARY_TITLE = re.compile(r"^(.+) (\d+\.\d+\.\d+) is outdated$")
_DISALLOW = re.compile(r"(?im)^disallow:\s*(\S+)")
_DOC_LIMIT = 5_000_000
_SCRIPT_LIMIT = 64_000


class TargetUnreachable(RuntimeError):
    """The start URL could not be fetched."""


def _stamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _disallow_paths(text: str) -> list[str]:
    """Read Disallow paths from a robots.txt that uses User-agent: *."""
    paths: list[str] = []
    applies = False
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            applies = value == "*" or value.lower().startswith("watson")
        elif key == "disallow" and applies and value:
            paths.append(value)
    if paths:
        return paths
    return [match.strip() for match in _DISALLOW.findall(text) if match.strip()]


def _crawl_delay(parser, user_agent: str) -> float | None:
    for token in (user_agent, "*"):
        try:
            delay = parser.crawl_delay(token)
        except Exception:
            delay = None
        if delay:
            return float(delay)
    return None


def _query_osv(name: str, version: str, client: httpx.Client) -> list[str]:
    package = _OSV_PACKAGES.get(name)
    if not package:
        return []
    ecosystem, package_name = package
    response = client.post(
        "https://api.osv.dev/v1/query",
        json={"version": version, "package": {"name": package_name, "ecosystem": ecosystem}},
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        timeout=10.0,
    )
    response.raise_for_status()
    payload = response.json()
    ids: list[str] = []
    for vuln in payload.get("vulns") or []:
        identifier = vuln.get("id")
        if isinstance(identifier, str):
            ids.append(identifier)
    return ids[:10]


def _exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}[fail_on]
    limit = SEVERITY_ORDER[threshold]

    def fails(severity: str) -> bool:
        return SEVERITY_ORDER.get(severity, 9) <= limit

    if any(item.category == "broken" for item in result.links):
        return 1
    if any(fails(item.severity) for item in result.findings):
        return 1
    if fail_on != "high" and any(
        fails(item.severity) and item.kind == "Stale content" for item in result.updates
    ):
        return 1
    return 0


def _checklist(findings: list[Finding], *, https_ok: bool, hsts_relevant: bool) -> list[tuple[str, str]]:
    by_check: dict[str, Finding] = {}
    for finding in findings:
        by_check.setdefault(finding.check, finding)
    labels = [
        ("https-enforcement", "HTTPS"),
        ("https-redirect", "HTTP to HTTPS redirect"),
        ("tls", "TLS certificate"),
        ("tls-expiry", "Certificate expiry"),
        ("tls-protocol", "TLS protocol"),
        ("hsts", "HSTS"),
        ("content-security-policy", "Content-Security-Policy"),
        ("clickjacking", "Clickjacking protection"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
        ("cookie-secure", "Cookie Secure flag"),
        ("cookie-httponly", "Cookie HttpOnly flag"),
        ("cookie-samesite", "Cookie SameSite"),
        ("version-banner", "Server version banner"),
        ("security-txt", "security.txt"),
        ("robots-sitemap", "robots.txt and sitemap"),
    ]
    rows: list[tuple[str, str]] = []
    for check, label in labels:
        finding = by_check.get(check)
        if finding:
            rows.append((f"Check: {label}", f"{finding.severity} — {finding.title}"))
        elif check == "https-redirect" and not https_ok:
            rows.append((f"Check: {label}", "Not checked separately — the site is not on HTTPS"))
        elif check == "hsts" and not hsts_relevant:
            rows.append((f"Check: {label}", "Not checked — site is not on HTTPS"))
        elif check in {"tls", "tls-expiry", "tls-protocol"} and not https_ok:
            rows.append((f"Check: {label}", "Not checked — no TLS certificate was presented"))
        else:
            rows.append((f"Check: {label}", "No problem found"))
    return rows


def run_scan(config: Config, log=print) -> ScanResult:
    """Crawl one site and run the selected checks.

    The only network calls are to the target site, plus api.osv.dev when
    `osv_lookup` is on. Reserved documentation names are not contacted.
    """
    started = _stamp()
    log(
        f"Watson {config.user_agent.split()[0]} — passive check only "
        "(GET and HEAD, plus one TLS handshake). No logins, form posts, hidden-page guessing, or port scans."
    )
    log(f"Target: {config.start_url}")
    fetcher = Fetcher(
        rate=config.rate,
        timeout=config.timeout,
        user_agent=config.user_agent,
        start_url=config.start_url,
    )
    notes = [
        "Requests are sent one at a time.",
        "OSV lookup is on." if config.osv_lookup else "OSV lookup is off.",
        "External links are not requested." if config.no_external else "External links are checked with HEAD.",
    ]
    if config.australian_terms:
        notes.append("Australian school-term rules are on.")
    try:
        robots_url = f"{_origin(config.start_url)}/robots.txt"
        robots_fetch = fetcher.get(robots_url, limit=200_000)
        robots_text = ""
        parser = None
        if robots_fetch.status == 200 and robots_fetch.body and not robots_fetch.error:
            robots_text = robots_fetch.body.decode("utf-8", "replace")
            parser = robots_from_text(robots_text)
            fetcher.limiter.set_crawl_delay(_crawl_delay(parser, config.user_agent), config.rate)
        try:
            pages = crawl(
                fetcher,
                config.start_url,
                max_pages=config.max_pages,
                max_depth=config.max_depth,
                robots=parser,
                user_agent=config.user_agent,
            )
        except CrawlError as exc:
            raise TargetUnreachable(str(exc)) from exc
        log(f"Crawled {len(pages)} HTML page(s).")
        home = pages[0]
        references = []
        for page in pages:
            references.extend(extract_references(page.html, page.url))
        link_results: list = []
        skipped = 0
        if "links" in config.checks:
            log(f"Checking {min(len(references), config.max_links)} link(s).")
            if len(references) > config.max_links:
                notes.append(f"Stopped after {config.max_links} links. Raise max_links in the config to check the rest.")
            link_results, skipped = check_links(
                fetcher,
                references,
                pages,
                start_url=config.start_url,
                home_url=home.url,
                robots=parser,
                user_agent=config.user_agent,
                no_external=config.no_external,
                max_links=config.max_links,
            )
        updates = []
        newest_newsletter = "Not checked"
        newest_news = "Not checked"
        newest_event = "Not checked"
        if "freshness" in config.checks:
            report = analyse_freshness(
                [(page.url, page.html) for page in pages],
                FreshnessRules(
                    newsletter_stale_weeks=config.newsletter_stale_weeks,
                    copyright_grace_years=config.copyright_grace_years,
                    calendar_grace_days=config.calendar_grace_days,
                    australian_terms=config.australian_terms,
                    terms=list(config.terms),
                ),
                today=config.today,
            )
            updates = report.rows
            newest_newsletter = report.newest_newsletter
            newest_news = report.newest_news
            newest_event = report.newest_event
        findings: list[Finding] = []
        if "security" in config.checks:
            findings.extend(_security(config, fetcher, pages, references, link_results, robots_text, log))
        findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.check, item.url))
        result = ScanResult(
            target=config.start_url,
            started_at=started,
            finished_at=_stamp(),
            pages=pages,
            links=link_results,
            updates=updates,
            findings=findings,
            newest_newsletter=newest_newsletter,
            newest_news=newest_news,
            newest_event=newest_event,
            user_agent=config.user_agent,
            external_skipped=skipped,
            notes=notes,
            checklist=_checklist(
                findings,
                https_ok=urlparse(home.url).scheme == "https",
                hsts_relevant=urlparse(home.url).scheme == "https",
            ),
        )
        result.exit_code = _exit_code(result, config.fail_on)
        result.finished_at = _stamp()
        return result
    finally:
        fetcher.close()


def _security(config, fetcher, pages: list[Page], references, link_results, robots_text: str, log) -> list[Finding]:
    home = pages[0]
    scheme = urlparse(home.url).scheme
    findings: list[Finding] = []
    findings.extend(grade_headers(home.headers, scheme=scheme, url=home.url))
    findings.extend(grade_cookies(home.set_cookies, scheme=scheme, url=home.url))
    findings.extend(grade_banner(home.headers, url=home.url))
    parsed = urlparse(config.start_url)
    host = parsed.hostname or ""
    explicit = parsed.port
    tls_port = explicit if explicit and explicit not in {80, 443} else 443
    fetcher.limiter.wait()
    tls = inspect_tls(host, tls_port, min(config.timeout, 5))
    http_status = None
    http_location = None
    if scheme == "https" and (explicit is None or explicit in {80, 443}):
        probe = fetcher.get(f"http://{host}/", limit=4096)
        http_status = probe.status
        http_location = probe.location
    elif scheme == "http":
        entry = fetcher.cache.get(("GET", config.start_url, 2_000_000))
        if entry is not None and entry.status in {301, 302, 303, 307, 308}:
            http_status = entry.status
            http_location = entry.location
    if scheme == "https" or tls.ok:
        now = datetime.now(timezone.utc)
        findings.extend(
            grade_certificate(
                not_after=tls.not_after,
                protocol=tls.protocol,
                verified=tls.verified,
                hostname_ok=tls.hostname_ok,
                now=now,
                error=None if tls.ok else tls.error,
                url=home.url,
            )
        )
    findings.extend(
        grade_https_enforcement(
            site_scheme=scheme,
            tls_ok=tls.ok,
            tls_error=tls.error,
            http_status=http_status,
            http_location=http_location,
            url=home.url,
        )
    )
    extra_texts: list[tuple[str, str]] = []
    seen_scripts: set[str] = set()
    for reference in references:
        if reference.kind != "script" or not same_site(reference.url, config.start_url):
            continue
        if reference.url in seen_scripts:
            continue
        seen_scripts.add(reference.url)
        fetched = fetcher.get(reference.url, limit=_SCRIPT_LIMIT)
        if fetched.error or not fetched.body:
            continue
        extra_texts.append((reference.url, fetched.body.decode("utf-8", "replace")))
    findings.extend(
        content_findings([(page.url, page.html) for page in pages], extra_texts=extra_texts)
    )
    seen_docs: set[str] = set()
    for reference in references:
        suffix = Path(urlparse(reference.url).path).suffix.lower()
        if suffix not in {".pdf", ".docx"} or not same_site(reference.url, config.start_url):
            continue
        if reference.url in seen_docs:
            continue
        seen_docs.add(reference.url)
        fetched = fetcher.get(reference.url, limit=_DOC_LIMIT)
        if fetched.error or not fetched.body:
            continue
        if has_author_metadata(fetched.body, suffix):
            findings.append(document_metadata_finding(reference.url, suffix))
    if not config.no_external:
        hosts: Counter[str] = Counter()
        example_page: dict[str, str] = {}
        for item in link_results:
            if item.error != "dns":
                continue
            host_name = (urlparse(item.url).hostname or "").lower()
            if not host_name or same_site(item.url, config.start_url):
                continue
            hosts[host_name] += 1
            example_page.setdefault(host_name, item.source_url)
        for host_name, count in sorted(hosts.items()):
            findings.append(dangling_domain_finding(host_name, count, example_page[host_name]))
    origin = _origin(home.url)
    present = False
    present_url = origin + "/.well-known/security.txt"
    for path in ("/.well-known/security.txt", "/security.txt"):
        fetched = fetcher.get(origin + path, limit=100_000)
        if fetched.status == 200 and fetched.body and fetched.body.strip():
            present = True
            present_url = origin + path
            break
    findings.append(security_txt_finding(present=present, url=present_url))
    sitemap_count = None
    sitemap_offsite = False
    locs: list[str] = []
    for sitemap in sitemap_urls_from_robots(robots_text):
        if not same_site(sitemap, config.start_url):
            sitemap_offsite = True
            continue
        fetched = fetcher.get(sitemap, limit=500_000)
        if fetched.status == 200 and fetched.body:
            locs = parse_sitemap_locs(fetched.body.decode("utf-8", "replace"))
            sitemap_count = len(locs)
            break
    if sitemap_count is None and not sitemap_offsite:
        fetched = fetcher.get(origin + "/sitemap.xml", limit=500_000)
        if fetched.status == 200 and fetched.body:
            locs = parse_sitemap_locs(fetched.body.decode("utf-8", "replace"))
            sitemap_count = len(locs)
    findings.append(
        robots_sitemap_finding(
            disallow=_disallow_paths(robots_text),
            fetched=bool(robots_text),
            sitemap_count=sitemap_count,
            sensitive_paths=sensitive_paths(locs),
            sitemap_offsite=sitemap_offsite,
            url=origin + "/robots.txt",
        )
    )
    if config.osv_lookup:
        log("OSV lookup is on. Library names and versions will be sent to api.osv.dev.")
        lookups: dict[tuple[str, str], list[str]] = {}
        failed = False
        try:
            with httpx.Client(timeout=10.0, trust_env=True, follow_redirects=False) as client:
                seen: set[tuple[str, str]] = set()
                for finding in findings:
                    match = _LIBRARY_TITLE.match(finding.title)
                    if not match:
                        continue
                    key = (match.group(1), match.group(2))
                    if key in seen or key[0] not in _OSV_PACKAGES:
                        continue
                    seen.add(key)
                    try:
                        lookups[key] = _query_osv(key[0], key[1], client)
                    except (httpx.HTTPError, ValueError):
                        failed = True
        except httpx.HTTPError:
            failed = True
        findings = apply_osv(findings, lookups)
        if failed:
            findings.append(
                Finding(
                    severity="Info",
                    check="osv-lookup",
                    title="OSV lookup could not be completed",
                    evidence="The optional request to api.osv.dev failed. No page content was sent.",
                    owner="Platform/hosting provider",
                    fix="Re-run later with --osv-lookup if you still want public vulnerability ids. The rest of the report does not depend on it.",
                    url="",
                )
            )
    return findings
