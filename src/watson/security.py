"""Passive security checks. Every check is a normal browser GET or HEAD, or a TLS handshake."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from watson.libraries import LibraryHit, detect_libraries
from watson.models import OWNER_EDITOR, OWNER_PLATFORM, Finding
from watson.redact import EMAIL_RE, redact

_UNSAFE_CSP = re.compile(r"unsafe-inline|unsafe-eval", re.IGNORECASE)
_FRAME_ANCESTORS = re.compile(r"frame-ancestors\s+[^;]+", re.IGNORECASE)
_XFO = re.compile(r"\b(DENY|SAMEORIGIN)\b", re.IGNORECASE)
_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_SENSITIVE_PATH = re.compile(
    r"(admin|wp-admin|intranet|staff|login|password|backup|private|draft|staging|phpmyadmin)",
    re.IGNORECASE,
)
_EMBED_TAGS = {
    "script": "src",
    "iframe": "src",
    "embed": "src",
    "object": "data",
}
_MIXED_TAGS = {
    "script": ("src", "High"),
    "iframe": ("src", "High"),
    "embed": ("src", "High"),
    "object": ("data", "High"),
    "img": ("src", "Medium"),
    "audio": ("src", "Medium"),
    "video": ("src", "Medium"),
    "source": ("src", "Medium"),
    "link": ("href", "Medium"),
}
_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
)
_SESSION_NAME = re.compile(r"session|auth|token|sid", re.IGNORECASE)


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _finding(
    *,
    severity: str,
    check: str,
    title: str,
    evidence: str,
    owner: str,
    fix: str,
    url: str = "",
) -> Finding:
    return Finding(
        severity=severity,
        check=check,
        title=redact(title, limit=200),
        evidence=redact(evidence, limit=500),
        owner=owner,
        fix=fix,
        url=url,
    )


def grade_headers(headers: Mapping[str, str], *, scheme: str, url: str = "") -> list[Finding]:
    """Grade security headers. Only problems are returned."""
    findings: list[Finding] = []
    csp = header_value(headers, "content-security-policy")
    xfo = header_value(headers, "x-frame-options")
    nosniff = header_value(headers, "x-content-type-options")
    referrer = header_value(headers, "referrer-policy")
    permissions = header_value(headers, "permissions-policy") or header_value(headers, "feature-policy")
    hsts = header_value(headers, "strict-transport-security")

    if not csp:
        findings.append(
            _finding(
                severity="Medium",
                check="content-security-policy",
                title="Content-Security-Policy header is missing",
                evidence="The homepage response has no Content-Security-Policy header.",
                owner=OWNER_PLATFORM,
                fix=(
                    "Ask the platform team to add a Content-Security-Policy. "
                    "A report-only policy is a safe first step."
                ),
                url=url,
            )
        )
    elif _UNSAFE_CSP.search(csp):
        findings.append(
            _finding(
                severity="Low",
                check="csp-unsafe",
                title="Content-Security-Policy allows unsafe inline script or eval",
                evidence="The policy contains unsafe-inline or unsafe-eval.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to remove unsafe-inline and unsafe-eval where the template allows.",
                url=url,
            )
        )

    frames_protected = bool(xfo and _XFO.search(xfo)) or bool(csp and _FRAME_ANCESTORS.search(csp))
    if not frames_protected:
        findings.append(
            _finding(
                severity="Medium",
                check="clickjacking",
                title="No clickjacking protection (X-Frame-Options or frame-ancestors)",
                evidence="Neither X-Frame-Options nor a CSP frame-ancestors directive was found.",
                owner=OWNER_PLATFORM,
                fix="Set X-Frame-Options: SAMEORIGIN, or add frame-ancestors 'self' to the Content-Security-Policy.",
                url=url,
            )
        )

    if not nosniff or nosniff.strip().lower() != "nosniff":
        findings.append(
            _finding(
                severity="Low",
                check="x-content-type-options",
                title="X-Content-Type-Options is not set to nosniff",
                evidence="The homepage response does not send X-Content-Type-Options: nosniff.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to send X-Content-Type-Options: nosniff.",
                url=url,
            )
        )

    if not referrer:
        findings.append(
            _finding(
                severity="Low",
                check="referrer-policy",
                title="Referrer-Policy header is missing",
                evidence="The homepage response has no Referrer-Policy header.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
                url=url,
            )
        )
    elif referrer.strip().lower() == "unsafe-url":
        findings.append(
            _finding(
                severity="Medium",
                check="referrer-policy",
                title="Referrer-Policy is unsafe-url",
                evidence="The homepage sends Referrer-Policy: unsafe-url, which forwards full addresses.",
                owner=OWNER_PLATFORM,
                fix="Change Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
                url=url,
            )
        )

    if not permissions:
        findings.append(
            _finding(
                severity="Low",
                check="permissions-policy",
                title="Permissions-Policy header is missing",
                evidence="The homepage response has no Permissions-Policy (or Feature-Policy) header.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to send a Permissions-Policy that turns off camera, microphone, and geolocation unless a page needs them.",
                url=url,
            )
        )

    if scheme == "https":
        if not hsts:
            findings.append(
                _finding(
                    severity="Medium",
                    check="hsts",
                    title="HSTS is not set",
                    evidence="The HTTPS homepage has no Strict-Transport-Security header.",
                    owner=OWNER_PLATFORM,
                    fix="Ask the platform team to send Strict-Transport-Security with a max-age of at least six months.",
                    url=url,
                )
            )
        else:
            match = _MAX_AGE.search(hsts)
            max_age = int(match.group(1)) if match else None
            if max_age is None or max_age <= 0:
                findings.append(
                    _finding(
                        severity="Medium",
                        check="hsts",
                        title="HSTS max-age is missing or zero",
                        evidence="Strict-Transport-Security is present but max-age is missing or zero.",
                        owner=OWNER_PLATFORM,
                        fix="Set max-age to at least 15552000 (six months). Add includeSubDomains only if every subdomain supports HTTPS.",
                        url=url,
                    )
                )
            elif max_age < 10800:
                findings.append(
                    _finding(
                        severity="Low",
                        check="hsts",
                        title="HSTS max-age is very short",
                        evidence=f"Strict-Transport-Security max-age is {max_age} seconds.",
                        owner=OWNER_PLATFORM,
                        fix="Raise max-age to at least 15552000 seconds once you are sure HTTPS is stable.",
                        url=url,
                    )
                )
    return findings


def parse_set_cookie(header: str) -> dict[str, object]:
    """Read cookie flags. The cookie value is discarded."""
    parts = [part.strip() for part in header.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    secure = False
    httponly = False
    samesite = ""
    for part in parts[1:]:
        key, _, raw_value = part.partition("=")
        lowered = key.strip().lower()
        if lowered == "secure":
            secure = True
        elif lowered == "httponly":
            httponly = True
        elif lowered == "samesite":
            samesite = raw_value.strip().lower()
    return {"name": name, "secure": secure, "httponly": httponly, "samesite": samesite}


def grade_cookies(set_cookies: list[str], *, scheme: str, url: str = "") -> list[Finding]:
    parsed = [parse_set_cookie(item) for item in set_cookies if item]
    if not parsed:
        return []
    findings: list[Finding] = []
    missing_secure = [item for item in parsed if not item["secure"]]
    missing_httponly = [item for item in parsed if not item["httponly"]]
    missing_samesite = [item for item in parsed if not item["samesite"]]
    session_without_httponly = [
        item for item in missing_httponly if _SESSION_NAME.search(str(item["name"]))
    ]

    def names(items: list[dict[str, object]]) -> str:
        rendered = ", ".join(redact(str(item["name"]), limit=40) for item in items[:6] if item["name"])
        return rendered or "unnamed"

    if missing_secure:
        findings.append(
            _finding(
                severity="Medium" if scheme == "https" else "Low",
                check="cookie-secure",
                title="A cookie is missing the Secure flag",
                evidence=(
                    f"{len(missing_secure)} cookie(s) without Secure (names: {names(missing_secure)}). "
                    "Cookie values are not recorded."
                ),
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to set the Secure flag on cookies once the site is on HTTPS.",
                url=url,
            )
        )
    if missing_httponly:
        findings.append(
            _finding(
                severity="Medium" if session_without_httponly else "Low",
                check="cookie-httponly",
                title="A cookie is missing the HttpOnly flag",
                evidence=(
                    f"{len(missing_httponly)} cookie(s) without HttpOnly (names: {names(missing_httponly)}). "
                    "Cookie values are not recorded."
                ),
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to mark session cookies HttpOnly so page script cannot read them.",
                url=url,
            )
        )
    if missing_samesite:
        findings.append(
            _finding(
                severity="Low",
                check="cookie-samesite",
                title="A cookie is missing SameSite",
                evidence=(
                    f"{len(missing_samesite)} cookie(s) without SameSite (names: {names(missing_samesite)}). "
                    "Cookie values are not recorded."
                ),
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to set SameSite=Lax, or Strict if the site does not need cross-site cookies.",
                url=url,
            )
        )
    return findings


def grade_certificate(
    *,
    not_after: datetime | None,
    protocol: str | None,
    verified: bool,
    hostname_ok: bool,
    now: datetime | None = None,
    error: str | None = None,
    url: str = "",
) -> list[Finding]:
    """Grade a TLS certificate. A healthy certificate is reported as Info."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    findings: list[Finding] = []
    if error and not_after is None and not protocol:
        findings.append(
            _finding(
                severity="High",
                check="tls",
                title="TLS certificate could not be inspected",
                evidence=error,
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to confirm HTTPS is enabled and the certificate is current.",
                url=url,
            )
        )
        return findings
    if not verified:
        findings.append(
            _finding(
                severity="High",
                check="tls-untrusted",
                title="TLS certificate is not trusted",
                evidence="The certificate failed validation against this computer's trust store.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to install a publicly trusted certificate for this hostname.",
                url=url,
            )
        )
    if hostname_ok is False:
        findings.append(
            _finding(
                severity="High",
                check="tls-hostname",
                title="TLS certificate does not match the site name",
                evidence="The certificate name does not match the site Watson was asked to check.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to issue the certificate for the public site name.",
                url=url,
            )
        )
    if protocol:
        outdated = protocol in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"} or protocol.startswith(
            ("TLSv1.0", "TLSv1.1")
        )
        if outdated:
            findings.append(
                _finding(
                    severity="High",
                    check="tls-protocol",
                    title=f"Outdated TLS protocol ({protocol})",
                    evidence=f"The connection negotiated {protocol}.",
                    owner=OWNER_PLATFORM,
                    fix="Ask the platform team to disable TLS 1.0 and 1.1 and keep TLS 1.2 and 1.3.",
                    url=url,
                )
            )
        elif protocol == "TLSv1.2":
            findings.append(
                _finding(
                    severity="Info",
                    check="tls-protocol",
                    title="TLS 1.2 is in use",
                    evidence="The connection negotiated TLS 1.2. TLS 1.3 is preferred when the platform supports it.",
                    owner=OWNER_PLATFORM,
                    fix="No urgent action. Ask the platform team whether TLS 1.3 can be enabled.",
                    url=url,
                )
            )
    if not_after is not None:
        expiry = not_after if not_after.tzinfo else not_after.replace(tzinfo=timezone.utc)
        days = (expiry.date() - now.astimezone(expiry.tzinfo).date()).days
        if days < 0:
            findings.append(
                _finding(
                    severity="High",
                    check="tls-expiry",
                    title="TLS certificate has expired",
                    evidence=f"The certificate expired {abs(days)} day(s) ago.",
                    owner=OWNER_PLATFORM,
                    fix="Ask the platform team to renew the certificate now.",
                    url=url,
                )
            )
        elif days < 14:
            findings.append(
                _finding(
                    severity="High",
                    check="tls-expiry",
                    title="TLS certificate expires within 14 days",
                    evidence=f"The certificate expires in {days} day(s).",
                    owner=OWNER_PLATFORM,
                    fix="Ask the platform team to renew the certificate before it expires.",
                    url=url,
                )
            )
        elif days < 30:
            findings.append(
                _finding(
                    severity="Medium",
                    check="tls-expiry",
                    title="TLS certificate expires within 30 days",
                    evidence=f"The certificate expires in {days} day(s).",
                    owner=OWNER_PLATFORM,
                    fix="Ask the platform team to confirm renewal is scheduled.",
                    url=url,
                )
            )
        elif days < 60:
            findings.append(
                _finding(
                    severity="Low",
                    check="tls-expiry",
                    title="TLS certificate expires within 60 days",
                    evidence=f"The certificate expires in {days} day(s).",
                    owner=OWNER_PLATFORM,
                    fix="Ask the platform team to confirm renewal is scheduled.",
                    url=url,
                )
            )
        elif verified and hostname_ok and protocol == "TLSv1.3":
            findings.append(
                _finding(
                    severity="Info",
                    check="tls",
                    title="TLS certificate looks current",
                    evidence=f"Trusted certificate, {protocol}, expires in {days} day(s).",
                    owner=OWNER_PLATFORM,
                    fix="No action.",
                    url=url,
                )
            )
        elif verified and hostname_ok and not any(item.check == "tls-protocol" for item in findings):
            findings.append(
                _finding(
                    severity="Info",
                    check="tls",
                    title="TLS certificate is trusted",
                    evidence=f"Trusted certificate expires in {days} day(s). Protocol: {protocol or 'unknown'}.",
                    owner=OWNER_PLATFORM,
                    fix="No action.",
                    url=url,
                )
            )
    return findings


def grade_https_enforcement(
    *,
    site_scheme: str,
    tls_ok: bool,
    tls_error: str | None,
    http_status: int | None,
    http_location: str | None,
    url: str = "",
) -> list[Finding]:
    """Check that the public site is on HTTPS and that plain HTTP redirects to it."""
    if site_scheme != "https":
        evidence = "The site was requested with http://."
        if tls_error:
            evidence += f" A TLS connection did not succeed ({tls_error})."
        elif tls_ok:
            evidence += " HTTPS did respond. Plain HTTP should redirect to it."
        return [
            _finding(
                severity="High",
                check="https-enforcement",
                title="Site is not being served over HTTPS",
                evidence=evidence,
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to turn on HTTPS and redirect every HTTP address to HTTPS.",
                url=url,
            )
        ]
    if http_status is None and not http_location:
        return [
            _finding(
                severity="Low",
                check="https-redirect",
                title="The HTTP to HTTPS redirect could not be checked",
                evidence="Watson could not complete a request to the plain HTTP address.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to confirm that http:// redirects to https://.",
                url=url,
            )
        ]
    location = http_location or ""
    if http_status in {301, 302, 303, 307, 308} and location.startswith("https://"):
        return []
    if location.startswith("http://"):
        return [
            _finding(
                severity="High",
                check="https-redirect",
                title="HTTP redirect does not go to HTTPS",
                evidence=f"The plain HTTP address responded with HTTP {http_status} and stayed on http://.",
                owner=OWNER_PLATFORM,
                fix="Ask the platform team to redirect HTTP straight to HTTPS.",
                url=url,
            )
        ]
    return [
        _finding(
            severity="High",
            check="https-redirect",
            title="HTTP does not redirect to HTTPS",
            evidence=f"Requesting the http:// address returned HTTP {http_status}.",
            owner=OWNER_PLATFORM,
            fix="Ask the platform team to redirect every HTTP address to HTTPS with a permanent redirect.",
            url=url,
        )
    ]


def grade_banner(headers: Mapping[str, str], *, url: str = "") -> list[Finding]:
    exposed: list[str] = []
    for name in _BANNER_HEADERS:
        value = header_value(headers, name)
        if value and re.search(r"\d", value):
            exposed.append(f"{name}: {value}")
    if not exposed:
        return []
    return [
        _finding(
            severity="Low",
            check="version-banner",
            title="Server or platform version is advertised",
            evidence="; ".join(exposed),
            owner=OWNER_PLATFORM,
            fix="Ask the platform team to remove version numbers from Server and X-Powered-By if the host allows it.",
            url=url,
        )
    ]


def email_fingerprints(html: str) -> set[str]:
    """Hash addresses so a report can count them without storing them."""
    soup = BeautifulSoup(html or "", "html.parser")
    addresses = {match.lower() for match in EMAIL_RE.findall(soup.get_text(" ", strip=True))}
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"]
        if href.lower().startswith("mailto:"):
            address = href.split(":", 1)[1].split("?")[0].strip()
            if EMAIL_RE.fullmatch(address):
                addresses.add(address.lower())
    fingerprints = {hashlib.sha256(address.encode("utf-8")).hexdigest() for address in addresses}
    addresses.clear()
    return fingerprints


def count_email_addresses(html: str) -> int:
    """Count unique addresses on one page. The addresses are not returned."""
    return len(email_fingerprints(html))


def insecure_form_targets(html: str, page_url: str) -> list[str]:
    """Return form actions that explicitly post over http://."""
    soup = BeautifulSoup(html or "", "html.parser")
    targets: list[str] = []
    page_scheme = urlparse(page_url).scheme
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action.lower().startswith("http://"):
            targets.append(urljoin(page_url, action))
        elif page_scheme == "https":
            resolved = urljoin(page_url, action) if action else page_url
            if urlparse(resolved).scheme == "http":
                targets.append(resolved)
    return targets


def mixed_content_items(html: str, page_url: str) -> list[tuple[str, str, str]]:
    """Return (tag, absolute url, severity) for http resources on an https page."""
    if urlparse(page_url).scheme != "https":
        return []
    soup = BeautifulSoup(html or "", "html.parser")
    found: list[tuple[str, str, str]] = []
    for tag, (attr, severity) in _MIXED_TAGS.items():
        for element in soup.find_all(tag):
            if tag == "link":
                rel = " ".join(element.get("rel") or []).lower()
                if rel and "stylesheet" not in rel and "icon" not in rel:
                    continue
            raw = (element.get(attr) or "").strip()
            if raw.lower().startswith("http://"):
                found.append((tag, urljoin(page_url, raw), severity))
            if element.get("srcset"):
                for part in str(element.get("srcset")).split(","):
                    candidate = part.strip().split(" ")[0]
                    if candidate.lower().startswith("http://"):
                        found.append((tag, urljoin(page_url, candidate), severity))
    return found


def third_party_embeds(html: str, page_url: str) -> list[tuple[str, str]]:
    """Return (tag, host) for script, frame, and object embeds on other hosts."""
    page_host = (urlparse(page_url).hostname or "").lower()
    soup = BeautifulSoup(html or "", "html.parser")
    found: list[tuple[str, str]] = []
    for tag, attr in _EMBED_TAGS.items():
        for element in soup.find_all(tag):
            raw = (element.get(attr) or "").strip()
            if not raw or raw.startswith(("data:", "javascript:", "mailto:")):
                continue
            absolute = urljoin(page_url, raw)
            host = (urlparse(absolute).hostname or "").lower()
            if host and host != page_host:
                found.append((tag, host))
    return found


def library_hits_for_html(html: str, page_url: str) -> list[LibraryHit]:
    soup = BeautifulSoup(html or "", "html.parser")
    hits: list[LibraryHit] = []
    for element in soup.find_all("script"):
        if element.string:
            hits.extend(detect_libraries(element.string, page_url))
        src = element.get("src")
        if src:
            absolute = urljoin(page_url, src)
            hits.extend(detect_libraries(absolute, absolute))
            hits.extend(detect_libraries(src, absolute))
    for element in soup.find_all("link", href=True):
        absolute = urljoin(page_url, element["href"])
        hits.extend(detect_libraries(absolute, absolute))
    return hits


def _add_library(
    findings: list[Finding],
    seen: set[tuple[str, str]],
    hit: LibraryHit,
    *,
    page_url: str,
) -> None:
    key = (hit.name, hit.version)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        _finding(
            severity=hit.severity,
            check="outdated-library",
            title=f"{hit.name} {hit.version} is outdated",
            evidence=f"{hit.name} {hit.version} is loaded from {redact(hit.evidence_source, limit=180)}.",
            owner=OWNER_EDITOR,
            fix=hit.fix,
            url=page_url,
        )
    )


def content_findings(
    pages: list[tuple[str, str]],
    extra_texts: list[tuple[str, str]] | None = None,
) -> list[Finding]:
    """Findings that come from HTML Watson has already downloaded."""
    findings: list[Finding] = []
    email_pages: list[tuple[str, int]] = []
    email_ids: set[str] = set()
    seen_libraries: set[tuple[str, str]] = set()
    seen_embeds: set[tuple[str, str, str]] = set()
    seen_forms: set[str] = set()
    for url, html in pages:
        fingerprints = email_fingerprints(html)
        if fingerprints:
            email_pages.append((url, len(fingerprints)))
            email_ids.update(fingerprints)
        for target in insecure_form_targets(html, url):
            host = urlparse(target).hostname or "an http address"
            if target in seen_forms:
                continue
            seen_forms.add(target)
            findings.append(
                _finding(
                    severity="High",
                    check="insecure-form",
                    title="A form posts over HTTP",
                    evidence=f"A form on this page posts to http://{host}. The full action is not repeated.",
                    owner=OWNER_EDITOR,
                    fix="Point the form at an https:// address, or ask the platform team if the form is part of the template.",
                    url=url,
                )
            )
        mixed = mixed_content_items(html, url)
        if mixed:
            high = sum(1 for _tag, _target, level in mixed if level == "High")
            other = len(mixed) - high
            level = "High" if high else "Medium"
            findings.append(
                _finding(
                    severity=level,
                    check="mixed-content",
                    title="HTTPS page loads resources over HTTP",
                    evidence=(
                        f"{high} active item(s) (script or frame) and {other} other item(s) use http://. "
                        "Addresses are omitted beyond the page they were found on."
                    ),
                    owner=OWNER_EDITOR,
                    fix="Change those addresses to https://, or remove the resource if it has no HTTPS version.",
                    url=url,
                )
            )
        for hit in library_hits_for_html(html, url):
            _add_library(findings, seen_libraries, hit, page_url=url)
        for tag, host in third_party_embeds(html, url):
            key = (url, tag, host)
            if key in seen_embeds:
                continue
            seen_embeds.add(key)
            if any(item.check == "outdated-library" and host in item.evidence for item in findings):
                continue
            article = "an" if tag[:1].lower() in "aeiou" else "a"
            findings.append(
                _finding(
                    severity="Info",
                    check="third-party-embed",
                    title=f"Page loads {article} {tag} from another site",
                    evidence=f"{article.capitalize()} {tag} is loaded from {host}. Watson did not download the third-party file.",
                    owner=OWNER_EDITOR,
                    fix="Confirm this embed is still wanted and that the provider is expected.",
                    url=url,
                )
            )
    for label, text in extra_texts or []:
        for hit in detect_libraries(text, label):
            _add_library(findings, seen_libraries, hit, page_url=label)
    if email_pages:
        locations = ", ".join(f"{page} ({count})" for page, count in email_pages[:12])
        findings.append(
            _finding(
                severity="Low",
                check="exposed-email",
                title="Email addresses are visible in page HTML",
                evidence=(
                    f"{len(email_ids)} unique email {'address' if len(email_ids) == 1 else 'addresses'} across {len(email_pages)} page(s). "
                    f"Addresses are not included. Pages: {locations}."
                ),
                owner=OWNER_EDITOR,
                fix=(
                    "Remove personal addresses from public pages where you can. "
                    "A role address or a contact form is easier to change later."
                ),
                url=email_pages[0][0],
            )
        )
    return findings


def document_metadata_finding(url: str, suffix: str) -> Finding:
    kind = "PDF" if suffix == ".pdf" else "Word document"
    return _finding(
        severity="Low",
        check="document-metadata",
        title=f"{kind} has author metadata",
        evidence=(
            f"This {kind} has author or creator metadata. "
            "The values are not included in this report."
        ),
        owner=OWNER_EDITOR,
        fix=(
            "Remove document properties before publishing. "
            "In Word, use Info → Check for Issues → Inspect Document, then save a fresh PDF."
        ),
        url=url,
    )


def dangling_domain_finding(host: str, count: int, example_page: str) -> Finding:
    return _finding(
        severity="Medium",
        check="dangling-domain",
        title=f"External link host does not resolve ({host})",
        evidence=(
            f"{host} did not resolve. {count} link(s) point at it. "
            "Someone could register this name and take over the link."
        ),
        owner=OWNER_EDITOR,
        fix="Remove or replace the link. If the organisation still owns the name, ask them to renew it.",
        url=example_page,
    )


def security_txt_finding(*, present: bool, url: str) -> Finding:
    if present:
        return _finding(
            severity="Info",
            check="security-txt",
            title="security.txt is published",
            evidence=(
                "A security.txt file was found. Contact details from the file are not copied into this report."
            ),
            owner=OWNER_PLATFORM,
            fix="No action unless the contact in that file is out of date. Ask the platform team to review it.",
            url=url,
        )
    return _finding(
        severity="Info",
        check="security-txt",
        title="security.txt was not found",
        evidence="No file was found at /.well-known/security.txt or /security.txt.",
        owner=OWNER_PLATFORM,
        fix="Optional. Ask the host if a security.txt contact should be published.",
        url=url,
    )


def robots_sitemap_finding(
    *,
    disallow: list[str],
    fetched: bool,
    sitemap_count: int | None,
    sensitive_paths: list[str],
    sitemap_offsite: bool,
    url: str,
) -> Finding:
    if not fetched:
        evidence = "robots.txt could not be fetched. Watson allowed the crawl and did not guess hidden paths."
    else:
        shown = ", ".join(disallow[:12]) if disallow else "none"
        extra = ""
        if len(disallow) > 12:
            extra = f" ({len(disallow) - 12} more not listed)"
        evidence = f"Disallow rules: {shown}{extra}."
        if sitemap_offsite:
            evidence += " The sitemap points at another host and was not downloaded."
        elif sitemap_count is None:
            evidence += " No same-site sitemap was downloaded."
        else:
            evidence += f" Sitemap lists {sitemap_count} address(es)."
        if sensitive_paths:
            evidence += " Paths that look operational: " + ", ".join(sensitive_paths[:8]) + "."
    return _finding(
        severity="Info",
        check="robots-sitemap",
        title="Notes from robots.txt and the sitemap",
        evidence=evidence,
        owner=OWNER_PLATFORM,
        fix=(
            "Disallow rules are not access control. "
            "Ask the platform team to review anything sensitive that a public sitemap advertises."
        ),
        url=url,
    )


def sensitive_paths(urls: list[str]) -> list[str]:
    found: list[str] = []
    for item in urls:
        path = urlparse(item).path or item
        if _SENSITIVE_PATH.search(path) and path not in found:
            found.append(path)
    return found[:8]


def apply_osv(findings: list[Finding], lookups: dict[tuple[str, str], list[str]]) -> list[Finding]:
    """Attach opt-in OSV ids. `lookups` maps (library name, version) to ids."""
    if not lookups:
        return findings
    updated: list[Finding] = []
    for finding in findings:
        if finding.check != "outdated-library":
            updated.append(finding)
            continue
        matched: list[str] | None = None
        for (name, version), ids in lookups.items():
            if finding.title.startswith(f"{name} {version}"):
                matched = ids
                break
        if not matched:
            updated.append(finding)
            continue
        shown = ", ".join(matched[:8])
        evidence = finding.evidence + f" OSV ids: {shown}."
        severity = finding.severity
        if severity in {"Low", "Info"}:
            severity = "Medium"
        updated.append(
            Finding(
                severity=severity,
                check=finding.check,
                title=finding.title,
                evidence=redact(evidence, limit=500),
                owner=finding.owner,
                fix=finding.fix,
                url=finding.url,
            )
        )
    return updated
