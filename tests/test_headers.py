"""Header, cookie, and certificate grading."""

from datetime import datetime, timedelta, timezone

from watson.models import OWNER_PLATFORM
from watson.security import (
    grade_certificate,
    grade_cookies,
    grade_headers,
    grade_https_enforcement,
    parse_set_cookie,
)

URL = "https://example-school.example.edu/"
NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)


def _checks(findings):
    return {finding.check for finding in findings}


def test_missing_headers_on_https():
    findings = grade_headers({}, scheme="https", url=URL)
    checks = _checks(findings)
    assert "content-security-policy" in checks
    assert "clickjacking" in checks
    assert "x-content-type-options" in checks
    assert "referrer-policy" in checks
    assert "permissions-policy" in checks
    assert "hsts" in checks
    assert all(finding.owner == OWNER_PLATFORM for finding in findings)


def test_hsts_is_not_required_on_plain_http():
    findings = grade_headers({}, scheme="http", url="http://example-school.example.edu/")
    assert "hsts" not in _checks(findings)


def test_good_headers_have_no_findings():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    assert grade_headers(headers, scheme="https", url=URL) == []


def test_x_frame_options_covers_clickjacking_and_unsafe_csp_is_low():
    headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
        "Strict-Transport-Security": "max-age=15552000",
    }
    findings = grade_headers(headers, scheme="https", url=URL)
    assert [finding.check for finding in findings] == ["csp-unsafe"]
    assert findings[0].severity == "Low"


def test_unsafe_referrer_and_short_hsts():
    headers = {
        "Content-Security-Policy": "frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "unsafe-url",
        "Permissions-Policy": "camera=()",
        "Strict-Transport-Security": "max-age=60",
    }
    checks = {finding.check: finding.severity for finding in grade_headers(headers, scheme="https")}
    assert checks["referrer-policy"] == "Medium"
    assert checks["hsts"] == "Low"


def test_cookie_flags_do_not_keep_the_value():
    header = "session=example-secret-value; Path=/"
    parsed = parse_set_cookie(header)
    assert "value" not in parsed
    assert parsed["name"] == "session"
    findings = grade_cookies([header], scheme="https", url=URL)
    blob = " ".join(finding.evidence for finding in findings)
    assert "example-secret-value" not in blob
    assert "session" in blob
    severities = {finding.check: finding.severity for finding in findings}
    assert severities["cookie-secure"] == "Medium"
    assert severities["cookie-httponly"] == "Medium"
    assert severities["cookie-samesite"] == "Low"


def test_secure_cookie_on_http_is_low():
    findings = grade_cookies(["session=1; Path=/"], scheme="http")
    secure = next(finding for finding in findings if finding.check == "cookie-secure")
    assert secure.severity == "Low"


def test_certificate_expiry_and_old_protocol():
    soon = grade_certificate(
        not_after=NOW + timedelta(days=10),
        protocol="TLSv1.3",
        verified=True,
        hostname_ok=True,
        now=NOW,
    )
    assert any(finding.check == "tls-expiry" and finding.severity == "High" for finding in soon)
    old = grade_certificate(
        not_after=NOW + timedelta(days=200),
        protocol="TLSv1.0",
        verified=True,
        hostname_ok=True,
        now=NOW,
    )
    assert any(finding.check == "tls-protocol" and finding.severity == "High" for finding in old)
    healthy = grade_certificate(
        not_after=NOW + timedelta(days=200),
        protocol="TLSv1.3",
        verified=True,
        hostname_ok=True,
        now=NOW,
    )
    assert healthy
    assert all(finding.severity == "Info" for finding in healthy)
    assert "200" in healthy[0].evidence


def test_untrusted_certificate_is_high():
    findings = grade_certificate(
        not_after=NOW + timedelta(days=200),
        protocol="TLSv1.3",
        verified=False,
        hostname_ok=False,
        now=NOW,
    )
    checks = _checks(findings)
    assert "tls-untrusted" in checks
    assert "tls-hostname" in checks


def test_https_enforcement():
    http_only = grade_https_enforcement(
        site_scheme="http",
        tls_ok=False,
        tls_error="TLS handshake failed",
        http_status=200,
        http_location=None,
    )
    assert http_only[0].severity == "High"
    assert http_only[0].owner == OWNER_PLATFORM
    missing_redirect = grade_https_enforcement(
        site_scheme="https",
        tls_ok=True,
        tls_error=None,
        http_status=200,
        http_location=None,
    )
    assert missing_redirect[0].check == "https-redirect"
    good = grade_https_enforcement(
        site_scheme="https",
        tls_ok=True,
        tls_error=None,
        http_status=301,
        http_location="https://example-school.example.edu/",
    )
    assert good == []
