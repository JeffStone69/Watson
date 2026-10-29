"""Classify one link into broken, couldn't verify, redirect, or insecure."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

BROKEN = "broken"
UNVERIFIED = "unverified"
REDIRECT = "redirect"
INSECURE = "insecure"
OK = "ok"

BROKEN_ERRORS = {"dns", "refused", "timeout"}
REDIRECT_STATUSES = {300, 301, 302, 303, 307, 308}
HOME_PATHS = {
    "/",
    "/index.html",
    "/index.htm",
    "/index.php",
    "/home",
    "/default.aspx",
    "/default.asp",
}

NOT_FOUND_PATH = re.compile(
    r"(404|not-found|notfound|page-not-found|pagenotfound|error-404|file-not-found)",
    re.IGNORECASE,
)
NOT_FOUND_TITLE = re.compile(
    r"("
    r"page\s+(could\s+)?not\s+be\s+found"
    r"|page\s+not\s+found"
    r"|404(\s+not\s+found)?"
    r"|doesn['’]t\s+exist"
    r"|does\s+not\s+exist"
    r"|no\s+longer\s+available"
    r"|we\s+can['’]t\s+find"
    r"|the\s+page\s+you\s+(requested|were\s+looking\s+for)"
    r")",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Classification:
    category: str
    reason: str
    soft_404: bool = False


def _path(url: str) -> str:
    path = urlparse(url).path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return path.lower()


def _same(left: str, right: str) -> bool:
    parsed_left, parsed_right = urlparse(left), urlparse(right)
    if (parsed_left.hostname or "").lower() != (parsed_right.hostname or "").lower():
        return False
    return _path(left) == _path(right) and parsed_left.query == parsed_right.query


def is_home_url(url: str, home_url: str) -> bool:
    """True when `url` is the site home page."""
    if not url or not home_url:
        return False
    if (urlparse(url).hostname or "").lower() != (urlparse(home_url).hostname or "").lower():
        return False
    return _path(url) in HOME_PATHS or _path(url) == _path(home_url)


def is_not_found_path(url: str) -> bool:
    return bool(NOT_FOUND_PATH.search(urlparse(url).path or ""))


def body_looks_like_not_found(title: str, heading: str) -> bool:
    return bool(NOT_FOUND_TITLE.search(f"{title or ''} {heading or ''}"))


def _resolve(location: str | None, requested_url: str) -> str:
    if not location:
        return ""
    if "://" not in location:
        return urljoin(requested_url, location)
    return location


def detect_soft_404(
    *,
    requested_url: str,
    status: int | None,
    location: str | None,
    home_url: str,
    title: str = "",
    heading: str = "",
) -> bool:
    """Return True for a soft 404.

    A soft 404 is a redirect to the home page or to a generic not-found page,
    or a 200 response whose title or top heading says the page does not exist.
    A real HTTP 404 or 410 is a hard break, and the not-found page itself is
    not reported again.
    """
    if status in (404, 410):
        return False
    target = _resolve(location, requested_url)
    if is_not_found_path(requested_url) and (not target or _same(target, requested_url)):
        return False
    if target and not _same(target, requested_url):
        if is_home_url(target, home_url) and not is_home_url(requested_url, home_url):
            return True
        if is_not_found_path(target):
            return True
    if status is not None and 200 <= status < 300:
        if body_looks_like_not_found(title, heading) and not is_not_found_path(requested_url):
            return True
    return False


def raw_href_is_http(raw: str | None) -> bool:
    """True only when the author wrote an http:// URL, not a relative link."""
    return bool(raw) and raw.strip().lower().startswith("http://")


def _soft_reason(location: str | None, home_url: str, requested_url: str) -> str:
    target = _resolve(location, requested_url)
    if target and is_home_url(target, home_url):
        return "Redirects to the home page (soft 404)"
    if target and is_not_found_path(target):
        return "Redirects to a not-found page (soft 404)"
    return "Page looks like a generic not-found page (soft 404)"


def classify_link(
    *,
    status: int | None,
    error: str | None,
    location: str | None,
    requested_url: str,
    home_url: str,
    raw_href: str | None = None,
    title: str = "",
    heading: str = "",
) -> Classification:
    """Classify one checked URL.

    Broken wins over the other groups. A working ``http://`` link is insecure.
    Redirects, including soft 404s, are their own group.
    """
    insecure = raw_href_is_http(raw_href)
    soft = detect_soft_404(
        requested_url=requested_url,
        status=status,
        location=location,
        home_url=home_url,
        title=title,
        heading=heading,
    )
    if error in BROKEN_ERRORS or status in (404, 410):
        reason = {
            "dns": "DNS lookup failed",
            "refused": "Connection refused",
            "timeout": "Timed out",
        }.get(error or "", f"HTTP {status}")
        if insecure:
            reason = f"{reason} (link uses http://)"
        return Classification(BROKEN, reason, False)
    if error:
        return Classification(UNVERIFIED, f"Could not verify ({error})", False)
    if status in (401, 403, 429, 999) or (status is not None and status >= 500):
        return Classification(UNVERIFIED, f"HTTP {status}", False)
    if soft:
        return Classification(REDIRECT, _soft_reason(location, home_url, requested_url), True)
    if status in REDIRECT_STATUSES:
        destination = location or "another address"
        reason = f"Redirects to {destination}"
        if insecure:
            reason = f"{reason} (link uses http://)"
        return Classification(REDIRECT, reason, False)
    if status is not None and 400 <= status < 500:
        return Classification(UNVERIFIED, f"HTTP {status}", False)
    if insecure:
        return Classification(INSECURE, "Link uses http:// and should use https://", False)
    if status in (204, 304) or (status is not None and 200 <= status < 300):
        return Classification(OK, f"HTTP {status}", False)
    if status is None:
        return Classification(UNVERIFIED, "No response", False)
    return Classification(UNVERIFIED, f"HTTP {status}", False)


def link_severity(classification: Classification) -> tuple[str, str]:
    """Return a severity and a short fix for a classified link."""
    if classification.category == BROKEN:
        return (
            "Medium",
            "Update or remove the link. If the document moved, link to the new address.",
        )
    if classification.category == UNVERIFIED:
        return (
            "Info",
            "Open the link in a normal browser. If it loads, the other site may be blocking automated checks.",
        )
    if classification.soft_404:
        return (
            "Medium",
            "Replace the link. It sends people to the home page or a generic not-found page.",
        )
    if classification.category == REDIRECT:
        return (
            "Info",
            "Point the link at the final address if you do not need the old address.",
        )
    if classification.category == INSECURE:
        return (
            "Low",
            "Change http:// to https:// when the target supports HTTPS.",
        )
    return ("Info", "")
