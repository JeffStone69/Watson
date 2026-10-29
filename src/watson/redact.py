"""Remove email addresses from text that may be copied into a report."""

from __future__ import annotations

import re

# Addresses are replaced and discarded. The pattern is intentionally ordinary.
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def redact(text: str, limit: int = 180) -> str:
    """Collapse whitespace, strip email addresses, and cap length."""
    if not text:
        return ""
    cleaned = EMAIL_RE.sub("[redacted-email]", text)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        return cleaned[: limit - 1] + "…"
    return cleaned


def redact_url(url: str) -> str:
    """Strip email addresses from a URL without otherwise rewriting it."""
    if not url:
        return ""
    return EMAIL_RE.sub("[redacted-email]", url)


def excel_safe(value: str) -> str:
    """Stop a cell being interpreted as a formula."""
    if value and value[0] in "=-+@":
        return "'" + value
    return value
