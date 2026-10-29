"""Shared result types. Page HTML stays in memory and is never serialised."""

from __future__ import annotations

from dataclasses import dataclass, field


OWNER_PLATFORM = "Platform/hosting provider"
OWNER_EDITOR = "School content editor"

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


@dataclass
class Page:
    url: str
    status: int
    content_type: str
    html: str
    headers: dict[str, str]
    set_cookies: list[str]
    depth: int


@dataclass
class Reference:
    """A link or embedded resource as written on a page."""

    url: str
    raw: str
    source_url: str
    text: str
    kind: str


@dataclass
class LinkResult:
    url: str
    source_url: str
    link_text: str
    category: str
    reason: str
    status: int | None = None
    location: str = ""
    soft_404: bool = False
    error: str = ""
    severity: str = "Info"
    owner: str = OWNER_EDITOR
    fix: str = ""


@dataclass
class Finding:
    severity: str
    check: str
    title: str
    evidence: str
    owner: str
    fix: str
    url: str = ""


@dataclass
class UpdateRow:
    kind: str
    severity: str
    page_url: str
    observed_date: str
    detail: str
    owner: str = OWNER_EDITOR
    fix: str = ""


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    pages: list[Page]
    links: list[LinkResult]
    updates: list[UpdateRow]
    findings: list[Finding]
    newest_newsletter: str
    newest_news: str
    newest_event: str
    user_agent: str
    external_skipped: int
    notes: list[str] = field(default_factory=list)
    checklist: list[tuple[str, str]] = field(default_factory=list)
    exit_code: int = 0

    def links_in(self, category: str) -> list[LinkResult]:
        return [item for item in self.links if item.category == category]
