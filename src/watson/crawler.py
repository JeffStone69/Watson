"""Crawl same-site HTML pages and collect links from them."""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from watson.http_client import Fetcher
from watson.models import Page, Reference
from watson.redact import redact, redact_url

_SKIP_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".css",
    ".js",
    ".mjs",
    ".doc",
    ".docx",
    ".zip",
    ".mp3",
    ".mp4",
    ".ico",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".xml",
    ".json",
    ".txt",
}
_ATTRS = (
    ("a", "href", "a"),
    ("area", "href", "area"),
    ("img", "src", "img"),
    ("script", "src", "script"),
    ("iframe", "src", "iframe"),
    ("embed", "src", "embed"),
    ("audio", "src", "audio"),
    ("video", "src", "video"),
    ("source", "src", "source"),
    ("object", "data", "object"),
    ("link", "href", "link"),
    ("form", "action", "form"),
)
_SKIP_PREFIXES = ("#", "mailto:", "tel:", "javascript:", "data:")
_SITEMAP_LINE = re.compile(r"(?im)^sitemap:\s*(\S+)")


def hostname_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower().rstrip(".")


def same_site(url: str, start_url: str) -> bool:
    return hostname_of(url) == hostname_of(start_url) and bool(hostname_of(url))


def looks_like_page(url: str) -> bool:
    suffix = Path(urlparse(url).path).suffix.lower()
    return suffix not in _SKIP_EXTENSIONS


def strip_fragment(url: str) -> str:
    cleaned, _fragment = urldefrag(url)
    return cleaned


def robots_from_text(text: str) -> RobotFileParser:
    parser = RobotFileParser()
    parser.parse(text.splitlines())
    return parser


def allowed_by_robots(parser: RobotFileParser | None, user_agent: str, url: str) -> bool:
    if parser is None:
        return True
    try:
        return parser.can_fetch(user_agent, url)
    except Exception:
        return True


def charset_from(content_type: str) -> str:
    match = re.search(r"charset=([\w.-]+)", content_type or "", re.IGNORECASE)
    return match.group(1) if match else "utf-8"


def decode_html(body: bytes, content_type: str) -> str:
    encoding = charset_from(content_type)
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _srcset_urls(value: str) -> list[str]:
    urls: list[str] = []
    for part in value.split(","):
        candidate = part.strip().split(" ")[0].strip()
        if candidate:
            urls.append(candidate)
    return urls


def extract_references(html: str, base_url: str) -> list[Reference]:
    """Collect links and embedded resources. Email and phone links are skipped."""
    soup = BeautifulSoup(html or "", "html.parser")
    found: list[Reference] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(kind: str, raw: str, element) -> None:
        original = (raw or "").strip()
        if not original or original.lower().startswith(_SKIP_PREFIXES):
            return
        absolute = strip_fragment(urljoin(base_url, original))
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            return
        text = ""
        if hasattr(element, "get_text"):
            text = element.get_text(" ", strip=True)
        if not text and hasattr(element, "get"):
            text = element.get("alt") or element.get("title") or element.get("aria-label") or ""
        text = redact(str(text))
        if not text:
            text = redact(Path(urlparse(absolute).path).name)
        absolute = redact_url(absolute)
        key = (absolute, original, text, kind)
        if key in seen:
            return
        seen.add(key)
        found.append(Reference(url=absolute, raw=original, source_url=base_url, text=text, kind=kind))

    for tag, attr, kind in _ATTRS:
        for element in soup.find_all(tag):
            raw = element.get(attr)
            if isinstance(raw, str):
                add(kind, raw, element)
            elif kind == "form":
                # An empty action posts back to this page. It is not an authored http:// link.
                continue
            srcset = element.get("srcset") if hasattr(element, "get") else None
            if isinstance(srcset, str):
                for candidate in _srcset_urls(srcset):
                    add(tag, candidate, element)
    return found


def meta_refresh_target(html: str, base_url: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    for meta in soup.find_all("meta"):
        if (meta.get("http-equiv") or "").lower() != "refresh":
            continue
        content = meta.get("content") or ""
        match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.IGNORECASE)
        if not match:
            continue
        return strip_fragment(urljoin(base_url, match.group(1).strip()))
    return ""


def page_title_and_heading(html: str) -> tuple[str, str]:
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    heading = soup.h1.get_text(" ", strip=True) if soup.h1 else ""
    return redact(title, limit=120), redact(heading, limit=120)


def sitemap_urls_from_robots(text: str) -> list[str]:
    return [match.strip() for match in _SITEMAP_LINE.findall(text or "")]


def parse_sitemap_locs(xml_text: str) -> list[str]:
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml_text or "", flags=re.IGNORECASE)


class CrawlError(RuntimeError):
    """The start URL could not be fetched."""


def crawl(
    fetcher: Fetcher,
    start_url: str,
    *,
    max_pages: int,
    max_depth: int,
    robots: RobotFileParser | None,
    user_agent: str,
) -> list[Page]:
    """Breadth-first crawl of same-site HTML. Non-HTML links are left for the link checker."""
    queue: deque[tuple[str, int]] = deque([(strip_fragment(start_url), 0)])
    seen: set[str] = set()
    pages: list[Page] = []
    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        url = strip_fragment(url)
        if url in seen or not same_site(url, start_url) or not looks_like_page(url):
            continue
        seen.add(url)
        if not allowed_by_robots(robots, user_agent, url):
            continue
        result = fetcher.get(url)
        hops = 0
        current = url
        followed_to_existing = False
        while (
            result.error is None
            and result.status in {301, 302, 303, 307, 308}
            and result.location
            and hops < 5
        ):
            hops += 1
            nxt = strip_fragment(result.location)
            if not same_site(nxt, start_url) or not allowed_by_robots(robots, user_agent, nxt):
                break
            if nxt in seen:
                followed_to_existing = True
                break
            seen.add(nxt)
            current = nxt
            result = fetcher.get(current)
        if followed_to_existing:
            continue
        if result.error or result.status != 200 or not result.body:
            if not pages and url == strip_fragment(start_url):
                reason = result.error or f"HTTP {result.status}"
                raise CrawlError(f"Could not read the start page ({reason}).")
            continue
        content_type = result.content_type or ""
        if "html" not in content_type.lower() and not result.body.lstrip().startswith(b"<"):
            continue
        html = decode_html(result.body, content_type)
        pages.append(
            Page(
                url=current,
                status=result.status or 0,
                content_type=content_type,
                html=html,
                headers={key.lower(): value for key, value in result.headers.items()},
                set_cookies=list(result.set_cookies),
                depth=depth,
            )
        )
        if depth >= max_depth:
            continue
        for reference in extract_references(html, current):
            if reference.kind == "a" and same_site(reference.url, start_url) and looks_like_page(reference.url):
                queue.append((reference.url, depth + 1))
    if not pages:
        raise CrawlError("Could not read the start page.")
    return pages
