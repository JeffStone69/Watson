"""Polite HTTP client. One request at a time, with a fixed User-Agent."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

import httpx

from watson import USER_AGENT

# These names are reserved for documentation and do not resolve on the public DNS.
_NONRESOLVING_SUFFIXES = (".invalid", ".example", ".test")


def polite_interval(rate: float, crawl_delay: float | None = None) -> float:
    if rate <= 0:
        raise ValueError("rate must be greater than zero")
    interval = 1.0 / rate
    if crawl_delay:
        interval = max(interval, float(crawl_delay))
    return interval


class RateLimiter:
    """Sleep so requests stay at or below `rate` per second."""

    def __init__(
        self,
        rate: float,
        crawl_delay: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self.interval = polite_interval(rate, crawl_delay)
        self.sleep = sleep
        self.now = now
        self._next = 0.0

    def set_crawl_delay(self, crawl_delay: float | None, rate: float) -> None:
        self.interval = polite_interval(rate, crawl_delay)

    def wait(self) -> None:
        current = self.now()
        if self._next <= current:
            self._next = current
        else:
            self.sleep(self._next - current)
        self._next += self.interval


def is_nonresolving_host(host: str) -> bool:
    """True for reserved documentation names such as `sponsor.invalid`."""
    cleaned = (host or "").lower().rstrip(".")
    if not cleaned or cleaned == "localhost":
        return False
    for suffix in _NONRESOLVING_SUFFIXES:
        if cleaned == suffix[1:] or cleaned.endswith(suffix):
            return True
    return False


def classify_connect(exc: BaseException) -> str:
    """Map a connection error to dns, refused, timeout, or connect."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, (TimeoutError, socket.timeout)):
            return "timeout"
        if isinstance(current, ConnectionRefusedError):
            return "refused"
        if isinstance(current, socket.gaierror):
            return "dns"
        text = str(current).lower()
        if any(
            phrase in text
            for phrase in (
                "name or service not known",
                "nodename nor servname",
                "getaddrinfo",
                "no address associated",
                "temporary failure in name resolution",
                "name resolution",
            )
        ):
            return "dns"
        if "connection refused" in text or "actively refused" in text:
            return "refused"
        if "timed out" in text or "timeout" in text:
            return "timeout"
        current = current.__cause__ or current.__context__
    return "connect"


@dataclass
class FetchResult:
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    content_type: str = ""
    error: str | None = None
    location: str = ""
    method: str = "GET"


class Fetcher:
    """GET and HEAD against the target, paced, without storing cookies."""

    def __init__(
        self,
        *,
        rate: float,
        timeout: float,
        user_agent: str = USER_AGENT,
        start_url: str = "",
        trust_env: bool = True,
    ) -> None:
        self.user_agent = user_agent
        self.start_url = start_url
        self.limiter = RateLimiter(rate)
        self.rate = rate
        self.cache: dict[tuple[str, str, int], FetchResult] = {}
        host = (urlparse(start_url).hostname or "").lower()
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        self.client = httpx.Client(
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en",
            },
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            follow_redirects=False,
            trust_env=False if loopback else trust_env,
            limits=httpx.Limits(max_keepalive_connections=0, max_connections=1),
            event_hooks={"response": [self._drop_cookies]},
        )

    def _drop_cookies(self, response: httpx.Response) -> None:
        self.client.cookies.clear()
        response.cookies.clear()

    def close(self) -> None:
        self.client.close()

    def get(self, url: str, *, limit: int = 2_000_000) -> FetchResult:
        return self._request("GET", url, limit=limit)

    def head(self, url: str) -> FetchResult:
        return self._request("HEAD", url, limit=0)

    def _request(self, method: str, url: str, *, limit: int) -> FetchResult:
        key = (method, url, limit)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            result = FetchResult(url=url, error="unsupported", method=method)
            self.cache[key] = result
            return result
        host = parsed.hostname or ""
        if is_nonresolving_host(host):
            result = FetchResult(url=url, error="dns", method=method)
            self.cache[key] = result
            return result
        self.limiter.wait()
        try:
            if method == "HEAD":
                response = self.client.head(url)
                result = self._from_response(url, method, response, b"")
            else:
                with self.client.stream("GET", url) as response:
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        if not chunk:
                            continue
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= limit:
                            break
                    body = b"".join(chunks)[:limit]
                    result = self._from_response(url, method, response, body)
        except httpx.TimeoutException:
            result = FetchResult(url=url, error="timeout", method=method)
        except httpx.ConnectError as exc:
            result = FetchResult(url=url, error=classify_connect(exc), method=method)
        except httpx.TransportError as exc:
            result = FetchResult(url=url, error=classify_connect(exc), method=method)
        self.cache[key] = result
        return result

    def _from_response(
        self,
        url: str,
        method: str,
        response: httpx.Response,
        body: bytes,
    ) -> FetchResult:
        headers = {key: value for key, value in response.headers.items()}
        content_type = headers.get("content-type", headers.get("Content-Type", ""))
        location = response.headers.get("location", "")
        if location:
            location = str(httpx.URL(url).join(location))
        try:
            cookies = response.headers.get_list("set-cookie")
        except Exception:
            raw = response.headers.get("set-cookie", "")
            cookies = [raw] if raw else []
        return FetchResult(
            url=url,
            status=response.status_code,
            headers=headers,
            set_cookies=list(cookies),
            body=body,
            content_type=content_type,
            location=location,
            method=method,
        )
