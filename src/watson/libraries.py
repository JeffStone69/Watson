"""Detect library versions from URLs and file banners. No exploit checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache

from watson.resources import resource_path


@dataclass(frozen=True)
class LibraryHit:
    name: str
    version: str
    severity: str
    fix: str
    evidence_source: str


def version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in value.split("."):
        digits = ""
        for character in piece:
            if character.isdigit():
                digits += character
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def version_older(left: str, right: str) -> bool:
    """True when `left` is older than `right`. Missing pieces compare as zero."""
    first, second = version_tuple(left), version_tuple(right)
    width = max(len(first), len(second))
    first = first + (0,) * (width - len(first))
    second = second + (0,) * (width - len(second))
    return first < second


@lru_cache(maxsize=1)
def load_library_rules() -> list[dict]:
    path = resource_path("data", "libraries.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("libraries.json must be a list")
    return data


def severity_for(version: str, thresholds: list[dict]) -> str | None:
    ordered = sorted(thresholds, key=lambda item: version_tuple(str(item.get("below", "0"))))
    for threshold in ordered:
        boundary = str(threshold.get("below", ""))
        level = str(threshold.get("severity", ""))
        if boundary and level and version_older(version, boundary):
            return level
    return None


def detect_libraries(text: str, source: str) -> list[LibraryHit]:
    """Return outdated or flagged libraries mentioned in `text`."""
    if not text:
        return []
    hits: list[LibraryHit] = []
    seen: set[tuple[str, str]] = set()
    for rule in load_library_rules():
        name = str(rule.get("name", ""))
        fix = str(rule.get("fix", "Upgrade this library to a current supported release."))
        thresholds = list(rule.get("thresholds") or [])
        for pattern in rule.get("patterns") or []:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            for match in compiled.finditer(text):
                version = match.group(1)
                if not version or (name, version) in seen:
                    continue
                level = severity_for(version, thresholds)
                if not level:
                    continue
                seen.add((name, version))
                hits.append(
                    LibraryHit(
                        name=name,
                        version=version,
                        severity=level,
                        fix=fix,
                        evidence_source=source,
                    )
                )
    return hits
