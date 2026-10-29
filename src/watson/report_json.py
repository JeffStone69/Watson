"""JSON report for scheduled runs. Page bodies are not included."""

from __future__ import annotations

import json
from pathlib import Path

from watson import __version__
from watson.classify import BROKEN, INSECURE, REDIRECT, UNVERIFIED
from watson.models import ScanResult
from watson.present import sort_findings, summary_rows


def _link(item) -> dict:
    return {
        "url": item.url,
        "source_url": item.source_url,
        "link_text": item.link_text,
        "category": item.category,
        "reason": item.reason,
        "status": item.status,
        "location": item.location,
        "soft_404": item.soft_404,
        "severity": item.severity,
        "owner": item.owner,
        "fix": item.fix,
    }


def _finding(item) -> dict:
    return {
        "severity": item.severity,
        "check": item.check,
        "title": item.title,
        "evidence": item.evidence,
        "owner": item.owner,
        "fix": item.fix,
        "url": item.url,
    }


def result_to_dict(result: ScanResult) -> dict:
    return {
        "tool": "watson",
        "version": __version__,
        "passive_only": True,
        "privacy": (
            "Email addresses, personal names, and document metadata values are not included. "
            "Counts and page locations only."
        ),
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "user_agent": result.user_agent,
        "pages": [{"url": page.url, "status": page.status, "depth": page.depth} for page in result.pages],
        "external_links_skipped": result.external_skipped,
        "links": {
            "broken": [_link(item) for item in result.links_in(BROKEN)],
            "unverified": [_link(item) for item in result.links_in(UNVERIFIED)],
            "redirects": [_link(item) for item in result.links_in(REDIRECT)],
            "insecure": [_link(item) for item in result.links_in(INSECURE)],
        },
        "freshness": {
            "newest_newsletter": result.newest_newsletter,
            "newest_news": result.newest_news,
            "newest_event": result.newest_event,
            "rows": [
                {
                    "kind": item.kind,
                    "severity": item.severity,
                    "page_url": item.page_url,
                    "date": item.observed_date,
                    "detail": item.detail,
                    "owner": item.owner,
                    "fix": item.fix,
                }
                for item in result.updates
            ],
        },
        "security": [_finding(item) for item in sort_findings(result)],
        "summary": [{"item": item, "value": value} for item, value in summary_rows(result)],
        "notes": list(result.notes),
        "exit_code": result.exit_code,
    }


def write_json(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result_to_dict(result), indent=2) + "\n", encoding="utf-8")
