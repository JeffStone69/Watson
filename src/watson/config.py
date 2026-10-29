"""Load Watson settings from flags and an optional TOML file."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

from watson import USER_AGENT

CHECKS = {"links", "freshness", "security"}


class UsageError(ValueError):
    """The command or config file is not usable."""


@dataclass
class Config:
    start_url: str
    max_pages: int = 100
    max_depth: int = 3
    rate: float = 1.0
    timeout: float = 15.0
    output_dir: Path = field(default_factory=lambda: Path("watson-report"))
    no_external: bool = False
    checks: set[str] = field(default_factory=lambda: set(CHECKS))
    user_agent: str = USER_AGENT
    newsletter_stale_weeks: int = 8
    copyright_grace_years: int = 0
    calendar_grace_days: int = 31
    osv_lookup: bool = False
    fail_on: str = "high"
    max_links: int = 2000
    demo: bool = False
    verbose: bool = False
    today: date | None = None


def load_toml(path: Path) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib  # type: ignore

    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"Could not read config file {path}: {exc}") from exc
    except Exception as exc:
        raise UsageError(f"Could not parse {path} as TOML: {exc}") from exc


def parse_checks(value: object) -> set[str]:
    if isinstance(value, (list, tuple)):
        parts = [str(item).strip().lower() for item in value]
    else:
        text = str(value).strip().lower()
        if text == "all":
            return set(CHECKS)
        parts = [item.strip() for item in text.split(",") if item.strip()]
    if len(parts) == 1 and parts[0] == "all":
        return set(CHECKS)
    checks = set(parts)
    unknown = checks - CHECKS
    if unknown or not checks:
        raise UsageError("--checks must be links, freshness, security, or all")
    return checks


def validate_config(config: Config) -> None:
    if not config.demo:
        parsed = urlparse(config.start_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise UsageError("The address must start with http:// or https:// and include a host name")
    if config.max_pages < 1:
        raise UsageError("--max-pages must be at least 1")
    if config.max_depth < 0:
        raise UsageError("--max-depth must be 0 or more")
    if config.rate <= 0:
        raise UsageError("--rate must be greater than zero (requests per second)")
    if config.timeout <= 0:
        raise UsageError("--timeout must be greater than zero")
    if config.newsletter_stale_weeks < 1:
        raise UsageError("newsletter_stale_weeks must be at least 1")
    if config.fail_on not in {"high", "medium", "low", "info", "none"}:
        raise UsageError("--fail-on must be high, medium, low, info, or none")
    if config.max_links < 1:
        raise UsageError("max_links must be at least 1")


def config_from_mapping(data: dict, *, overrides: dict | None = None) -> Config:
    """Build a Config. Values in `overrides` replace the file when they are not None."""
    overrides = overrides or {}
    freshness = data.get("freshness") if isinstance(data.get("freshness"), dict) else {}
    checks_value = overrides.get("checks")
    if checks_value is None:
        checks_value = data.get("checks", "all")
    start_url = overrides.get("start_url") or str(data.get("start_url") or "")
    config = Config(
        start_url=start_url,
        max_pages=int(overrides.get("max_pages") if overrides.get("max_pages") is not None else data.get("max_pages", 100)),
        max_depth=int(overrides.get("max_depth") if overrides.get("max_depth") is not None else data.get("max_depth", 3)),
        rate=float(overrides.get("rate") if overrides.get("rate") is not None else data.get("rate", 1.0)),
        timeout=float(overrides.get("timeout") if overrides.get("timeout") is not None else data.get("timeout", 15)),
        output_dir=Path(
            overrides.get("output_dir")
            if overrides.get("output_dir") is not None
            else data.get("output_dir", "watson-report")
        ),
        no_external=bool(overrides["no_external"]) if overrides.get("no_external") else bool(data.get("no_external", False)),
        checks=parse_checks(checks_value),
        newsletter_stale_weeks=int(
            freshness.get("newsletter_stale_weeks", data.get("newsletter_stale_weeks", 8))
        ),
        copyright_grace_years=int(
            freshness.get("copyright_grace_years", data.get("copyright_grace_years", 0))
        ),
        calendar_grace_days=int(freshness.get("calendar_grace_days", data.get("calendar_grace_days", 31))),
        osv_lookup=bool(overrides["osv_lookup"]) if overrides.get("osv_lookup") else bool(data.get("osv_lookup", False)),
        fail_on=str(overrides.get("fail_on") or data.get("fail_on") or "high"),
        max_links=int(data.get("max_links", 2000)),
        demo=bool(overrides.get("demo", False)),
        verbose=bool(overrides.get("verbose", False)),
    )
    validate_config(config)
    return config
