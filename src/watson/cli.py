"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from watson import __version__
from watson.config import UsageError, config_from_mapping, load_toml
from watson.fixture_site import serve_fixture
from watson.report_excel import write_excel
from watson.report_html import write_html
from watson.report_json import write_json
from watson.scan import TargetUnreachable, run_scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="watson",
        description=(
            "Passive health check for a public website. "
            "Watson only sends normal GET and HEAD requests, plus one TLS handshake. "
            "It does not log in, submit forms, guess hidden pages, or scan ports."
        ),
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Public website address. Only scan a site you are allowed to check.",
    )
    parser.add_argument("--config", type=Path, help="TOML settings file. See watson.example.toml.")
    parser.add_argument("--max-pages", type=int, help="Maximum HTML pages to read. Default 100.")
    parser.add_argument("--max-depth", type=int, help="How many links deep to follow. Default 3.")
    parser.add_argument("--rate", type=float, help="Requests per second. Default 1.")
    parser.add_argument("--timeout", type=float, help="Seconds to wait for each request. Default 15.")
    parser.add_argument("--output-dir", type=Path, help="Folder for report.xlsx, report.html, and report.json.")
    parser.add_argument(
        "--no-external",
        action="store_true",
        help="Do not request links that leave the site's host name.",
    )
    parser.add_argument(
        "--checks",
        help="Comma-separated list: links, freshness, security, or all. Default all.",
    )
    parser.add_argument(
        "--osv-lookup",
        action="store_true",
        help="Opt in: send library names and versions to api.osv.dev. Off by default.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "info", "none"],
        help="Exit 1 when a finding is at least this serious. Broken links always exit 1 unless none. Default high.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Scan the built-in example site on this computer. Does not use the network.",
    )
    parser.add_argument("--verbose", action="store_true", help="Show the technical traceback if Watson crashes.")
    parser.add_argument("--version", action="version", version=f"Watson {__version__}")
    return parser


def _build(argv: list[str]):
    parser = _parser()
    args = parser.parse_args(argv)
    file_data: dict = {}
    if args.config:
        file_data = load_toml(args.config)
    if args.demo and args.url:
        raise UsageError("--demo does not take a website address. It only scans the built-in example site.")
    overrides = {
        "start_url": args.url,
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "rate": args.rate,
        "timeout": args.timeout,
        "output_dir": args.output_dir,
        "no_external": True if args.no_external else None,
        "checks": args.checks,
        "osv_lookup": True if args.osv_lookup else None,
        "fail_on": args.fail_on,
        "demo": args.demo,
        "verbose": args.verbose,
    }
    # Drop None so the file and the defaults stay in place.
    overrides = {key: value for key, value in overrides.items() if value is not None}
    if args.demo and "rate" not in overrides and "rate" not in file_data:
        overrides["rate"] = 10
    if args.demo and "output_dir" not in overrides and "output_dir" not in file_data:
        overrides["output_dir"] = Path("watson-demo-report")
    if not args.demo and not overrides.get("start_url") and not file_data.get("start_url"):
        parser.error("Give a website address, or run watson --demo to practise on the example site.")
    return config_from_mapping(file_data, overrides=overrides)


def write_reports(result, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "xlsx": output_dir / "report.xlsx",
        "html": output_dir / "report.html",
        "json": output_dir / "report.json",
    }
    write_excel(result, paths["xlsx"])
    write_html(result, paths["html"])
    write_json(result, paths["json"])
    return paths


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        config = _build(argv)
    except UsageError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0

    def log(message: str) -> None:
        print(message, file=sys.stderr)

    try:
        if config.demo:
            log("Demo mode: scanning the built-in example site on this computer.")
            with serve_fixture() as site:
                config.start_url = site.base + "/"
                result = run_scan(config, log=log)
        else:
            result = run_scan(config, log=log)
        paths = write_reports(result, config.output_dir)
    except TargetUnreachable as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if config.verbose:
            traceback.print_exc()
        else:
            print("Run again with --verbose if you need the technical detail for your web team.", file=sys.stderr)
        return 3
    broken = sum(1 for item in result.links if item.category == "broken")
    high = sum(1 for item in result.findings if item.severity == "High")
    log(f"Excel: {paths['xlsx']}")
    log(f"HTML:  {paths['html']}")
    log(f"JSON:  {paths['json']}")
    log(f"Done. Broken links: {broken}. High findings: {high}. Exit code {result.exit_code}.")
    return result.exit_code
