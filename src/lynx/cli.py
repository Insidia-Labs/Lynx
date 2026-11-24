"""The `lynx` command line."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from lynx import __version__
from lynx.config import EXIT_FINISHED, EXIT_NOT_FINISHED
from lynx.core.sarif import to_sarif
from lynx.detectors import DetectorRun
from lynx.detectors.gitleaks import run_gitleaks
from lynx.detectors.osv_scanner import run_osv_scanner

DETECTORS = (run_gitleaks, run_osv_scanner)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lynx",
        description="AI security testing that proves what it finds and opens the fix.",
    )
    parser.add_argument("--version", action="version", version=f"lynx {__version__}")
    commands = parser.add_subparsers(dest="command")
    scan = commands.add_parser("scan", help="scan a local folder")
    scan.add_argument("path", type=Path, help="the folder to scan")
    scan.add_argument(
        "--sarif",
        type=Path,
        default=Path("lynx.sarif"),
        help="where to write the SARIF report (default: lynx.sarif)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path, args.sarif)
    parser.print_help()
    return EXIT_FINISHED


def _scan(source: Path, sarif: Path) -> int:
    """Exit 0 when the scan finished, even with a detector missing; 2 when nothing ran."""
    if not source.is_dir():
        print(f"lynx: {source} isn't a folder", file=sys.stderr)
        return EXIT_NOT_FINISHED
    runs = [detector(source.resolve()) for detector in DETECTORS]
    problems = [f"{r.name}: {r.status} ({r.reason})" for r in runs if r.status != "complete"]
    findings = [finding for run in runs for finding in run.findings]
    document = to_sarif(findings, version=__version__, problems=problems)
    sarif.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    _print_summary(runs, document, sarif)
    finished = any(run.status == "complete" for run in runs)
    return EXIT_FINISHED if finished else EXIT_NOT_FINISHED


def _print_summary(runs: Sequence[DetectorRun], document: dict[str, Any], sarif: Path) -> None:
    for run in runs:
        count = len(run.findings)
        line = f"{run.name}: {run.status}, {count} finding{'' if count == 1 else 's'}"
        # A complete run can still carry a note, such as no lockfile to check.
        note = f" ({run.reason})" if run.status == "complete" and run.reason else ""
        print(line + note, file=sys.stderr)
    # The reasons are printed from the SARIF document because it has already been masked.
    for note in document["runs"][0]["invocations"][0].get("toolExecutionNotifications", []):
        print(f"  {note['message']['text']}", file=sys.stderr)
    print(f"report: {sarif}", file=sys.stderr)
