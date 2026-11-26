"""The `lynx` command line."""

import argparse
import signal
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from langchain_core.runnables import RunnableConfig

from lynx import __version__
from lynx.agent.models import check_tool_calling
from lynx.config import (
    EXIT_CHECK_FAILED,
    EXIT_FINISHED,
    EXIT_NOT_FINISHED,
    ModelSpec,
    settings,
)
from lynx.core.mask import mask_text
from lynx.detectors import DetectorRun
from lynx.engine.graph import build_graph, new_run_id, open_checkpointer
from lynx.engine.state import RunState

DEFAULT_SARIF = Path("lynx.sarif")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lynx",
        description="AI security testing that proves what it finds and opens the fix.",
    )
    parser.add_argument("--version", action="version", version=f"lynx {__version__}")
    commands = parser.add_subparsers(dest="command")
    scan = commands.add_parser("scan", help="scan a local folder")
    scan.add_argument("path", type=Path, nargs="?", help="the folder to scan")
    scan.add_argument(
        "--sarif", type=Path, help="where to write the SARIF report (default: lynx.sarif)"
    )
    scan.add_argument(
        "--resume",
        metavar="RUN_ID",
        help="finish an interrupted scan, with the folder and report path it started with",
    )
    commands.add_parser("doctor", help="check that each role's chat model works and calls tools")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor()
    if args.command != "scan":
        parser.print_help()
        return EXIT_FINISHED
    if args.resume:
        if args.path or args.sarif:
            parser.error("--resume takes no folder or --sarif; the scan keeps its own")
        return _run(args.resume, None)
    if args.path is None:
        parser.error("scan needs a folder, or --resume RUN_ID")
    return _scan(args.path, args.sarif or DEFAULT_SARIF)


def _scan(source: Path, sarif: Path) -> int:
    if not source.is_dir():
        print(f"lynx: {source} isn't a folder", file=sys.stderr)
        return EXIT_NOT_FINISHED
    run_id = new_run_id()
    print(f"run {run_id}: scanning {source}", file=sys.stderr)
    return _run(run_id, RunState(source=source.resolve(), sarif=sarif.resolve(), runs=[]))


def _run(run_id: str, start: RunState | None) -> int:
    """Run the graph from `start`, or resume the saved run when `start` is None.

    Exit 0 when the scan finished, even with a detector missing; 2 when nothing ran or
    the scan was interrupted.
    """
    config: RunnableConfig = {"configurable": {"thread_id": run_id}}
    with open_checkpointer(settings.state_dir) as checkpointer:
        graph = build_graph(checkpointer)
        if start is None and not graph.get_state(config).values:
            print(f"lynx: no saved run {run_id}", file=sys.stderr)
            return EXIT_NOT_FINISHED
        try:
            with _sigterm_as_interrupt():
                for update in graph.stream(start, config, stream_mode="updates"):
                    _print_progress(update)
        except KeyboardInterrupt:
            print(f"lynx: interrupted; resume with: lynx scan --resume {run_id}", file=sys.stderr)
            return EXIT_NOT_FINISHED
        state = graph.get_state(config).values
    print(f"report: {state['sarif']}", file=sys.stderr)
    finished = any(run.status == "complete" for run in state["runs"])
    return EXIT_FINISHED if finished else EXIT_NOT_FINISHED


@contextmanager
def _sigterm_as_interrupt() -> Iterator[None]:
    """CI stops a job with SIGTERM. Treat it like Ctrl-C, so the run can be resumed."""
    previous = signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _print_progress(update: dict[str, Any]) -> None:
    """One line per detector as it finishes, masked because a reason can quote tool output."""
    for change in update.values():
        for run in (change or {}).get("runs", []):
            print(mask_text(_summary(run)), file=sys.stderr)


def _doctor() -> int:
    """One line per role. A model shared by several roles is checked once."""
    roles = {
        "map": settings.map_model,
        "investigate": settings.investigate_model,
        "skeptic": settings.skeptic_model,
        "fix": settings.fix_model,
    }
    problems: dict[ModelSpec, str | None] = {}
    for role, spec in roles.items():
        if spec not in problems:
            problems[spec] = check_tool_calling(spec)
        where = f" at {spec.base_url}" if spec.base_url else ""
        verdict = problems[spec] or "ok, calls tools"
        # Masked, as a URL or a provider's error message can carry a credential.
        print(mask_text(f"{role}: {spec.provider} {spec.name}{where}: {verdict}"))
    return EXIT_CHECK_FAILED if any(problems.values()) else EXIT_FINISHED


def _summary(run: DetectorRun) -> str:
    count = len(run.findings)
    line = f"{run.name}: {run.status}, {count} finding{'' if count == 1 else 's'}"
    return f"{line} ({run.reason})" if run.reason else line
