"""Report: write one SARIF report from every detector's run."""

import json

from lynx import __version__
from lynx.core.sarif import to_sarif
from lynx.engine.state import RunState


def report(state: RunState) -> None:
    runs = state["runs"]
    problems = [f"{r.name}: {r.status} ({r.reason})" for r in runs if r.status != "complete"]
    findings = [finding for run in runs for finding in run.findings]
    document = to_sarif(findings, version=__version__, problems=problems)
    state["sarif"].write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
