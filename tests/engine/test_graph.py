import logging
import re
from pathlib import Path

import pytest
from langchain_core.runnables import RunnableConfig

from lynx.core.findings import (
    Confidence,
    Finding,
    FindingState,
    LiveLocation,
    Needle,
    Severity,
    SourceLocation,
    TraceStep,
)
from lynx.core.process import ToolRun
from lynx.detectors import DetectorRun
from lynx.engine import graph
from lynx.engine.graph import build_graph, new_run_id, open_checkpointer
from lynx.engine.nodes.prepare import DETECTORS
from lynx.engine.state import RunState

CONFIG: RunnableConfig = {"configurable": {"thread_id": "run-1"}}


def _finding() -> Finding:
    """A finding that uses every field type, so a checkpoint must rebuild all of them."""
    handler = SourceLocation(path="app/views.py", start_line=12, end_line=14)
    return Finding(
        rule_id="sqli.raw-query",
        title="SQL injection",
        message="User input reaches a raw query.",
        cwes=(89,),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        state=FindingState.CORROBORATED,
        location=LiveLocation(url="http://localhost:8000/search", method="POST"),
        trace=(TraceStep(role="sink", location=handler, symbol="search"),),
        needles=(Needle(location=handler, text="cursor.execute(query)"),),
        detector="test",
    )


def test_a_checkpoint_rebuilds_every_finding_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    finding = _finding()
    monkeypatch.setattr(
        graph, "DETECTORS", {"test": lambda _: DetectorRun("test", "complete", (finding,))}
    )
    start = RunState(source=tmp_path, sarif=tmp_path / "out.sarif", runs=[])
    with open_checkpointer(tmp_path / "state") as checkpointer:
        build_graph(checkpointer).invoke(start, CONFIG)

    # A new connection reads only what was saved, like a resumed scan in a new process.
    with caplog.at_level(logging.WARNING), open_checkpointer(tmp_path / "state") as checkpointer:
        saved = build_graph(checkpointer).get_state(CONFIG).values

    [run] = saved["runs"]
    assert list(run.findings) == [finding]
    assert type(run.findings[0].severity) is Severity
    assert "Blocked" not in caplog.text


def test_a_checkpoint_refuses_types_it_was_not_built_for(
    caplog: pytest.LogCaptureFixture,
) -> None:
    stored = graph._SERDE.dumps_typed(ToolRun(0, "out", ""))

    with caplog.at_level(logging.WARNING):
        restored = graph._SERDE.loads_typed(stored)

    assert not isinstance(restored, ToolRun)
    assert "Blocked deserialization of lynx.core.process.ToolRun" in caplog.text


def test_the_graph_runs_each_detector_then_the_report(tmp_path: Path) -> None:
    with open_checkpointer(tmp_path / "state") as checkpointer:
        nodes = list(build_graph(checkpointer).get_graph().nodes)

    assert nodes == ["__start__", *DETECTORS, "report", "__end__"]


def test_run_ids_sort_by_start_time_and_never_repeat() -> None:
    ids = {new_run_id() for _ in range(50)}

    assert len(ids) == 50
    assert all(re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{6}", run_id) for run_id in ids)


def test_the_state_folder_is_private(tmp_path: Path) -> None:
    folder = tmp_path / "state"

    with open_checkpointer(folder):
        pass

    assert folder.stat().st_mode & 0o777 == 0o700
    assert (folder / "runs.sqlite").is_file()
