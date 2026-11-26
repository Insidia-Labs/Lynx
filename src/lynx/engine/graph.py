"""The run graph, saved to a SQLite checkpoint after every node.

Today it runs the detectors one after another and then writes the report. The
checkpoint's thread id is the run id, so `lynx scan --resume <run id>` carries on
after the last node that finished.
"""

import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from lynx.core.findings import Confidence, Finding, FindingState, Severity
from lynx.detectors import DetectorRun
from lynx.engine.nodes.prepare import DETECTORS, run_detector
from lynx.engine.nodes.report import report
from lynx.engine.state import RunState

type RunGraph = CompiledStateGraph[RunState, None, RunState, RunState]

# A checkpoint is only ever rebuilt into these types. Anything else stored in the
# database is refused, so a tampered checkpoint can't construct arbitrary objects.
_SERDE = JsonPlusSerializer(
    allowed_msgpack_modules=[DetectorRun, Finding, Severity, Confidence, FindingState]
)


def new_run_id() -> str:
    """A unique run id that sorts by start time, such as 20261125T021132Z-3f9a1c."""
    return f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


@contextmanager
def open_checkpointer(state_dir: Path) -> Iterator[SqliteSaver]:
    """The run checkpoints, in a folder only the current user can open."""
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with closing(sqlite3.connect(state_dir / "runs.sqlite", check_same_thread=False)) as conn:
        yield SqliteSaver(conn, serde=_SERDE)


def build_graph(checkpointer: SqliteSaver) -> RunGraph:
    builder = StateGraph(RunState)
    previous = START
    for name, detector in DETECTORS.items():
        builder.add_node(name, partial(run_detector, detector))
        builder.add_edge(previous, name)
        previous = name
    builder.add_node("report", report)
    builder.add_edge(previous, "report")
    builder.add_edge("report", END)
    return builder.compile(checkpointer=checkpointer)
