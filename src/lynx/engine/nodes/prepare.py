"""Prepare: the deterministic detectors, one graph node each.

A node's result is saved in the checkpoint after it, so a resumed scan doesn't run
a detector that already finished.
"""

from collections.abc import Callable
from pathlib import Path

from lynx.detectors import DetectorRun, gitleaks, osv_scanner
from lynx.engine.state import RunState

type Detector = Callable[[Path], DetectorRun]
type DetectorUpdate = dict[str, list[DetectorRun]]

DETECTORS: dict[str, Detector] = {
    gitleaks.NAME: gitleaks.run_gitleaks,
    osv_scanner.NAME: osv_scanner.run_osv_scanner,
}


def run_detector(detector: Detector, state: RunState) -> DetectorUpdate:
    """One detector as a graph node; the graph binds `detector` with functools.partial."""
    return {"runs": [detector(state["source"])]}
