"""What a run carries from node to node. Every checkpoint saves it."""

import operator
from pathlib import Path
from typing import Annotated, TypedDict

from lynx.detectors import DetectorRun


class RunState(TypedDict):
    source: Path  # the scanned folder
    sarif: Path  # where the report is written
    runs: Annotated[list[DetectorRun], operator.add]  # each detector node adds its run
