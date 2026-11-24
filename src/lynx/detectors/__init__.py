"""Detectors: deterministic tools Lynx runs, and what each run produced.

Each detector is a function that takes the scanned folder and returns a
`DetectorRun`. A detector that isn't installed or fails reports that plainly; it
never comes back looking like a clean result.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from lynx.core.findings import Finding
from lynx.core.process import ToolRun

type DetectorStatus = Literal["complete", "not run", "failed"]


@dataclass(frozen=True)
class DetectorRun:
    name: str
    status: DetectorStatus
    findings: tuple[Finding, ...] = ()
    reason: str | None = None


def failure_reason(run: ToolRun) -> str:
    if run.exit_code is None:
        return "timed out (raise LYNX_DETECTOR_TIMEOUT to allow longer)"
    lines = run.stderr.strip().splitlines()
    detail = f": {lines[-1]}" if lines else ""
    return f"exited with code {run.exit_code}{detail}"


def relative_path(path: str, root: Path) -> str:
    """A tool's reported path, relative to the scanned folder."""
    return Path(path).resolve().relative_to(root.resolve()).as_posix()


def rule_id(group: str, name: str) -> str:
    """`group.name` with the name reduced to the characters a rule id allows."""
    return f"{group}.{re.sub(r'[^a-z0-9._/-]+', '-', name.lower())}"
