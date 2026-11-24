"""gitleaks: secrets committed in files.

gitleaks always runs with `--redact`, so the secret itself never enters Lynx.
"""

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from lynx.config import settings
from lynx.core.findings import Finding, FindingState, Severity, SourceLocation
from lynx.core.process import run_tool
from lynx.detectors import DetectorRun, failure_reason, relative_path, rule_id

NAME = "gitleaks"
_HARD_CODED_CREDENTIALS = 798  # CWE-798


def run_gitleaks(source: Path) -> DetectorRun:
    if shutil.which(NAME) is None:
        return DetectorRun(NAME, "not run", reason=f"{NAME} isn't installed")
    with tempfile.TemporaryDirectory(prefix="lynx-gitleaks-") as workdir:
        report = Path(workdir) / "report.json"
        run = run_tool(
            [
                NAME,
                "dir",
                str(source),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--exit-code",
                "0",
                "--no-banner",
                "--redact",
            ],
            timeout=settings.detector_timeout,
        )
        if run.exit_code != 0 or not report.is_file():
            return DetectorRun(NAME, "failed", reason=failure_reason(run))
        try:
            findings = tuple(_finding(leak, source) for leak in json.loads(report.read_text()))
        except (ValueError, KeyError, TypeError) as error:
            return DetectorRun(NAME, "failed", reason=f"couldn't read its report ({error})")
    return DetectorRun(NAME, "complete", findings)


def _finding(leak: dict[str, Any], source: Path) -> Finding:
    return Finding(
        rule_id=rule_id("secrets", leak["RuleID"]),
        title=f"Exposed secret ({leak['RuleID']})",
        message=leak["Description"],
        cwes=(_HARD_CODED_CREDENTIALS,),
        severity=Severity.HIGH,
        state=FindingState.CORROBORATED,
        location=SourceLocation(
            path=relative_path(leak["File"], source),
            start_line=leak["StartLine"],
            end_line=leak["EndLine"],
        ),
        detector=NAME,
    )
