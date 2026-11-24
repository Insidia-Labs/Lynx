"""OSV-Scanner: dependencies with known vulnerabilities.

OSV-Scanner groups advisories that describe the same vulnerability (for example a
PYSEC and a GHSA id for one CVE). Lynx reports one finding per group, so a single
vulnerability is never counted twice.
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

NAME = "osv-scanner"
_FOUND_NOTHING = 0
_FOUND_VULNERABILITIES = 1
_NO_PACKAGE_SOURCES = 128  # no lockfile found; osv-scanner reads lockfiles, not manifests
_CVSS_BANDS = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


def run_osv_scanner(source: Path) -> DetectorRun:
    if shutil.which(NAME) is None:
        return DetectorRun(NAME, "not run", reason=f"{NAME} isn't installed")
    with tempfile.TemporaryDirectory(prefix="lynx-osv-") as workdir:
        report = Path(workdir) / "report.json"
        run = run_tool(
            [
                NAME,
                "scan",
                "source",
                "-r",
                "--format",
                "json",
                "--output-file",
                str(report),
                str(source),
            ],
            timeout=settings.detector_timeout,
        )
        if run.exit_code == _NO_PACKAGE_SOURCES:
            # Finished, but say so: a manifest without a lockfile means nothing was checked.
            return DetectorRun(
                NAME, "complete", reason="no lockfile found, so no dependencies were checked"
            )
        if run.exit_code not in (_FOUND_NOTHING, _FOUND_VULNERABILITIES) or not report.is_file():
            return DetectorRun(NAME, "failed", reason=failure_reason(run))
        try:
            results = json.loads(report.read_text())["results"]
            findings = tuple(
                _finding(result["source"]["path"], package, group, source)
                for result in results
                for package in result["packages"]
                for group in package.get("groups", [])
            )
        except (ValueError, KeyError, TypeError) as error:
            return DetectorRun(NAME, "failed", reason=f"couldn't read its report ({error})")
    return DetectorRun(NAME, "complete", findings)


def _finding(
    lockfile: str, package: dict[str, Any], group: dict[str, Any], source: Path
) -> Finding:
    """One finding for one advisory group, using the details of every advisory in it."""
    advisories = [a for a in package.get("vulnerabilities", []) if a["id"] in group["ids"]]
    first = group["ids"][0]
    summary = next((a["summary"] for a in advisories if a.get("summary")), first)
    cwes = {
        int(number)
        for advisory in advisories
        for cwe in (advisory.get("database_specific") or {}).get("cwe_ids", [])
        if (number := cwe.removeprefix("CWE-")).isdigit()
    }
    known_as = ", ".join(group.get("aliases") or group["ids"])
    name, version, ecosystem = (package["package"][key] for key in ("name", "version", "ecosystem"))
    return Finding(
        rule_id=rule_id("deps", first),
        title=summary,
        message=f"{name} {version} ({ecosystem}) is affected by {known_as}: {summary}",
        cwes=tuple(sorted(cwes)),
        severity=_severity(group.get("max_severity")),
        state=FindingState.CORROBORATED,
        location=SourceLocation(path=relative_path(lockfile, source)),
        detector=NAME,
    )


def _severity(score: str | None) -> Severity:
    """CVSS score bands; an unscored advisory is treated as medium."""
    try:
        value = float(score or "")
    except ValueError:
        return Severity.MEDIUM
    return next((severity for floor, severity in _CVSS_BANDS if value >= floor), Severity.INFO)
