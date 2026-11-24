import json
from collections.abc import Callable
from pathlib import Path

import pytest

from lynx.core.findings import FindingState, Severity
from lynx.detectors.osv_scanner import run_osv_scanner

FLAG = "--output-file"


def _report(source: Path, max_severity: str = "9.8") -> str:
    """The shape osv-scanner 2.7 writes with --format json, trimmed to what Lynx reads."""
    return json.dumps(
        {
            "results": [
                {
                    "source": {"path": str(source / "requirements.txt"), "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "pyyaml", "version": "5.3.1", "ecosystem": "PyPI"},
                            "groups": [
                                {
                                    "ids": ["PYSEC-2021-142", "GHSA-8q59-q68h-6hv4"],
                                    "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
                                    "max_severity": max_severity,
                                }
                            ],
                            "vulnerabilities": [
                                {"id": "PYSEC-2021-142", "database_specific": None},
                                {
                                    "id": "GHSA-8q59-q68h-6hv4",
                                    "summary": "Improper Input Validation in PyYAML",
                                    "database_specific": {"cwe_ids": ["CWE-20"]},
                                },
                            ],
                        }
                    ],
                }
            ]
        }
    )


def test_a_missing_binary_means_not_run(fake_tool: Callable[..., Path], source: Path) -> None:
    run = run_osv_scanner(source)

    assert run.status == "not run"
    assert run.reason == "osv-scanner isn't installed"


def test_a_folder_without_dependency_files_completes_clean(
    fake_tool: Callable[..., Path], source: Path
) -> None:
    fake_tool("osv-scanner", flag=FLAG, exit_code=128, stderr="No package sources found\n")

    run = run_osv_scanner(source)

    assert run.status == "complete"
    assert run.findings == ()
    assert run.reason == "no lockfile found, so no dependencies were checked"


def test_each_vulnerability_group_becomes_one_finding(
    fake_tool: Callable[..., Path], source: Path
) -> None:
    fake_tool("osv-scanner", flag=FLAG, report=_report(source), exit_code=1)

    run = run_osv_scanner(source)

    assert run.status == "complete"
    [finding] = run.findings
    assert finding.rule_id == "deps.pysec-2021-142"
    assert finding.title == "Improper Input Validation in PyYAML"
    assert finding.cwes == (20,)
    assert finding.severity is Severity.CRITICAL
    assert finding.state is FindingState.CORROBORATED
    assert "pyyaml 5.3.1" in finding.message
    assert "CVE-2020-14343" in finding.message
    assert finding.location.model_dump() == {
        "kind": "source",
        "path": "requirements.txt",
        "start_line": None,
        "end_line": None,
    }


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        ("9.0", Severity.CRITICAL),
        ("7.5", Severity.HIGH),
        ("5.0", Severity.MEDIUM),
        ("2.0", Severity.LOW),
        ("0", Severity.INFO),
        ("", Severity.MEDIUM),
    ],
)
def test_cvss_scores_map_to_severities(
    fake_tool: Callable[..., Path], source: Path, score: str, severity: Severity
) -> None:
    fake_tool("osv-scanner", flag=FLAG, report=_report(source, max_severity=score), exit_code=1)

    assert run_osv_scanner(source).findings[0].severity is severity


def test_a_clean_scan_completes_with_no_findings(
    fake_tool: Callable[..., Path], source: Path
) -> None:
    fake_tool("osv-scanner", flag=FLAG, report=json.dumps({"results": []}), exit_code=0)

    run = run_osv_scanner(source)

    assert run.status == "complete"
    assert run.findings == ()


def test_an_unexpected_exit_code_is_a_failure(fake_tool: Callable[..., Path], source: Path) -> None:
    fake_tool("osv-scanner", flag=FLAG, exit_code=127, stderr="network error\n")

    run = run_osv_scanner(source)

    assert run.status == "failed"
    assert run.reason == "exited with code 127: network error"


def test_osv_scanner_scans_the_folder_recursively(
    fake_tool: Callable[..., Path], source: Path
) -> None:
    args_file = fake_tool("osv-scanner", flag=FLAG, report=json.dumps({"results": []}))

    run_osv_scanner(source)

    args = json.loads(args_file.read_text())
    assert args[:3] == ["scan", "source", "-r"]
    assert args[-1] == str(source)


def test_a_corrupt_report_is_a_failure(fake_tool: Callable[..., Path], source: Path) -> None:
    fake_tool("osv-scanner", flag=FLAG, report='{"unexpected": []}', exit_code=1)

    run = run_osv_scanner(source)

    assert run.status == "failed"
    assert run.reason is not None
    assert run.reason.startswith("couldn't read its report")
