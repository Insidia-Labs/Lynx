import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from lynx.cli import main


def _leak(source: Path) -> str:
    return json.dumps(
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Detected a Generic API Key.",
                "StartLine": 1,
                "EndLine": 1,
                "File": str(source / "settings.py"),
            }
        ]
    )


def _vulnerable_dependency(source: Path) -> str:
    return json.dumps(
        {
            "results": [
                {
                    "source": {"path": str(source / "requirements.txt")},
                    "packages": [
                        {
                            "package": {"name": "pyyaml", "version": "5.3.1", "ecosystem": "PyPI"},
                            "groups": [{"ids": ["GHSA-8q59-q68h-6hv4"], "max_severity": "9.8"}],
                            "vulnerabilities": [{"id": "GHSA-8q59-q68h-6hv4"}],
                        }
                    ],
                }
            ]
        }
    )


def _invocation(report: Path) -> dict[str, Any]:
    invocation: dict[str, Any] = json.loads(report.read_text())["runs"][0]["invocations"][0]
    return invocation


def test_a_full_scan_reports_every_detector_and_finishes(
    fake_tool: Callable[..., Path], source: Path, tmp_path: Path
) -> None:
    fake_tool("gitleaks", flag="--report-path", report=_leak(source))
    fake_tool(
        "osv-scanner", flag="--output-file", report=_vulnerable_dependency(source), exit_code=1
    )
    report = tmp_path / "out.sarif"

    assert main(["scan", str(source), "--sarif", str(report)]) == 0

    results = json.loads(report.read_text())["runs"][0]["results"]
    assert sorted(result["ruleId"] for result in results) == [
        "deps.ghsa-8q59-q68h-6hv4",
        "secrets.generic-api-key",
    ]
    assert _invocation(report) == {"executionSuccessful": True}


def test_a_missing_detector_marks_the_run_incomplete_but_the_scan_finishes(
    fake_tool: Callable[..., Path], source: Path, tmp_path: Path
) -> None:
    fake_tool("gitleaks", flag="--report-path", report="[]")
    report = tmp_path / "out.sarif"

    assert main(["scan", str(source), "--sarif", str(report)]) == 0

    invocation = _invocation(report)
    assert invocation["executionSuccessful"] is False
    notes = [note["message"]["text"] for note in invocation["toolExecutionNotifications"]]
    assert notes == ["osv-scanner: not run (osv-scanner isn't installed)"]


def test_when_no_detector_can_run_the_scan_did_not_finish(
    fake_tool: Callable[..., Path], source: Path, tmp_path: Path
) -> None:
    report = tmp_path / "out.sarif"

    assert main(["scan", str(source), "--sarif", str(report)]) == 2

    assert _invocation(report)["executionSuccessful"] is False


def test_a_path_that_is_not_a_folder_writes_no_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "out.sarif"

    assert main(["scan", str(tmp_path / "missing"), "--sarif", str(report)]) == 2

    assert not report.exists()
    assert "isn't a folder" in capsys.readouterr().err


def test_the_report_defaults_to_lynx_sarif_in_the_current_folder(
    fake_tool: Callable[..., Path],
    source: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_tool("gitleaks", flag="--report-path", report="[]")
    monkeypatch.chdir(tmp_path)

    main(["scan", str(source)])

    assert (tmp_path / "lynx.sarif").is_file()


def test_a_summary_of_each_detector_goes_to_stderr(
    fake_tool: Callable[..., Path],
    source: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_tool("gitleaks", flag="--report-path", report=_leak(source))

    main(["scan", str(source), "--sarif", str(tmp_path / "out.sarif")])

    err = capsys.readouterr().err
    assert "gitleaks: complete, 1 finding\n" in err
    assert "osv-scanner: not run, 0 findings\n" in err
    assert "osv-scanner isn't installed" in err


def test_a_folder_without_a_lockfile_says_dependencies_were_not_checked(
    fake_tool: Callable[..., Path],
    source: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_tool("gitleaks", flag="--report-path", report="[]")
    fake_tool("osv-scanner", flag="--output-file", exit_code=128)
    report = tmp_path / "out.sarif"

    assert main(["scan", str(source), "--sarif", str(report)]) == 0

    err = capsys.readouterr().err
    assert "osv-scanner: complete, 0 findings (no lockfile found" in err
    assert _invocation(report) == {"executionSuccessful": True}
