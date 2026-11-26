import json
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from lynx.cli import main
from lynx.detectors import DetectorRun
from lynx.engine.nodes.prepare import DETECTORS


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


def test_progress_shows_each_detector_then_the_report(
    fake_tool: Callable[..., Path],
    source: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_tool("gitleaks", flag="--report-path", report=_leak(source))
    report = tmp_path / "out.sarif"

    main(["scan", str(source), "--sarif", str(report)])

    lines = capsys.readouterr().err.splitlines()
    assert lines[0].startswith("run ")
    assert lines[0].endswith(f": scanning {source}")
    assert lines[1:] == [
        "gitleaks: complete, 1 finding",
        "osv-scanner: not run, 0 findings (osv-scanner isn't installed)",
        f"report: {report}",
    ]


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


def _run_id(err: str) -> str:
    match = re.search(r"lynx scan --resume (\S+)", err)
    assert match, err
    return match.group(1)


def test_an_interrupted_scan_resumes_without_running_finished_detectors_again(
    fake_tool: Callable[..., Path],
    source: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gitleaks_args = fake_tool("gitleaks", flag="--report-path", report=_leak(source))
    fake_tool("osv-scanner", flag="--output-file", exit_code=128)
    osv_scanner = DETECTORS["osv-scanner"]

    def interrupted(folder: Path) -> DetectorRun:
        raise KeyboardInterrupt

    monkeypatch.setitem(DETECTORS, "osv-scanner", interrupted)
    report = tmp_path / "out.sarif"

    assert main(["scan", str(source), "--sarif", str(report)]) == 2
    run_id = _run_id(capsys.readouterr().err)
    assert not report.exists()

    gitleaks_args.unlink()
    monkeypatch.setitem(DETECTORS, "osv-scanner", osv_scanner)
    assert main(["scan", "--resume", run_id]) == 0

    assert not gitleaks_args.exists(), "gitleaks ran again instead of coming from the checkpoint"
    results = json.loads(report.read_text())["runs"][0]["results"]
    assert [result["ruleId"] for result in results] == ["secrets.generic-api-key"]
    assert _invocation(report) == {"executionSuccessful": True}


def test_sigterm_stops_a_scan_that_can_then_be_resumed(
    fake_tool: Callable[..., Path], source: Path, tmp_path: Path
) -> None:
    fake_tool("gitleaks", flag="--report-path", report="[]")
    osv_args = fake_tool("osv-scanner", flag="--output-file", exit_code=128, sleep=30)
    report = tmp_path / "out.sarif"
    scan = subprocess.Popen(  # noqa: S603 - a fixed command running this checkout's Lynx
        [sys.executable, "-m", "lynx", "scan", str(source), "--sarif", str(report)],
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 30
    while not osv_args.exists() and time.monotonic() < deadline:
        time.sleep(0.05)

    scan.terminate()
    _, err = scan.communicate(timeout=30)

    assert scan.returncode == 2, err
    fake_tool("osv-scanner", flag="--output-file", exit_code=128)
    assert main(["scan", "--resume", _run_id(err)]) == 0
    assert report.is_file()


def test_resuming_a_finished_scan_runs_nothing_again(
    fake_tool: Callable[..., Path],
    source: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gitleaks_args = fake_tool("gitleaks", flag="--report-path", report="[]")
    main(["scan", str(source), "--sarif", str(tmp_path / "out.sarif")])
    run_id = capsys.readouterr().err.split()[1].removesuffix(":")
    gitleaks_args.unlink()

    assert main(["scan", "--resume", run_id]) == 0

    assert not gitleaks_args.exists()


def test_resuming_an_unknown_run_fails_and_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--resume", "20261125T000000Z-000000"]) == 2

    assert "no saved run 20261125T000000Z-000000" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["scan"],
        ["scan", "--resume", "run-1", "some/folder"],
        ["scan", "--resume", "run-1", "--sarif", "out.sarif"],
    ],
)
def test_scan_needs_either_a_folder_or_a_run_to_resume(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(argv)

    assert exit_info.value.code == 2
