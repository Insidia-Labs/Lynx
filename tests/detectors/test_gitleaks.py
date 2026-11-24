import json
from collections.abc import Callable
from pathlib import Path

import pytest

from lynx.config import Settings
from lynx.core.findings import FindingState, Severity
from lynx.detectors.gitleaks import run_gitleaks

FLAG = "--report-path"


def _leak(source: Path) -> dict[str, object]:
    """One finding as gitleaks 8.30 writes it with --redact."""
    return {
        "RuleID": "generic-api-key",
        "Description": "Detected a Generic API Key, potentially exposing access.",
        "StartLine": 4,
        "EndLine": 4,
        "Match": 'aws_key = "REDACTED"',
        "Secret": "REDACTED",
        "File": str(source / "app" / "settings.py"),
    }


def test_a_missing_binary_means_not_run(fake_tool: Callable[..., Path], source: Path) -> None:
    run = run_gitleaks(source)

    assert run.status == "not run"
    assert run.reason == "gitleaks isn't installed"


def test_a_clean_folder_completes_with_no_findings(
    fake_tool: Callable[..., Path], source: Path
) -> None:
    fake_tool("gitleaks", flag=FLAG, report="[]")

    run = run_gitleaks(source)

    assert run.status == "complete"
    assert run.findings == ()


def test_a_leak_becomes_a_corroborated_finding(
    fake_tool: Callable[..., Path], source: Path
) -> None:
    fake_tool("gitleaks", flag=FLAG, report=json.dumps([_leak(source)]))

    finding = run_gitleaks(source).findings[0]

    assert finding.rule_id == "secrets.generic-api-key"
    assert finding.cwes == (798,)
    assert finding.severity is Severity.HIGH
    assert finding.state is FindingState.CORROBORATED
    assert finding.location.model_dump() == {
        "kind": "source",
        "path": "app/settings.py",
        "start_line": 4,
        "end_line": 4,
    }
    assert finding.detector == "gitleaks"


def test_gitleaks_is_always_asked_to_redact_secrets(
    fake_tool: Callable[..., Path], source: Path
) -> None:
    args_file = fake_tool("gitleaks", flag=FLAG, report="[]")

    run_gitleaks(source)

    args = json.loads(args_file.read_text())
    assert args[:2] == ["dir", str(source)]
    assert "--redact" in args
    assert args[args.index("--exit-code") + 1] == "0"


def test_a_crash_is_a_failure_with_the_reason(fake_tool: Callable[..., Path], source: Path) -> None:
    fake_tool("gitleaks", flag=FLAG, exit_code=2, stderr="config error: bad rule\n")

    run = run_gitleaks(source)

    assert run.status == "failed"
    assert run.reason == "exited with code 2: config error: bad rule"


def test_a_corrupt_report_is_a_failure(fake_tool: Callable[..., Path], source: Path) -> None:
    fake_tool("gitleaks", flag=FLAG, report="not json")

    run = run_gitleaks(source)

    assert run.status == "failed"
    assert run.reason is not None
    assert run.reason.startswith("couldn't read its report")


def test_a_slow_run_is_killed_and_reported(
    fake_tool: Callable[..., Path], source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_tool("gitleaks", flag=FLAG, report="[]", sleep=30)
    monkeypatch.setattr("lynx.detectors.gitleaks.settings", Settings(detector_timeout=0.5))

    run = run_gitleaks(source)

    assert run.status == "failed"
    assert run.reason == "timed out (raise LYNX_DETECTOR_TIMEOUT to allow longer)"
