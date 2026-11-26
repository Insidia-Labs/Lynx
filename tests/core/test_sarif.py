import json
from typing import Any

import pytest

from lynx.config import Settings
from lynx.core.findings import (
    Finding,
    FindingState,
    LiveLocation,
    Severity,
    SourceLocation,
    TraceStep,
)
from lynx.core.sarif import to_sarif


def _finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "rule_id": "injection.sql",
        "title": "SQL injection",
        "message": "User input reaches a SQL query without parameters.",
        "cwes": (89,),
        "severity": Severity.HIGH,
        "state": FindingState.PROVEN,
        "location": SourceLocation(path="app/db.py", start_line=12, end_line=14),
        "detector": "taylon",
    }
    fields.update(overrides)
    return Finding.model_validate(fields)


def _run(document: dict[str, Any]) -> dict[str, Any]:
    runs = document["runs"]
    assert len(runs) == 1
    run: dict[str, Any] = runs[0]
    return run


def test_document_is_sarif_2_1_0_from_lynx() -> None:
    document = to_sarif([_finding()], version="0.0.1")

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    driver = _run(document)["tool"]["driver"]
    assert driver["name"] == "Lynx"
    assert driver["version"] == "0.0.1"


def test_rules_and_results_carry_cwe_tags() -> None:
    run = _run(to_sarif([_finding(cwes=(89, 20))], version="0.0.1"))

    assert {"CWE-20", "CWE-89"} <= set(run["tool"]["driver"]["rules"][0]["properties"]["tags"])
    assert {"CWE-20", "CWE-89"} <= set(run["results"][0]["properties"]["tags"])


def test_source_findings_use_a_relative_path_and_lines() -> None:
    result = _run(to_sarif([_finding()], version="0.0.1"))["results"][0]

    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "app/db.py"
    assert physical["region"] == {"startLine": 12, "endLine": 14}


def test_live_findings_use_the_full_url() -> None:
    live = _finding(location=LiveLocation(url="https://app.test/items?id=1", method="POST"))

    result = _run(to_sarif([live], version="0.0.1"))["results"][0]

    location = result["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "https://app.test/items?id=1"
    assert location["properties"]["method"] == "POST"


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_severity_maps_to_a_sarif_level(severity: Severity, level: str) -> None:
    result = _run(to_sarif([_finding(severity=severity)], version="0.0.1"))["results"][0]

    assert result["level"] == level


def test_only_proven_and_corroborated_findings_are_reported_by_default() -> None:
    findings = [_finding(state=state) for state in FindingState]

    states = [
        r["properties"]["state"] for r in _run(to_sarif(findings, version="0.0.1"))["results"]
    ]

    assert sorted(states) == ["corroborated", "proven"]


def test_rules_are_listed_once_and_results_point_at_them() -> None:
    findings = [
        _finding(),
        _finding(location=SourceLocation(path="app/other.py", start_line=3)),
        _finding(rule_id="secrets.hardcoded", title="Hard-coded secret", cwes=(798,)),
    ]

    run = _run(to_sarif(findings, version="0.0.1"))

    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["injection.sql", "secrets.hardcoded"]
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]


def test_trace_becomes_a_code_flow() -> None:
    trace = (
        TraceStep(role="source", location=SourceLocation(path="app/api.py", start_line=3)),
        TraceStep(role="sink", location=SourceLocation(path="app/db.py", start_line=12)),
    )

    result = _run(to_sarif([_finding(trace=trace)], version="0.0.1"))["results"][0]

    steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
    uris = [step["location"]["physicalLocation"]["artifactLocation"]["uri"] for step in steps]
    assert uris == ["app/api.py", "app/db.py"]


def test_a_clean_run_is_still_a_valid_report() -> None:
    run = _run(to_sarif([], version="0.0.1"))

    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_tool_name_and_reported_states_come_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    configured = Settings(
        tool_name="Lynx CI",
        reported_states=frozenset({FindingState.CANDIDATE}),
    )
    monkeypatch.setattr("lynx.core.sarif.settings", configured)

    run = _run(to_sarif([_finding(state=FindingState.CANDIDATE)], version="0.0.1"))

    assert run["tool"]["driver"]["name"] == "Lynx CI"
    assert len(run["results"]) == 1


def test_secrets_in_findings_never_reach_the_report() -> None:
    token = "ghp" + "_" + "z9Y8x7W6" * 5
    finding = _finding(
        message=f"Token {token} is committed in config.py",
        location=LiveLocation(url="https://admin:hunter2-pass@app.test/x?api_key=abcd1234"),
    )

    report = json.dumps(to_sarif([finding], version="0.0.1"))

    assert token not in report
    assert "hunter2-pass" not in report
    assert "abcd1234" not in report


def test_a_whole_file_location_has_no_region() -> None:
    result = _run(
        to_sarif([_finding(location=SourceLocation(path="requirements.txt"))], version="0")
    )["results"][0]

    assert "region" not in result["locations"][0]["physicalLocation"]


def test_a_run_with_no_problems_completed() -> None:
    run = _run(to_sarif([_finding()], version="0.0.1"))

    assert run["invocations"] == [{"executionSuccessful": True}]


def test_problems_mark_the_run_incomplete_and_are_listed() -> None:
    run = _run(
        to_sarif([_finding()], version="0.0.1", problems=["gitleaks: not run (not installed)"])
    )

    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    notes = [note["message"]["text"] for note in invocation["toolExecutionNotifications"]]
    assert notes == ["gitleaks: not run (not installed)"]
    assert len(run["results"]) == 1
