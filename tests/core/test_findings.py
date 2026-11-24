import pytest
from pydantic import ValidationError

from lynx.core.findings import (
    Confidence,
    Finding,
    FindingState,
    Needle,
    Severity,
    SourceLocation,
    TraceStep,
)


def _finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "rule_id": "injection.sql",
        "title": "SQL injection",
        "message": "User input reaches a SQL query without parameters.",
        "cwes": (89,),
        "severity": Severity.HIGH,
        "location": SourceLocation(path="app/db.py", start_line=12),
        "detector": "taylon",
    }
    fields.update(overrides)
    return Finding.model_validate(fields)


def test_a_new_finding_starts_as_a_candidate() -> None:
    finding = _finding()

    assert finding.state is FindingState.CANDIDATE
    assert finding.confidence is Confidence.MEDIUM


def test_findings_are_immutable() -> None:
    finding = _finding()

    with pytest.raises(ValidationError):
        finding.state = FindingState.PROVEN  # type: ignore[misc]


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(verified=True)


def test_source_lines_start_at_one() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(path="a.py", start_line=0)


def test_cwe_ids_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        _finding(cwes=(0,))


def test_trace_and_needles_are_kept_in_order() -> None:
    trace = (
        TraceStep(role="source", location=SourceLocation(path="app/api.py", start_line=3)),
        TraceStep(role="sink", location=SourceLocation(path="app/db.py", start_line=12)),
    )
    needle = Needle(location=SourceLocation(path="app/db.py", start_line=12), text="execute(")

    finding = _finding(trace=trace, needles=(needle,))

    assert [step.role for step in finding.trace] == ["source", "sink"]
    assert finding.needles == (needle,)


def test_a_source_location_without_lines_means_the_whole_file() -> None:
    location = SourceLocation(path="requirements.txt")

    assert location.start_line is None
