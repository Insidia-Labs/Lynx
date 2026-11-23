"""SARIF 2.1.0 output, in the shape the Insidia Labs Test Suite scores.

CWE ids go in `properties.tags` on both the rule and the result, source findings
use paths relative to the scanned folder with line numbers, and live findings use
the full URL. A run that found nothing still produces a valid report, and secrets
quoted in findings are masked before anything is returned.
"""

from collections.abc import Iterable, Sequence
from typing import Any

from lynx.config import SARIF_SCHEMA, SARIF_VERSION, SOURCE_ROOT, settings
from lynx.core.findings import (
    Finding,
    LiveLocation,
    Severity,
    SourceLocation,
    TraceStep,
)
from lynx.core.mask import mask_secrets

type Json = dict[str, Any]


_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning ranks alerts by this score (0.0-10.0), passed as a string.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _cwe_tags(cwes: Iterable[int]) -> list[str]:
    return [f"CWE-{cwe}" for cwe in cwes]


def to_sarif(findings: Iterable[Finding], *, version: str) -> Json:
    """Build a SARIF document from the findings in the reported states (see `lynx.config`)."""
    reported = [finding for finding in findings if finding.state in settings.reported_states]
    rules, index = _rules(reported)
    driver = {
        "name": settings.tool_name,
        "version": version,
        "informationUri": settings.information_uri,
    }
    run = {
        "tool": {"driver": {**driver, "rules": rules}},
        "originalUriBaseIds": {SOURCE_ROOT: {"description": {"text": "The scanned folder"}}},
        "results": [_result(finding, index[finding.rule_id]) for finding in reported],
    }
    return mask_secrets({"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]})


def _rules(findings: Sequence[Finding]) -> tuple[list[Json], dict[str, int]]:
    """One rule per rule id, in first-seen order, with the index each result points at."""
    first: dict[str, Finding] = {}

    def _rule(finding: Finding) -> Json:
        return {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "properties": {
                "tags": ["security", *_cwe_tags(finding.cwes)],
                "security-severity": _SECURITY_SEVERITY[finding.severity],
            },
        }

    for finding in findings:
        first.setdefault(finding.rule_id, finding)
    rules = [_rule(finding) for finding in first.values()]
    return rules, {rule_id: position for position, rule_id in enumerate(first)}


def _result(finding: Finding, rule_index: int) -> Json:
    result: Json = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity],
        "message": {"text": finding.message},
        "locations": [_location(finding.location)],
        "properties": {
            "tags": _cwe_tags(finding.cwes),
            "state": finding.state.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "detector": finding.detector,
        },
    }
    if not finding.trace:
        return result
    return {**result, "codeFlows": [_code_flow(finding.trace)]}


def _location(location: SourceLocation | LiveLocation) -> Json:
    if isinstance(location, LiveLocation):
        return {
            "physicalLocation": {"artifactLocation": {"uri": location.url}},
            "properties": {"method": location.method},
        }
    region = {"startLine": location.start_line}
    if location.end_line is not None:
        region = {**region, "endLine": location.end_line}
    artifact = {"uri": location.path, "uriBaseId": SOURCE_ROOT}
    return {"physicalLocation": {"artifactLocation": artifact, "region": region}}


def _code_flow(trace: Sequence[TraceStep]) -> Json:
    steps = [
        {
            "location": {
                **_location(step.location),
                "message": {"text": f"{step.role}: {step.symbol}" if step.symbol else step.role},
            }
        }
        for step in trace
    ]
    return {"threadFlows": [{"locations": steps}]}
