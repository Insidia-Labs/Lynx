"""The findings schema: what Lynx found, where, and how sure it is.

Findings are immutable. Every finding starts as a candidate; only the proof gate
(`lynx.proof`) and the fix verifier move it to corroborated, proven or refuted.
"""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class FindingState(StrEnum):
    CANDIDATE = "candidate"
    CORROBORATED = "corroborated"
    PROVEN = "proven"
    REFUTED = "refuted"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SourceLocation(_Frozen):
    """A place in the scanned source, by path relative to the scanned folder."""

    kind: Literal["source"] = "source"
    path: str = Field(min_length=1)
    start_line: int | None = Field(default=None, ge=1)  # None means the whole file
    end_line: int | None = Field(default=None, ge=1)


class LiveLocation(_Frozen):
    """A place in a running target: an http(s) URL and the request method."""

    kind: Literal["live"] = "live"
    url: str = Field(min_length=1)
    method: str = "GET"


Location = Annotated[SourceLocation | LiveLocation, Field(discriminator="kind")]


class TraceStep(_Frozen):
    """One hop of a data flow, from where input enters to where it does harm."""

    role: Literal["source", "step", "sink"]
    location: SourceLocation
    symbol: str | None = None


class Needle(_Frozen):
    """Exact text at an exact place; the proof gate checks it exists on disk."""

    location: SourceLocation
    text: str = Field(min_length=1)


class Finding(_Frozen):
    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._/-]*$")
    title: str = Field(min_length=1)
    message: str = Field(min_length=1)
    cwes: tuple[Annotated[int, Field(ge=1)], ...] = ()
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    state: FindingState = FindingState.CANDIDATE
    location: Location
    trace: tuple[TraceStep, ...] = ()
    needles: tuple[Needle, ...] = ()
    detector: str = Field(min_length=1)
