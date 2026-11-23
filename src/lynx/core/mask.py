"""Secret masking for everything Lynx writes out.

Findings often quote what they found, so a report could carry the secret itself.
Every output goes through `mask_secrets` before it's written.

The patterns are fixed in code, not settings: anything that could switch masking
off would let a scanned repository leak secrets into reports.
"""

import re
from typing import Any

# Applied in order. Specific token formats come before the generic name=value rule,
# and replacements keep any matched prefix (a header or parameter name) for context.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED:PRIVATE_KEY]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:AWS_ACCESS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED:SLACK_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), "[REDACTED:GOOGLE_API_KEY]"),
    (re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}"), "[REDACTED:STRIPE_KEY]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "[REDACTED:ANTHROPIC_KEY]"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"), "[REDACTED:OPENAI_KEY]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "[REDACTED:JWT]",
    ),
    (
        re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]+"),
        r"\1[REDACTED:AUTHORIZATION]",
    ),
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@:]+:[^/\s@]+@"),
        r"\1[REDACTED:URL_CREDENTIALS]@",
    ),
    (
        re.compile(
            r"(?i)\b((?:client[_-]?)?secret|password|passwd|pwd|api[_-]?key"
            r"|(?:access|auth)[_-]?token|token)"
            r"([\"']?\s*[:=]\s*[\"']?)[^\s\"'&;,]{4,}"
        ),
        r"\1\2[REDACTED:SECRET]",
    ),
)


def mask_secrets(document: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a JSON-like document with secrets masked in every string."""
    return {key: _mask_value(value) for key, value in document.items()}


def _mask_value(value: Any) -> Any:
    if isinstance(value, str):
        return _mask_text(value)
    if isinstance(value, dict):
        return mask_secrets(value)
    if isinstance(value, list):
        return [_mask_value(item) for item in value]
    return value


def _mask_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
