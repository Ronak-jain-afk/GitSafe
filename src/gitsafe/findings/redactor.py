"""Secret value redaction for safe output."""

from __future__ import annotations


def redact_local(value: str) -> str:
    """Partial reveal for local terminal: first 4 + last 2 chars.

    Example: ``ghp_Abc123xyz9`` → ``ghp_...z9``
    """
    if len(value) <= 6:
        return "[REDACTED]"
    return f"{value[:4]}...{value[-2:]}"


def redact_ci(_value: str) -> str:
    """Full redaction for CI logs — never reveal any part."""
    return "[REDACTED]"


def redact(value: str, *, ci_mode: bool = False) -> str:
    """Redact a matched secret value."""
    if ci_mode:
        return redact_ci(value)
    return redact_local(value)
