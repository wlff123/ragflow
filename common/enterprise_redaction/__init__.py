"""Opt-in, fail-closed document ingress for a dedicated validation instance."""

import os


class RedactionError(ValueError):
    """Only fixed, non-sensitive error codes may cross the ingress boundary."""


def enabled():
    value = os.environ.get("RAGFLOW_REDACTION_ENABLED", "0")
    if value not in {"0", "1"}:
        raise RedactionError("REDACTION_INVALID_ENABLED_FLAG")
    return value == "1"
