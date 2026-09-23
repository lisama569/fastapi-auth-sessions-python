"""Logging helpers that never leak credentials.

* :data:`SENSITIVE_FIELDS` lists keys whose values must never be logged.
* :func:`redact` recursively masks those keys (and any token-shaped value).
* :func:`audit` emits one structured line describing the *input* and the
  *decision basis* for an auth/access decision, which the test suite uses
  to make failures explainable.
"""

from __future__ import annotations

import json
import logging
from typing import Any

SENSITIVE_FIELDS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "current_password",
        "new_password",
        "refresh_token",
        "access_token",
        "token",
        "authorization",
        "jwt",
        "secret",
        "jwt_secret",
        "hash",
        "password_hash",
    }
)

REDACTED = "***REDACTED***"

logger = logging.getLogger("auth.audit")


def _looks_like_token(value: str) -> bool:
    # Only mask JWT-shaped values heuristically; opaque tokens are expected
    # to be logged under sensitive key names. This avoids masking ordinary
    # identifiers such as session ids.
    return value.count(".") == 2 and len(value) >= 16


def redact(data: Any) -> Any:
    """Return a copy of *data* with sensitive values masked."""
    if isinstance(data, dict):
        return {
            k: REDACTED
            if k.lower() in SENSITIVE_FIELDS and v is not None
            else redact(v)
            for k, v in data.items()
        }
    if isinstance(data, (list, tuple)):
        return [redact(v) for v in data]
    if isinstance(data, str) and _looks_like_token(data):
        return REDACTED
    return data


def audit(event: str, *, inputs: dict[str, Any] | None = None,
          decision: str | None = None, basis: str | None = None,
          **extra: Any) -> None:
    """Emit a structured, redacted audit record.

    ``inputs`` records what the caller supplied; ``decision`` is allow/deny
    and ``basis`` explains the rule that produced it.
    """
    record: dict[str, Any] = {"event": event}
    if inputs is not None:
        record["inputs"] = redact(inputs)
    if decision is not None:
        record["decision"] = decision
    if basis is not None:
        record["basis"] = basis
    for key, value in extra.items():
        record[key] = redact(value)
    logger.info(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str))
