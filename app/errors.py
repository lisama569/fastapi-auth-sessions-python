"""Distinguishable auth/access error codes and exception handling.

Every security-relevant rejection maps to a stable machine-readable
``error.code`` so callers (and tests) can tell apart expired, revoked,
replayed, throttled and forbidden requests.
"""

from __future__ import annotations

from enum import Enum

from fastapi import Request
from fastapi.responses import JSONResponse


class AuthErrorCode(str, Enum):
    INVALID_CREDENTIALS = "invalid_credentials"      # bad username/password
    MISSING_TOKEN = "missing_token"                  # no access token presented
    MALFORMED_TOKEN = "malformed_token"              # unparsable token
    UNSUPPORTED_TOKEN = "unsupported_token_type"     # unexpected type/header
    BAD_SIGNATURE = "bad_signature"                  # signature verification failed
    TOKEN_EXPIRED = "token_expired"                  # exp passed
    SESSION_REVOKED = "session_revoked"              # logout / explicit revoke
    SESSION_NOT_FOUND = "session_not_found"          # jti unknown / already rotated
    TOKEN_REPLAYED = "token_replayed"                # rotated refresh token reused
    USER_DISABLED = "user_disabled"                  # account deactivated
    FORBIDDEN = "forbidden"                          # authenticated but not allowed
    NOT_FOUND = "not_found"                          # resource missing/forbidden (uniform)
    RATE_LIMITED = "rate_limited"                    # login throttled
    BAD_REQUEST = "bad_request"


class AuthError(Exception):
    def __init__(
        self,
        code: AuthErrorCode,
        status_code: int = 401,
        message: str | None = None,
        *,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.status_code = status_code
        self.message = message or DEFAULT_MESSAGES.get(code, code.value)
        self.retry_after = retry_after


DEFAULT_MESSAGES: dict[AuthErrorCode, str] = {
    AuthErrorCode.INVALID_CREDENTIALS: "Invalid username or password.",
    AuthErrorCode.MISSING_TOKEN: "Authentication credentials were not provided.",
    AuthErrorCode.MALFORMED_TOKEN: "Token is malformed.",
    AuthErrorCode.UNSUPPORTED_TOKEN: "Unsupported token type.",
    AuthErrorCode.BAD_SIGNATURE: "Token signature is invalid.",
    AuthErrorCode.TOKEN_EXPIRED: "Token has expired.",
    AuthErrorCode.SESSION_REVOKED: "Session has been revoked.",
    AuthErrorCode.SESSION_NOT_FOUND: "Session does not exist.",
    AuthErrorCode.TOKEN_REPLAYED: "Refresh token has already been used.",
    AuthErrorCode.USER_DISABLED: "User account is disabled.",
    AuthErrorCode.FORBIDDEN: "You are not allowed to perform this action.",
    AuthErrorCode.NOT_FOUND: "Resource not found.",
    AuthErrorCode.RATE_LIMITED: "Too many attempts. Please back off and retry.",
    AuthErrorCode.BAD_REQUEST: "Malformed request.",
}


def register_exception_handlers(app) -> None:
    @app.exception_handler(AuthError)
    async def _handle_auth_error(_: Request, exc: AuthError) -> JSONResponse:
        headers: dict[str, str] = {}
        if exc.retry_after is not None:
            # RFC 6585 §4: seconds, round up.
            headers["Retry-After"] = str(max(1, int(exc.retry_after + 0.999)))
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code.value,
                    "message": exc.message,
                }
            },
            headers=headers,
        )
