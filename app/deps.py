"""FastAPI dependencies: application state, principal and authorization."""

from __future__ import annotations

from fastapi import Depends, Request

from app.config import Settings
from app.errors import AuthError, AuthErrorCode
from app.models import User
from app.permissions import Constraint, is_allowed
from app.ratelimit import LoginRateLimiter
from app.store import DataStore
from app.tokens import AccessClaims, Session, authenticate_access_token

BEARER_PREFIX = "Bearer "


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_store(request: Request) -> DataStore:
    return request.app.state.store


def get_rate_limiter(request: Request) -> LoginRateLimiter:
    return request.app.state.rate_limiter


def _extract_bearer(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if not header:
        return None
    if not header.startswith(BEARER_PREFIX):
        raise AuthError(AuthErrorCode.MALFORMED_TOKEN)
    token = header[len(BEARER_PREFIX):].strip()
    if not token:
        raise AuthError(AuthErrorCode.MISSING_TOKEN)
    return token


def client_source(request: Request) -> str:
    # First hop only; behind a trusted proxy use forwarded/X-Forwarded-For.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


Principal = tuple[User, Session, AccessClaims]


def get_principal(
    request: Request,
    settings: Settings = Depends(get_app_settings),
    store: DataStore = Depends(get_store),
) -> Principal:
    """Require a valid, live access token; fail with a specific code."""
    token = _extract_bearer(request)
    if token is None:
        raise AuthError(AuthErrorCode.MISSING_TOKEN)
    return authenticate_access_token(
        token, store, settings, source=client_source(request)
    )


def authorize(
    user: User,
    action: str,
    resource: object | None = None,
    *,
    constraints: dict[str, Constraint] | None = None,
    source: str = "-",
) -> None:
    """Raise FORBIDDEN when the policy denies an existing resource."""
    if not is_allowed(user, action, resource, constraints=constraints, source=source):
        raise AuthError(AuthErrorCode.FORBIDDEN, status_code=403)
