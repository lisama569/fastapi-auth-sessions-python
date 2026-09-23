"""Auth routes: login, refresh rotation, logout, admin revoke, me."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.config import Settings
from app.crypto import verify_password
from app.deps import (
    client_source,
    get_app_settings,
    get_principal,
    get_rate_limiter,
    get_store,
)
from app.errors import AuthError, AuthErrorCode
from app.logging_utils import audit
from app.models import (
    AccessTokenResponse,
    LoginRequest,
    RefreshRequest,
    Session,
    UserView,
)
from app.permissions import has_action
from app.ratelimit import LoginRateLimiter
from app.store import DataStore
from app.tokens import (
    issue_token_pair,
    rotate_refresh_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# --------------------------------------------------------------------- helpers
def _set_refresh_cookie(response: Response, raw_token: str, settings: Settings) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=raw_token,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path=settings.refresh_cookie_path,
        domain=settings.cookie_domain,
    )


def _clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=settings.refresh_cookie_path,
        domain=settings.cookie_domain,
    )


def _read_refresh_token(request: Request, body_token: str | None) -> str:
    if body_token:
        return body_token.strip()
    cookie_value = request.cookies.get(request.app.state.settings.refresh_cookie_name)
    if cookie_value:
        return cookie_value
    raise AuthError(AuthErrorCode.MISSING_TOKEN)


def _tokens_response(pair, settings: Settings) -> JSONResponse:
    payload = AccessTokenResponse(
        access_token=pair.access_token, expires_in=pair.access_expires_in
    ).model_dump()
    response = JSONResponse(payload)
    _set_refresh_cookie(response, pair.refresh_token, settings)
    return response


# ---------------------------------------------------------------------- routes
@router.post("/login", response_model=AccessTokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    settings: Settings = Depends(get_app_settings),
    store: DataStore = Depends(get_store),
    limiter: LoginRateLimiter = Depends(get_rate_limiter),
):
    source = client_source(request)
    now = time.time()

    retry_after = limiter.check(body.username, source, now)
    if retry_after > 0:
        audit(
            "login_throttled",
            inputs={"username": body.username, "source": source},
            decision="deny",
            basis="rate limiter locked due to repeated failures",
        )
        raise AuthError(
            AuthErrorCode.RATE_LIMITED, status_code=429, retry_after=retry_after
        )

    user = store.get_user_by_username(body.username)
    # Always perform a hash comparison path where possible to reduce
    # username-enumeration timing differences; failures share one code.
    password_ok = False
    if user is not None:
        password_ok = verify_password(body.password, user.password_hash)

    if user is None or not password_ok:
        wait = limiter.record_failure(body.username, source, now)
        audit(
            "login_failed",
            inputs={"username": body.username, "source": source},
            decision="deny",
            basis="unknown username" if user is None else "bad password",
        )
        if wait > 0:
            raise AuthError(
                AuthErrorCode.RATE_LIMITED, status_code=429, retry_after=wait
            )
        raise AuthError(AuthErrorCode.INVALID_CREDENTIALS)

    if user.disabled:
        audit(
            "login_failed",
            inputs={"username": body.username, "source": source},
            decision="deny",
            basis="user disabled",
        )
        raise AuthError(AuthErrorCode.USER_DISABLED, status_code=403)

    limiter.record_success(body.username, source)
    session = Session(
        id=f"s_{user.id}_{int(now * 1000)}",
        user_id=user.id,
        created_at=now,
        last_rotated_at=now,
    )
    store.add_session(session)
    pair = issue_token_pair(store, user, session, settings, now=now)
    audit(
        "login_succeeded",
        inputs={"username": body.username, "source": source, "session_id": session.id},
        decision="allow",
        basis="password verified; session created",
    )
    return _tokens_response(pair, settings)


@router.post("/refresh", response_model=AccessTokenResponse)
def refresh(
    request: Request,
    body: RefreshRequest | None = None,
    settings: Settings = Depends(get_app_settings),
    store: DataStore = Depends(get_store),
):
    source = client_source(request)
    body_token = body.refresh_token if body is not None else None
    raw = _read_refresh_token(request, body_token)
    pair = rotate_refresh_token(raw, store, settings, source=source)
    return _tokens_response(pair, settings)


@router.post("/logout")
def logout(
    request: Request,
    principal=Depends(get_principal),
    settings: Settings = Depends(get_app_settings),
    store: DataStore = Depends(get_store),
):
    user, session, _ = principal
    store.revoke_session(session.id, reason="logout")
    # Revoke every refresh family attached to this session.
    family_ids = {
        rt.family_id
        for rt in store.refresh_tokens.values()
        if rt.session_id == session.id
    }
    for family_id in family_ids:
        store.revoke_family(family_id, reason="logout")
    audit(
        "logout",
        inputs={"user_id": user.id, "session_id": session.id},
        decision="allow",
        basis="session and refresh family revoked",
    )
    response = Response(status_code=204)
    _clear_refresh_cookie(response, settings)
    return response


@router.post("/users/{user_id}/revoke")
def admin_revoke_user_sessions(
    user_id: str,
    principal=Depends(get_principal),
    store: DataStore = Depends(get_store),
):
    actor, _, _ = principal
    if not has_action(actor, "user:manage"):
        raise AuthError(AuthErrorCode.FORBIDDEN, status_code=403)
    target = store.get_user(user_id)
    if target is None:
        # Uniform 404: existence must not be exposed to unauthorized calls.
        raise AuthError(AuthErrorCode.NOT_FOUND, status_code=404)
    store.revoke_all_user_sessions(target.id, reason="admin_revoke")
    audit(
        "admin_revoke",
        inputs={"actor_id": actor.id, "user_id": user_id},
        decision="allow",
        basis="user:manage; all sessions revoked",
    )
    return {"revoked": True}


@router.get("/me", response_model=UserView)
def me(principal=Depends(get_principal)):
    user, _, _ = principal
    return UserView.of(user)


class RoleUpdate(BaseModel):
    roles: list[str] | None = None
    permissions: list[str] | None = None
    disabled: bool | None = None


@router.put("/users/{user_id}/security", response_model=UserView)
def update_user_security(
    user_id: str,
    payload: RoleUpdate,
    principal=Depends(get_principal),
    store: DataStore = Depends(get_store),
):
    """Admin changes roles/permissions/disabled flag.

    The security version is bumped, so already-issued access tokens stop
    carrying old entitlements on their *next* request — no waiting for
    token expiry and no forced logout. Sessions are intentionally left in
    place; explicit revocation uses ``/revoke``.
    """
    actor, _, _ = principal
    if not has_action(actor, "user:manage"):
        raise AuthError(AuthErrorCode.FORBIDDEN, status_code=403)
    target = store.get_user(user_id)
    if target is None:
        raise AuthError(AuthErrorCode.NOT_FOUND, status_code=404)

    changed = False
    if payload.roles is not None:
        target.roles = set(payload.roles)
        changed = True
    if payload.permissions is not None:
        target.permissions = set(payload.permissions)
        changed = True
    if payload.disabled is not None and payload.disabled != target.disabled:
        target.disabled = payload.disabled
        changed = True
    if changed:
        store.update_user_security(user_id)
    audit(
        "security_attributes_changed",
        inputs={
            "actor_id": actor.id,
            "user_id": user_id,
            "roles": sorted(target.roles),
            "permissions": sorted(target.permissions),
            "disabled": target.disabled,
        },
        decision="allow",
        basis="user:manage; security version bumped; existing tokens re-checked",
    )
    return UserView.of(target)
