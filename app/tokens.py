"""Access token (JWT) and rotating refresh token primitives.

Access tokens are short-lived self-contained JWTs (HS256) carrying the
user id, session id and the *security version* at issuance. Every
authenticated request re-checks the session state and current security
version against the store, so logout/revocation and role/permission
changes take effect immediately without waiting for token expiry.

Refresh tokens are opaque high-entropy strings. Only a SHA-256 digest is
stored server-side, they are single-use, and rotation is atomic
(:meth:`app.store.DataStore.rotate_refresh_token`).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

import jwt

from app.config import Settings
from app.crypto import generate_token_id
from app.errors import AuthError, AuthErrorCode
from app.logging_utils import audit
from app.models import RefreshTokenRecord, Session, User
from app.store import DataStore

ACCESS_TOKEN_TYPE = "access"


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int


@dataclass
class AccessClaims:
    user_id: str
    session_id: str
    jti: str
    security_version: int
    issued_at: float
    expires_at: float


# --------------------------------------------------------------- access tokens
def issue_access_token(
    user: User,
    session: Session,
    security_version: int,
    settings: Settings,
    *,
    now: float | None = None,
) -> tuple[str, int]:
    now = time.time() if now is None else now
    expires_at = now + settings.access_token_ttl_seconds
    payload = {
        "sub": user.id,
        "sid": session.id,
        "jti": generate_token_id(),
        "sv": security_version,
        "type": ACCESS_TOKEN_TYPE,
        "iss": settings.jwt_issuer,
        "iat": int(now),
        "exp": int(expires_at),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, settings.access_token_ttl_seconds


def decode_access_token(token: str, settings: Settings) -> AccessClaims:
    """Parse/verify the JWT signature and temporal claims.

    Raises a distinguishable :class:`AuthError` for each failure mode.
    Stateful checks (revocation, security version) happen separately in
    :func:`authenticate_access_token`.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "sid", "jti", "sv", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError(AuthErrorCode.TOKEN_EXPIRED) from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthError(AuthErrorCode.BAD_SIGNATURE) from exc
    except jwt.InvalidSignatureError as exc:
        raise AuthError(AuthErrorCode.BAD_SIGNATURE) from exc
    except jwt.InvalidTokenError as exc:  # malformed / missing claims / nbf
        raise AuthError(AuthErrorCode.MALFORMED_TOKEN) from exc

    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise AuthError(AuthErrorCode.UNSUPPORTED_TOKEN)

    return AccessClaims(
        user_id=payload["sub"],
        session_id=payload["sid"],
        jti=payload["jti"],
        security_version=int(payload["sv"]),
        issued_at=float(payload["iat"]),
        expires_at=float(payload["exp"]),
    )


def authenticate_access_token(
    token: str, store: DataStore, settings: Settings, *, source: str = "-"
) -> tuple[User, Session, AccessClaims]:
    """Full validation: signature/expiry + live session + security version."""
    claims = decode_access_token(token, settings)

    user = store.get_user(claims.user_id)
    if user is None:
        audit(
            "access_denied",
            inputs={"user_id": claims.user_id, "source": source},
            decision="deny",
            basis="user not found",
        )
        raise AuthError(AuthErrorCode.SESSION_NOT_FOUND)
    if user.disabled:
        audit(
            "access_denied",
            inputs={"user_id": user.id, "source": source},
            decision="deny",
            basis="user disabled",
        )
        raise AuthError(AuthErrorCode.USER_DISABLED)

    session = store.get_session(claims.session_id)
    if session is None or session.user_id != user.id:
        audit(
            "access_denied",
            inputs={"user_id": user.id, "session_id": claims.session_id, "source": source},
            decision="deny",
            basis="session not found",
        )
        raise AuthError(AuthErrorCode.SESSION_NOT_FOUND)
    if session.revoked:
        audit(
            "access_denied",
            inputs={"user_id": user.id, "session_id": session.id, "source": source},
            decision="deny",
            basis=f"session revoked: {session.revoked_reason}",
        )
        raise AuthError(AuthErrorCode.SESSION_REVOKED)

    current_version = store.get_security_version(user.id)
    if claims.security_version < current_version:
        audit(
            "access_denied",
            inputs={
                "user_id": user.id,
                "source": source,
                "token_sv": claims.security_version,
                "current_sv": current_version,
            },
            decision="deny",
            basis="stale security version: roles/permissions changed",
        )
        # The presented credential predates a security change and must not
        # carry old entitlements; report it as a revoked session.
        raise AuthError(AuthErrorCode.SESSION_REVOKED)

    audit(
        "access_allowed",
        inputs={"user_id": user.id, "session_id": session.id, "source": source},
        decision="allow",
        basis="valid signature, active session, current security version",
    )
    return user, session, claims


# -------------------------------------------------------------- refresh tokens
def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_token_pair(
    store: DataStore,
    user: User,
    session: Session,
    settings: Settings,
    *,
    family_id: str | None = None,
    now: float | None = None,
) -> TokenPair:
    """Mint an access/refresh pair; persist only the refresh token digest."""
    now = time.time() if now is None else now
    raw_refresh = generate_token_id()
    record = RefreshTokenRecord(
        id=hash_refresh_token(raw_refresh),
        family_id=family_id or generate_token_id(),
        session_id=session.id,
        user_id=user.id,
        issued_at=now,
        expires_at=now + settings.refresh_token_ttl_seconds,
    )
    store.save_refresh_token(record)
    access_token, expires_in = issue_access_token(
        user, session, store.get_security_version(user.id), settings, now=now
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=raw_refresh,
        access_expires_in=expires_in,
    )


def rotate_refresh_token(
    raw_token: str,
    store: DataStore,
    settings: Settings,
    *,
    source: str = "-",
    now: float | None = None,
) -> TokenPair:
    """Rotate a refresh token exactly once.

    Distinguishable outcomes:
    * unknown/missing digest  -> ``session_not_found``
    * expired                 -> ``token_expired``
    * family flagged          -> ``token_replayed`` (breach containment)
    * token already used      -> ``token_replayed`` and the family is
      revoked immediately (reuse detection / stolen-token reaction)
    * token revoked (logout)  -> ``session_revoked``
    """
    now = time.time() if now is None else now
    token_id = hash_refresh_token(raw_token)
    record = store.get_refresh_token(token_id)

    if record is None:
        audit(
            "refresh_denied",
            inputs={"source": source},
            decision="deny",
            basis="refresh token digest not found",
        )
        raise AuthError(AuthErrorCode.SESSION_NOT_FOUND)

    if store.is_family_compromised(record.family_id):
        audit(
            "refresh_denied",
            inputs={"family_id": record.family_id, "source": source},
            decision="deny",
            basis="token family already revoked due to replay",
        )
        raise AuthError(AuthErrorCode.TOKEN_REPLAYED)

    if record.expires_at <= now:
        audit(
            "refresh_denied",
            inputs={"user_id": record.user_id, "source": source},
            decision="deny",
            basis="refresh token expired",
        )
        raise AuthError(AuthErrorCode.TOKEN_EXPIRED)

    if record.revoked and not record.used:
        audit(
            "refresh_denied",
            inputs={"user_id": record.user_id, "source": source},
            decision="deny",
            basis="refresh token revoked (logout/admin)",
        )
        raise AuthError(AuthErrorCode.SESSION_REVOKED)

    user = store.get_user(record.user_id)
    if user is None or user.disabled:
        audit(
            "refresh_denied",
            inputs={"user_id": record.user_id, "source": source},
            decision="deny",
            basis="user missing or disabled",
        )
        raise AuthError(AuthErrorCode.USER_DISABLED)

    session = store.get_session(record.session_id)
    if session is None or session.revoked:
        audit(
            "refresh_denied",
            inputs={"user_id": record.user_id, "source": source},
            decision="deny",
            basis="session revoked or missing",
        )
        raise AuthError(AuthErrorCode.SESSION_REVOKED)

    # Prepare the successor first; the swap itself is atomic.
    successor_raw = generate_token_id()
    successor = RefreshTokenRecord(
        id=hash_refresh_token(successor_raw),
        family_id=record.family_id,
        session_id=session.id,
        user_id=user.id,
        issued_at=now,
        expires_at=now + settings.refresh_token_ttl_seconds,
    )

    winner = store.rotate_refresh_token(token_id, successor, now)
    if winner is None:
        # Lost the race or the token was already consumed: this is a replay.
        # Revoke the entire family so the stolen token cannot be traded in.
        store.mark_family_compromised(record.family_id, reason="replay")
        audit(
            "refresh_replay_detected",
            inputs={"family_id": record.family_id, "source": source},
            decision="deny",
            basis="refresh token already used; family revoked",
        )
        raise AuthError(AuthErrorCode.TOKEN_REPLAYED)

    access_token, expires_in = issue_access_token(
        user, session, store.get_security_version(user.id), settings, now=now
    )
    audit(
        "refresh_rotated",
        inputs={"user_id": user.id, "family_id": record.family_id, "source": source},
        decision="allow",
        basis="atomic single-use rotation succeeded",
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=successor_raw,
        access_expires_in=expires_in,
    )
