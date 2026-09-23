"""令牌签发与校验。

- 访问令牌：base64url(payload).hmac-signature 的紧凑串。payload 只放
  jti/sid/sub/exp 等非敏感字段；每次请求仍回查服务端 AccessRecord，
  因此吊销与权限变更即时生效。
- 刷新令牌：256bit 随机串，明文只在签发时出现一次，库存仅存 sha256 摘要。
- 会话与刷新令牌族一一对应：session.id 即 family_id。
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import time

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import AccessRecord, RefreshRecord
from app.security import digest_token, new_token, sign
from app.store import Store

logger = logging.getLogger("auth_sessions.tokens")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _issue_access(store: Store, settings: Settings, user_id: str,
                  session_id: str, now: float) -> str:
    jti = secrets.token_urlsafe(18)
    payload = {
        "v": 1,
        "iss": settings.token_issuer,
        "jti": jti,
        "sid": session_id,
        "sub": user_id,
        "iat": int(now),
        "exp": int(now + settings.access_token_ttl),
    }
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    token = f"{body}.{sign(body.encode(), settings.token_secret)}"
    store.add_access(AccessRecord(
        jti=jti, session_id=session_id, user_id=user_id,
        issued_at=now, expires_at=now + settings.access_token_ttl,
    ))
    return token


def _issue_refresh(store: Store, family_id: str, ttl: int, now: float) -> str:
    raw = new_token(32)
    store.add_refresh(RefreshRecord(
        family_id=family_id,
        token_hash=digest_token(raw),
        issued_at=now,
        expires_at=now + ttl,
    ))
    return raw


def issue_tokens(store: Store, settings: Settings, user_id: str,
                 session_id: str, now: float | None = None
                 ) -> tuple[str, str]:
    """在同一把存储锁内签发访问+刷新令牌并完成登记。"""
    now = time.time() if now is None else now
    with store.lock:
        access_token = _issue_access(store, settings, user_id, session_id, now)
        raw_refresh = _issue_refresh(
            store, session_id, settings.refresh_token_ttl, now,
        )
    logger.info(
        "tokens issued: user_id=%s session_id=%s family_id=%s",
        user_id, session_id, session_id,
    )
    return access_token, raw_refresh


def parse_access_token(token: str, settings: Settings) -> dict:
    """解析并验签访问令牌；格式/签名/过期分别抛出可区分错误。"""
    try:
        body, sig = token.split(".", 1)
    except (ValueError, AttributeError):
        raise AuthError(ErrorCode.UNAUTHENTICATED, "malformed token")
    expected = sign(body.encode(), settings.token_secret)
    if not secrets.compare_digest(expected, sig):
        raise AuthError(ErrorCode.UNAUTHENTICATED, "bad signature")
    try:
        payload = json.loads(_b64d(body))
    except (ValueError, json.JSONDecodeError):
        raise AuthError(ErrorCode.UNAUTHENTICATED, "bad payload")
    if payload.get("iss") != settings.token_issuer:
        raise AuthError(ErrorCode.UNAUTHENTICATED, "unexpected issuer")
    if float(payload.get("exp", 0)) < time.time():
        raise AuthError(ErrorCode.ACCESS_TOKEN_EXPIRED)
    return payload


def verify_access(store: Store, token: str, settings: Settings):
    """访问令牌全链路校验：签名 -> 过期 -> 服务端登记 -> 会话 -> 用户。

    返回 (user, session, access_record)。角色/权限即时生效由这里保证：
    任何判定都以服务端当前 User/Session 状态为准，而非令牌内嵌快照。
    """
    payload = parse_access_token(token, settings)
    with store.lock:
        record = store.get_access(payload["jti"])
        if record is None:
            raise AuthError(ErrorCode.ACCESS_TOKEN_REVOKED, "token not registered")
        if record.revoked:
            raise AuthError(ErrorCode.ACCESS_TOKEN_REVOKED, "token revoked")
        if record.expires_at < time.time():
            raise AuthError(ErrorCode.ACCESS_TOKEN_EXPIRED)
        session = store.get_session(record.session_id)
        if session is None or session.revoked:
            raise AuthError(
                ErrorCode.ACCESS_TOKEN_REVOKED,
                "session revoked" if session else "session missing",
            )
        user = store.get_user(record.user_id)
        if user is None or user.disabled:
            raise AuthError(ErrorCode.ACCESS_TOKEN_REVOKED, "user unavailable")
    logger.info(
        "access verified: jti=%s session_id=%s user_id=%s role=%s",
        record.jti, record.session_id, user.id, user.role.value,
    )
    return user, session, record


def rotate_refresh(store: Store, settings: Settings, raw_refresh: str,
                   now: float | None = None) -> tuple[str, str]:
    """原子旋转刷新令牌，返回 (new_access, new_refresh)。

    检查与写入在存储大锁内一次完成，因此同一刷新凭证并发使用时
    有且仅有一个请求成功。拒绝原因互斥可区分：
      记录不存在     -> UNAUTHENTICATED
      已吊销         -> REFRESH_TOKEN_REVOKED
      已旋转(重放)   -> REFRESH_TOKEN_REPLAY，并按配置吊销整族/会话/访问令牌
      已过期         -> REFRESH_TOKEN_EXPIRED
      会话/用户失效  -> REFRESH_TOKEN_REVOKED
    """
    now = time.time() if now is None else now
    token_hash = digest_token(raw_refresh)

    with store.lock:
        old = store.get_refresh(token_hash)
        if old is None:
            raise AuthError(ErrorCode.UNAUTHENTICATED, "unknown refresh token")
        if old.revoked:
            logger.warning("refresh denied: revoked family_id=%s", old.family_id)
            raise AuthError(ErrorCode.REFRESH_TOKEN_REVOKED)
        if old.rotated:
            logger.warning(
                "refresh replay detected: family_id=%s -> revoking family",
                old.family_id,
            )
            if settings.revoke_family_on_replay:
                _revoke_family_locked(store, old.family_id, "replay_detected")
            raise AuthError(
                ErrorCode.REFRESH_TOKEN_REPLAY,
                extra={"family_id": old.family_id},
            )
        if old.expires_at < now:
            logger.warning("refresh denied: expired family_id=%s", old.family_id)
            raise AuthError(ErrorCode.REFRESH_TOKEN_EXPIRED)

        session = store.get_session(old.family_id)
        if session is None or session.revoked:
            raise AuthError(ErrorCode.REFRESH_TOKEN_REVOKED, "session ended")
        user = store.get_user(session.user_id)
        if user is None or user.disabled:
            raise AuthError(ErrorCode.REFRESH_TOKEN_REVOKED, "user unavailable")

        # 首次使用：同一临界区完成"标记旧凭证 + 签发下一代"
        new_access = _issue_access(store, settings, user.id, session.id, now)
        new_refresh = _issue_refresh(
            store, old.family_id, settings.refresh_token_ttl, now,
        )
        old.rotated = True
        old.next_hash = digest_token(new_refresh)

        logger.info(
            "refresh rotated: family_id=%s session_id=%s user_id=%s",
            old.family_id, session.id, user.id,
        )
        return new_access, new_refresh


def revoke_family_tree(store: Store, family_id: str, reason: str) -> None:
    """主动注销：吊销整条刷新族、其会话及该会话下全部访问令牌。"""
    with store.lock:
        _revoke_family_locked(store, family_id, reason)


def _revoke_family_locked(store: Store, family_id: str, reason: str) -> None:
    store.revoke_family(family_id, reason)
    session = store.get_session(family_id)
    if session is not None:
        session.revoked = True
        session.revoke_reason = reason
        store.revoke_session_accesses(session.id, reason)
