"""登录/刷新/注销主流程；过期、吊销、重放必须可区分；敏感信息不外泄。"""

from __future__ import annotations

import time

import pytest

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.services import AuthService
from app.tokens import parse_access_token



def test_login_success_issues_separated_tokens(svc: AuthService):
    result = svc.login("viewer", "viewer-pw", "10.0.0.1")
    assert result.access_token != result.refresh_token
    # 访问令牌可通过服务端校验并对应当前用户/会话
    user, session, record = svc.authenticate(result.access_token)
    assert user.username == "viewer"
    assert session.id == result.session_id
    assert record.session_id == result.session_id
    print("\n[input] viewer/viewer-pw -> [decision] authenticated, role=viewer")


def test_invalid_password_and_unknown_user_share_same_code(svc: AuthService):
    with pytest.raises(AuthError) as e1:
        svc.login("viewer", "wrong", "10.0.0.1")
    with pytest.raises(AuthError) as e2:
        svc.login("nobody", "wrong", "10.0.0.1")
    # 不暴露账号是否存在：错误码与状态完全一致
    assert e1.value.code is ErrorCode.INVALID_CREDENTIALS
    assert e2.value.code is ErrorCode.INVALID_CREDENTIALS
    print("\n[input] bad password vs unknown user "
          "-> [decision] both invalid_credentials (no enumeration)")


def test_refresh_rotates_and_old_refresh_is_replay(svc: AuthService):
    r = svc.login("viewer", "viewer-pw", "10.0.0.1")
    new_access, new_refresh = svc.refresh(r.refresh_token)
    assert new_access != r.access_token
    assert new_refresh != r.refresh_token
    svc.authenticate(new_access)  # 新访问令牌有效

    # 旧刷新凭证再次使用 -> 明确的重放错误
    with pytest.raises(AuthError) as replay:
        svc.refresh(r.refresh_token)
    assert replay.value.code is ErrorCode.REFRESH_TOKEN_REPLAY
    print("\n[input] reused old refresh token "
          "-> [decision] refresh_token_replay, family revoked")

    # 重放即被盗用：族内新访问令牌立即失效，新刷新凭证被吊销
    with pytest.raises(AuthError) as access_err:
        svc.authenticate(new_access)
    assert access_err.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    with pytest.raises(AuthError) as refresh_err:
        svc.refresh(new_refresh)
    assert refresh_err.value.code is ErrorCode.REFRESH_TOKEN_REVOKED


def test_expired_refresh_is_distinct_from_revoked(svc: AuthService):
    fast = Settings(refresh_token_ttl=60)
    svc.settings = fast
    r = svc.login("viewer", "viewer-pw", "10.0.0.1")
    with pytest.raises(AuthError) as expired:
        svc.refresh(r.refresh_token, now=time.time() + 61)
    assert expired.value.code is ErrorCode.REFRESH_TOKEN_EXPIRED
    print("\n[input] refresh beyond ttl -> [decision] refresh_token_expired")

    # 主动注销的凭证 -> 明确的 revoked，而非 expired/replay
    r2 = svc.login("viewer", "viewer-pw", "10.0.0.2")
    svc.logout(r2.refresh_token, r2.access_token)
    with pytest.raises(AuthError) as revoked:
        svc.refresh(r2.refresh_token)
    assert revoked.value.code is ErrorCode.REFRESH_TOKEN_REVOKED
    print("\n[input] refresh after logout -> [decision] refresh_token_revoked")


def test_expired_access_token_is_distinct_from_revoked(svc: AuthService):
    fast = Settings(access_token_ttl=60)
    svc.settings = fast
    r = svc.login("viewer", "viewer-pw", "10.0.0.1")
    # 篡改 exp：直接解析结构后构造过期场景
    import json, base64
    from app.security import sign
    body, _sig = r.access_token.split(".", 1)
    pad = "=" * (-len(body) % 4)
    payload = json.loads(base64.urlsafe_b64decode(body + pad))
    payload["exp"] = int(time.time()) - 1
    new_body = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    expired_token = f"{new_body}.{sign(new_body.encode(), fast.token_secret)}"
    with pytest.raises(AuthError) as expired:
        svc.authenticate(expired_token)
    assert expired.value.code is ErrorCode.ACCESS_TOKEN_EXPIRED
    print("\n[input] access past exp -> [decision] access_token_expired")

    svc.logout(r.refresh_token, r.access_token)
    # 时间未到但被注销 -> 明确 revoked
    fresh = svc.login("viewer", "viewer-pw", "10.0.0.3")
    svc.logout(fresh.refresh_token, fresh.access_token)
    with pytest.raises(AuthError) as revoked:
        svc.authenticate(fresh.access_token)
    assert revoked.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    print("\n[input] valid-time access after logout "
          "-> [decision] access_token_revoked")


def test_logout_invalidates_all_credentials(svc: AuthService):
    r = svc.login("editor", "editor-pw", "10.0.0.9")
    svc.logout(r.refresh_token, r.access_token)
    with pytest.raises(AuthError) as e:
        svc.authenticate(r.access_token)
    assert e.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    with pytest.raises(AuthError) as e2:
        svc.refresh(r.refresh_token)
    assert e2.value.code is ErrorCode.REFRESH_TOKEN_REVOKED
    print("\n[input] logout -> [decision] access & refresh both revoked")


def test_tokens_never_contain_password(svc: AuthService):
    r = svc.login("viewer", "viewer-pw", "10.0.0.1")
    assert "viewer-pw" not in r.access_token
    assert "viewer-pw" not in r.refresh_token
    # 库存只存刷新令牌摘要，明文无法从存储还原
    from app.security import digest_token
    rec = svc.store.get_refresh(digest_token(r.refresh_token))
    assert rec is not None
    assert rec.token_hash != r.refresh_token
    print("\n[input] issued tokens/store -> [decision] no password material, "
          "refresh stored as hash only")
