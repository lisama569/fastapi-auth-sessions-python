"""Login, token lifecycle and distinguishable rejection reasons."""

from __future__ import annotations

import time

import jwt

from app.config import Settings
from app.errors import AuthErrorCode
from app.models import Session
from app.tokens import issue_token_pair


def test_login_success_sets_access_and_cookie(client, settings, helper, audit_records):
    at, rt, resp = helper.login(client, "alice", "alice-pass")
    assert at and rt
    # Refresh cookie must be HttpOnly and use the configured SameSite.
    set_cookie = resp.headers["set-cookie"]
    assert "httponly" in set_cookie.lower()
    assert f"samesite={settings.cookie_samesite}" in set_cookie.lower()
    # Response must never contain the refresh token in the JSON body.
    assert "refresh_token" not in resp.json()
    # Audit log shows the decision basis without leaking the password.
    texts = [r.getMessage() for r in audit_records.records]
    assert any("login_succeeded" in t and "password verified" in t for t in texts)
    assert all("alice-pass" not in t for t in texts)


def test_bad_password_is_rejected_with_distinct_code(client, helper, audit_records):
    r = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.INVALID_CREDENTIALS.value
    texts = [rec.getMessage() for rec in audit_records.records]
    assert any("login_failed" in t and "bad password" in t for t in texts)
    assert all("wrong" not in t for t in texts)  # password never logged


def test_unknown_user_shares_same_rejection(client):
    r = client.post("/auth/login", json={"username": "ghost", "password": "whatever1"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.INVALID_CREDENTIALS.value


def test_missing_and_malformed_access_token_codes(client, helper):
    helper.login(client, "alice", "alice-pass")
    r = client.get("/auth/me")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.MISSING_TOKEN.value

    r = client.get("/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.MALFORMED_TOKEN.value

    r = client.get("/auth/me", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.MALFORMED_TOKEN.value


def test_bad_signature_access_token_rejected(client, helper):
    at, _, _ = helper.login(client, "alice", "alice-pass")
    # Re-sign the same claims with a different secret.
    decoded = jwt.decode(at, options={"verify_signature": False})
    forged = jwt.encode(decoded, "attacker-secret", algorithm="HS256")
    r = client.get("/auth/me", headers=helper.auth_header(forged))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.BAD_SIGNATURE.value


def test_expired_access_token_has_distinct_code(client, store, helper):
    settings = Settings(jwt_secret="unit-test-secret-key-0123456789abcdef",
                        access_token_ttl_seconds=-10)
    user = store.get_user_by_username("alice")
    session = Session(id="s-exp", user_id=user.id, created_at=time.time(),
                      last_rotated_at=time.time())
    store.add_session(session)
    token, _ = __import__("app.tokens", fromlist=["issue_access_token"]).issue_access_token(
        user, session, store.get_security_version(user.id), settings
    )
    r = client.get("/auth/me", headers=helper.auth_header(token))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.TOKEN_EXPIRED.value


def test_refresh_rotates_and_old_token_is_replayed(client, store, helper, audit_records):
    _, rt, _ = helper.login(client, "alice", "alice-pass")

    # Rotate presenting the raw token in the body; do not use the cookie jar
    # so we can replay the *old* value afterwards.
    r1 = client.post("/auth/refresh", json={"refresh_token": rt})
    assert r1.status_code == 200, r1.text
    # NOTE: refresh token is cookie-only on this call; take it from set-cookie.
    rotated_rt = r1.cookies.get(client.app.state.settings.refresh_cookie_name)
    assert rotated_rt and rotated_rt != rt

    # Reusing the old token is detected as replay.
    r2 = client.post("/auth/refresh", json={"refresh_token": rt})
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == AuthErrorCode.TOKEN_REPLAYED.value

    # Breach containment: the rotated (previously valid) token is dead too.
    r3 = client.post("/auth/refresh", json={"refresh_token": rotated_rt})
    assert r3.status_code == 401
    assert r3.json()["error"]["code"] == AuthErrorCode.TOKEN_REPLAYED.value

    texts = [rec.getMessage() for rec in audit_records.records]
    assert any("refresh_replay_detected" in t and "family revoked" in t for t in texts)


def test_refresh_expired_token_code(client, store, settings, helper):
    settings.refresh_token_ttl_seconds = 3600
    user = store.get_user_by_username("alice")
    session = Session(id="s-rexp", user_id=user.id, created_at=time.time() - 7200,
                      last_rotated_at=time.time() - 7200)
    store.add_session(session)
    pair = issue_token_pair(store, user, session, settings, now=time.time() - 7200)
    r = client.post("/auth/refresh", json={"refresh_token": pair.refresh_token})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.TOKEN_EXPIRED.value


def test_logout_revokes_session_and_access_token(client, helper):
    helper.login(client, "alice", "alice-pass")
    # Rotate once via cookies (TestClient stores the new cookie).
    rr = client.post("/auth/refresh")
    assert rr.status_code == 200
    new_at = rr.json()["access_token"]
    rotated_after = rr.cookies.get(client.app.state.settings.refresh_cookie_name)

    r = client.post("/auth/logout", headers=helper.auth_header(new_at))
    assert r.status_code == 204

    # The rotated access token no longer works: session revoked.
    r = client.get("/auth/me", headers=helper.auth_header(new_at))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.SESSION_REVOKED.value

    # The refresh family is dead as well (present the token explicitly:
    # the 204 logout response intentionally cleared the cookie).
    r = client.post("/auth/refresh", json={"refresh_token": rotated_after})
    assert r.status_code == 401
    assert r.json()["error"]["code"] in {
        AuthErrorCode.SESSION_REVOKED.value,
        AuthErrorCode.TOKEN_REPLAYED.value,
    }


def test_unknown_refresh_token_is_not_found(client):
    r = client.post("/auth/refresh", json={"refresh_token": "x" * 40})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.SESSION_NOT_FOUND.value


def test_sensitive_values_never_in_responses(client, helper):
    at, _, _ = helper.login(client, "alice", "alice-pass")
    me = client.get("/auth/me", headers=helper.auth_header(at)).json()
    assert "password" not in me and "password_hash" not in me
