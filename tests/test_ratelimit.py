"""Login throttling, exponential backoff and source isolation."""

from __future__ import annotations

from app.errors import AuthErrorCode
from app.ratelimit import LoginRateLimiter


def test_threshold_triggers_429_with_retry_after(client, helper, audit_records):
    # settings: max_attempts = 3
    for _ in range(2):
        r = client.post("/auth/login", json={"username": "alice", "password": "bad"})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == AuthErrorCode.INVALID_CREDENTIALS.value

    third = client.post("/auth/login", json={"username": "alice", "password": "bad"})
    assert third.status_code == 429
    assert third.json()["error"]["code"] == AuthErrorCode.RATE_LIMITED.value
    assert int(third.headers["retry-after"]) >= 1

    # Even the CORRECT password is refused while the lock is active.
    locked = client.post("/auth/login", json={"username": "alice", "password": "alice-pass"})
    assert locked.status_code == 429

    texts = [r.getMessage() for r in audit_records.records]
    assert any("login_throttled" in t for t in texts)
    print("\n[input+basis]", [t for t in texts if "throttled" in t])


def test_backoff_grows_exponentially():
    rl = LoginRateLimiter(max_attempts=3, backoff_base=1, backoff_multiplier=2,
                          backoff_max=100)
    t = 5000.0
    waits = []
    for _ in range(5):
        waits.append(rl.record_failure("alice", "10.0.0.1", t))
        t += 0.01  # attempts cluster together, lock keeps extending
    # waits: 0,0,1,2,4
    assert waits == [0, 0, 1.0, 2.0, 4.0]
    assert rl.check("alice", "10.0.0.1", t) > 0


def test_backoff_is_capped():
    rl = LoginRateLimiter(max_attempts=2, backoff_base=1, backoff_multiplier=10,
                          backoff_max=50)
    t = 0.0
    rl.record_failure("a", "ip", t)
    assert rl.record_failure("a", "ip", t) == 1.0
    assert rl.record_failure("a", "ip", t + 1) == 10.0
    assert rl.record_failure("a", "ip", t + 11) == 50.0  # capped
    assert rl.record_failure("a", "ip", t + 61) == 50.0


def test_limits_are_per_account_and_per_source(client):
    # Burn alice's budget from the default test client source.
    for _ in range(3):
        client.post("/auth/login", json={"username": "alice", "password": "bad"})
    assert client.post(
        "/auth/login", json={"username": "alice", "password": "bad"}
    ).status_code == 429

    # Different account unaffected.
    assert client.post(
        "/auth/login", json={"username": "bob", "password": "bad"}
    ).status_code == 401

    # Different source (forwarded IP) unaffected.
    r = client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice-pass"},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert r.status_code == 200


def test_window_resets_after_quiet_period():
    rl = LoginRateLimiter(max_attempts=3, window_seconds=100)
    t = 1000.0
    for _ in range(3):
        rl.record_failure("alice", "ip", t)
    assert rl.check("alice", "ip", t) > 0
    assert rl.check("alice", "ip", t + 101) == 0


def test_cookie_settings_reflect_configuration(client, settings, helper):
    _, _, resp = helper.login(client, "alice", "alice-pass")
    set_cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert f"samesite={settings.cookie_samesite}" in set_cookie
    # Test fixture sets cookie_secure=False (plain HTTP TestClient).
    assert "secure" not in set_cookie


def test_secure_defaults_on_production_settings():
    from app.config import Settings as S

    prod = S()  # defaults
    assert prod.cookie_secure is True
    assert prod.cookie_samesite == "strict"
    assert prod.cors_allow_origins == []


def test_secure_cookie_emitted_when_configured(settings):
    from fastapi.testclient import TestClient

    from app.app import create_app

    settings.cookie_secure = True
    settings.cookie_samesite = "strict"
    client = TestClient(create_app(settings=settings, seed=True))
    r = client.post(
        "/auth/login", json={"username": "alice", "password": "alice-pass"}
    )
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "; secure" in cookie or cookie.endswith("secure")
