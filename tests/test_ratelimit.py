"""登录失败限流：按账号与来源维度计数，阈值后退避并指数升级；
限流响应可与凭证错误区分，成功登录清零。"""

from __future__ import annotations

import time

import pytest

from app.errors import AuthError, ErrorCode
from app.services import AuthService


def test_backoff_after_threshold_with_distinct_code(svc: AuthService):
    # settings: max_failures=5, base_lockout=10
    for i in range(5):
        with pytest.raises(AuthError) as bad:
            svc.login("viewer", "wrong", "10.0.0.1")
        assert bad.value.code is ErrorCode.INVALID_CREDENTIALS
    # 第 6 次（即使密码正确）也被限流
    with pytest.raises(AuthError) as limited:
        svc.login("viewer", "viewer-pw", "10.0.0.1")
    assert limited.value.code is ErrorCode.RATE_LIMITED
    assert limited.value.extra["retry_after"] > 0
    print(f"\n[input] 5 failures then correct password "
          f"-> [decision] rate_limited, "
          f"retry_after={limited.value.extra['retry_after']}s")


def test_rate_limit_is_per_source_and_account(svc: AuthService):
    for _ in range(5):
        with pytest.raises(AuthError):
            svc.login("viewer", "wrong", "10.0.0.1")
    # 同账号不同来源不受影响
    ok = svc.login("viewer", "viewer-pw", "10.0.0.2")
    assert ok.access_token
    # 不同账号同来源也不受影响
    ok2 = svc.login("editor", "editor-pw", "10.0.0.1")
    assert ok2.access_token
    print("\n[input] lockout (viewer@ip1) "
          "-> [decision] viewer@ip2 and editor@ip1 still allowed")


def test_exponential_backoff_escalation(svc: AuthService):
    t = 0.0
    for _ in range(5):
        svc.limiter.record_failure("viewer", "10.0.0.1", now=t)
    assert svc.limiter.retry_after("viewer", "10.0.0.1", now=t + 1) == 10

    t = 12.0  # 首轮锁定过期
    for _ in range(5):
        svc.limiter.record_failure("viewer", "10.0.0.1", now=t)
    assert svc.limiter.retry_after("viewer", "10.0.0.1", now=t + 1) == 20
    print("\n[input] repeated threshold crossings "
          "-> [decision] backoff 10s then 20s (exponential)")


def test_success_resets_failures(svc: AuthService):
    for _ in range(3):
        with pytest.raises(AuthError):
            svc.login("viewer", "wrong", "10.0.0.1")
    svc.limiter.record_success("viewer", "10.0.0.1")
    # 重新计数，再失败 4 次也不会触发（阈值 5）
    for _ in range(4):
        with pytest.raises(AuthError):
            svc.login("viewer", "wrong", "10.0.0.1")
    svc.limiter.check("viewer", "10.0.0.1")  # 不抛异常
    print("\n[input] failures then success "
          "-> [decision] counters reset, no lockout")


def test_http_rate_limit_response_has_retry_after():
    import main
    from app.config import Settings
    from app.services import AuthService, seed_demo_data
    from app.store import Store
    from fastapi.testclient import TestClient

    store = Store(); seed_demo_data(store)
    service = AuthService(store, Settings(
        login_max_failures=3, login_base_lockout=15, login_max_lockout=300,
    ))
    main.app.state.service = service
    with TestClient(main.app) as c:
        for _ in range(3):
            r = c.post("/auth/login",
                       json={"username": "viewer", "password": "bad"})
            assert r.status_code == 401
            assert r.json()["error"]["code"] == "invalid_credentials"
        r = c.post("/auth/login",
                   json={"username": "viewer", "password": "viewer-pw"})
        assert r.status_code == 429
        body = r.json()["error"]
        assert body["code"] == "rate_limited"
        assert int(r.headers["retry-after"]) > 0
        # 对外安全的 extra 白名单字段随响应体透出
        assert body["extra"]["retry_after"] == int(r.headers["retry-after"])
        assert body["extra"]["backoff_count"] >= 1
        print(f"\n[input] 3 bad logins over HTTP "
              f"-> [decision] 429 rate_limited, "
              f"Retry-After={r.headers['retry-after']}")
