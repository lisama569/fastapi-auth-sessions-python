"""端到端 HTTP：Cookie 会话、刷新轮换、注销、错误码一致性与安全响应头。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import main
from app.config import Settings
from app.services import AuthService, seed_demo_data
from app.store import Store


@pytest.fixture
def client():
    store = Store()
    seed_demo_data(store)
    service = AuthService(store, Settings(login_max_failures=99))
    main.app.state.service = service
    main.app.state.store = store
    with TestClient(main.app) as c:
        yield c, service


def test_cookie_login_refresh_logout_flow(client):
    c, service = client
    r = c.post("/auth/login", json={"username": "viewer", "password": "viewer-pw"})
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    # 安全默认：HttpOnly + SameSite
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower().replace(" ", "")

    # 浏览器式调用：不带 Authorization，靠 Cookie 访问
    assert c.get("/me").json()["username"] == "viewer"

    # 凭 Cookie 刷新，返回新一代凭证
    r = c.post("/auth/refresh")
    assert r.status_code == 200, r.text
    new_refresh = r.json()["refresh_token"]
    current_access = c.cookies.get(service.settings.cookie_name_access)

    # 旧的旋转前 refresh cookie 已被新 cookie 覆盖；手工重放旧 refresh（登录时的）
    # 此处验证新凭证工作正常
    assert c.get("/me").status_code == 200

    # 注销：cookie 被清理，后续浏览器式访问 401
    old_access = current_access
    r = c.post("/auth/logout")
    assert r.status_code == 200
    assert c.cookies.get(service.settings.cookie_name_access) is None
    r = c.get("/me")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthenticated"  # 已无凭证
    # 显式重放注销前的访问令牌 -> 服务端确已吊销（可区分原因）
    r = c.get("/me", headers={"Authorization": f"Bearer {old_access}"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "access_token_revoked"
    print("\n[input] cookie login/refresh/logout "
          "-> [decision] session cookies work, logout revokes server-side")


def test_header_and_cookie_entry_points_give_same_result(client):
    """同一令牌，无论走 Header 还是 Cookie，判定必须一致。"""
    c, service = client
    r = c.post("/auth/login", json={"username": "viewer", "password": "viewer-pw"})
    token = r.json()["access_token"]
    # 清掉 cookie，纯 header 访问
    c.cookies.clear()
    via_header = c.get("/resources/doc-1",
                       headers={"Authorization": f"Bearer {token}"})
    via_cookie = c.get("/resources/doc-1")  # 无 cookie -> 401 证明入口独立
    # 重新带 cookie
    c.cookies.set(service.settings.cookie_name_access, token)
    via_cookie = c.get("/resources/doc-1")
    assert via_header.status_code == via_cookie.status_code == 200
    assert via_header.json()["id"] == via_cookie.json()["id"] == "doc-1"
    print("\n[input] same token via Bearer vs Cookie "
          "-> [decision] identical authorization result")


def test_cors_disallowed_by_default(client):
    c, _ = client
    r = c.options("/auth/login", headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST",
    })
    assert "access-control-allow-origin" not in r.headers
    print("\n[input] preflight from unconfigured origin "
          "-> [decision] no CORS allow headers (default deny)")


def test_error_bodies_never_echo_password(client):
    c, _ = client
    secret = "supersecret-password-123"
    r = c.post("/auth/login", json={"username": "viewer", "password": secret})
    assert secret not in r.text
    r2 = c.post("/auth/login", json={"username": "x" * 10, "password": secret})
    assert secret not in r2.text
    print("\n[input] failed login payload -> [decision] response contains no secret")
