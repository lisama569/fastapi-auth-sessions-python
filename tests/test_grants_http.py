"""协作授权 HTTP 端到端：改/删入口、授权端点、越权与不存在同形、上限、到期与撤销。"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import main
from app.config import Settings
from app.models import Resource, Role, User
from app.security import hash_password
from app.services import AuthService
from app.store import Store


@pytest.fixture
def client():
    store = Store()
    settings = Settings(login_max_failures=99, grant_max_active_per_resource=2)
    service = AuthService(store, settings)
    store.add_user(User(
        id="u_owner", username="owner",
        password_hash=hash_password("owner-pw"), role=Role.VIEWER))
    store.add_user(User(
        id="u_friend", username="friend",
        password_hash=hash_password("friend-pw"), role=Role.GUEST))
    store.add_resource(Resource(id="res-1", owner_id="u_owner", kind="doc"))
    main.app.state.service = service
    main.app.state.store = store
    with TestClient(main.app) as c:
        yield c, service


def _token(c, username, password):
    r = c.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_granted_guest_can_read_then_expiry_blocks_http(client):
    c, service = client
    owner = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    friend = {"Authorization": f"Bearer {_token(c, 'friend', 'friend-pw')}"}

    # 授权前 friend（guest 角色）读不到：与不存在同形 404
    assert c.get("/resources/res-1", headers=friend).status_code == 404

    # 30 天授权
    r = c.put("/resources/res-1/grants", headers=owner, json={
        "username": "friend", "actions": ["read"],
        "expires_in": 30 * 24 * 3600})
    assert r.status_code == 200, r.text
    assert r.json()["actions"] == ["read"]

    # 授权后立即可读（无需 friend 重新登录）
    assert c.get("/resources/res-1", headers=friend).status_code == 200

    # 篡改服务端时钟：把到期时间挪到过去，下一次请求立即 404（自动失效）
    grant = service.store.get_grant("res-1", "u_friend")
    grant.expires_at = time.time() - 1
    gone = c.get("/resources/res-1", headers=friend)
    missing = c.get("/resources/does-not-exist", headers=friend)
    assert gone.status_code == missing.status_code == 404
    assert gone.json() == missing.json()
    print("\n[input] http grant read -> expire -> [decision] "
          "200 then identical 404 body to missing resource")


def test_revoke_immediately_kills_existing_token_http(client):
    c, _ = client
    owner = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    friend = {"Authorization": f"Bearer {_token(c, 'friend', 'friend-pw')}"}
    c.put("/resources/res-1/grants", headers=owner, json={
        "username": "friend", "actions": ["read"], "expires_in": 60})
    assert c.get("/resources/res-1", headers=friend).status_code == 200

    r = c.post("/resources/res-1/grants/revoke", headers=owner,
                json={"username": "friend"})
    assert r.status_code == 200
    # 撤销幂等：再来一次仍成功
    assert c.post("/resources/res-1/grants/revoke", headers=owner,
                  json={"username": "friend"}).status_code == 200
    # friend 手里同一个访问令牌立刻失效
    r = c.get("/resources/res-1", headers=friend)
    assert r.status_code == 404
    # 授权列表中不再出现
    grants = c.get("/resources/res-1/grants", headers=owner).json()["grants"]
    assert grants == []


def test_update_and_delete_share_same_policy_and_404_shape(client):
    c, _ = client
    owner = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    friend = {"Authorization": f"Bearer {_token(c, 'friend', 'friend-pw')}"}

    # friend 未授权前：改/删 与资源不存在完全同形
    denied = c.patch("/resources/res-1", headers=friend, json={"kind": "x"})
    missing = c.patch("/resources/nope", headers=friend, json={"kind": "x"})
    assert denied.status_code == missing.status_code == 404
    assert denied.json() == missing.json()
    denied_d = c.request("DELETE", "/resources/res-1", headers=friend)
    missing_d = c.request("DELETE", "/resources/nope", headers=friend)
    assert denied_d.status_code == missing_d.status_code == 404

    # 只授 update：PATCH 放行，DELETE 仍 404
    c.put("/resources/res-1/grants", headers=owner, json={
        "username": "friend", "actions": ["update"], "expires_in": 60})
    r = c.patch("/resources/res-1", headers=friend, json={"kind": "sheet"})
    assert r.status_code == 200 and r.json()["kind"] == "sheet"
    assert c.request("DELETE", "/resources/res-1",
                    headers=friend).status_code == 404

    # 属主自己删除成功并级联清掉授权
    r = c.request("DELETE", "/resources/res-1", headers=owner)
    assert r.status_code == 204 and r.content == b""
    assert c.get("/resources/res-1", headers=owner).status_code == 404


def test_non_owner_cannot_see_or_change_grants(client):
    c, _ = client
    friend = {"Authorization": f"Bearer {_token(c, 'friend', 'friend-pw')}"}
    for method, path, body in [
        ("GET", "/resources/res-1/grants", None),
        ("PUT", "/resources/res-1/grants",
         {"username": "friend", "actions": ["read"], "expires_in": 10}),
        ("POST", "/resources/res-1/grants/revoke",
         {"username": "friend"}),
    ]:
        r = c.request(method, path, headers=friend, json=body)
        missing = c.request(method, path.replace("res-1", "nope"),
                           headers=friend, json=body)
        assert r.status_code == missing.status_code == 404
        assert r.json() == missing.json()
    print("\n[input] friend probes grants on existing vs missing resource "
          "-> [decision] byte-identical 404s")


def test_grant_limit_enforced_http(client):
    c, service = client
    owner = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    service.store.add_user(User(
        id="u_a2", username="alice",
        password_hash=hash_password("x"), role=Role.GUEST))
    service.store.add_user(User(
        id="u_b2", username="bob",
        password_hash=hash_password("x"), role=Role.GUEST))
    service.store.add_user(User(
        id="u_c2", username="carol",
        password_hash=hash_password("x"), role=Role.GUEST))
    for name in ("alice", "bob"):
        r = c.put("/resources/res-1/grants", headers=owner, json={
            "username": name, "actions": ["read"], "expires_in": 60})
        assert r.status_code == 200
    r = c.put("/resources/res-1/grants", headers=owner, json={
        "username": "carol", "actions": ["read"], "expires_in": 60})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "grant_limit_exceeded"
    # 对已授权人重复授权不占新名额，幂等成功
    r = c.put("/resources/res-1/grants", headers=owner, json={
        "username": "alice", "actions": ["delete"], "expires_in": 60})
    assert r.status_code == 200
    body = c.get("/resources/res-1/grants",
                  headers=owner).json()["grants"]
    alice = next(g for g in body if g["username"] == "alice")
    assert alice["actions"] == ["delete", "read"]


def test_invalid_grant_payloads_are_rejected(client):
    c, _ = client
    owner = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    # 非法动作名 -> 422 invalid_grant（服务层稳定错误码）
    r = c.put("/resources/res-1/grants", headers=owner, json={
        "username": "friend", "actions": ["explode"], "expires_in": 10})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_grant"
    # pydantic 字段约束 -> 422 validation_error
    r = c.put("/resources/res-1/grants", headers=owner, json={
        "username": "friend", "actions": ["read"], "expires_in": 0})
    assert r.status_code == 422
    r = c.put("/resources/res-1/grants", headers=owner, json={
        "username": "friend", "actions": [], "expires_in": 10})
    assert r.status_code == 422


def test_regrant_after_expiry_or_revoke_hits_same_cap_http(client):
    """上限=2 的 HTTP 全链路：已到期/已撤销账号重新授权与新账号走同一上限口径。"""
    c, service = client
    owner = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    for name in ("alice", "bob", "carol"):
        uid = f"u_{name[0]}2"
        service.store.add_user(User(
            id=uid, username=name,
            password_hash=hash_password("x"), role=Role.GUEST))

    def put(name, ttl=60):
        return c.put("/resources/res-1/grants", headers=owner, json={
            "username": name, "actions": ["read"], "expires_in": ttl})

    # alice 短 TTL 授权并篡改时钟使其到期；随后由 bob/friend 占满 2 个名额
    assert put("alice", ttl=60).status_code == 200
    service.store.get_grant("res-1", "u_a2").expires_at = time.time() - 1
    assert put("bob").status_code == 200
    assert put("friend").status_code == 200
    assert service.store.active_grant_count("res-1", time.time()) == 2

    # 名额满：给全新账号 carol -> 409
    r = put("carol")
    assert r.status_code == 409
    assert r.json()["error"]["extra"] == {"limit": 2, "active": 2}
    # 名额满：给已到期的 alice 重新授权同样 -> 409（漏洞回归点）
    r = put("alice")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "grant_limit_exceeded"
    # 被拒绝不复活旧授权、不新增条目
    assert service.store.active_grant_count("res-1", time.time()) == 2

    # bob 撤销释放名额后，alice 可以重新授权（恢复生效，覆盖新动作集）
    assert c.post("/resources/res-1/grants/revoke", headers=owner,
                  json={"username": "bob"}).status_code == 200
    assert put("alice").status_code == 200
    grants = c.get("/resources/res-1/grants",
                    headers=owner).json()["grants"]
    assert sorted(g["username"] for g in grants) == ["alice", "friend"]
    print("\n[input] http cap=2: expired alice + full bob/friend -> regrant 409; "
          "revoke frees slot -> regrant 200")


def test_concurrent_grant_revoke_never_exceeds_cap_http(client):
    """HTTP 层并发：新增/重新授权与撤销同时打，有效授权数绝不超过上限。"""
    import concurrent.futures

    c, service = client
    cap = 2
    owner_h = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    names = [f"racer{i}" for i in range(8)]
    for i, name in enumerate(names):
        service.store.add_user(User(
            id=f"u_r{i}", username=name,
            password_hash=hash_password("x"), role=Role.GUEST))

    def put(name):
        return c.put("/resources/res-1/grants", headers=owner_h, json={
            "username": name, "actions": ["read"],
            "expires_in": 600}).status_code

    def revoke(name):
        return c.post("/resources/res-1/grants/revoke", headers=owner_h,
                      json={"username": name}).status_code

    # 8 路全新账号并发抢 2 个名额：恰好 2 个 200，其余 409，绝不超发
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(put, names))
    assert sorted(statuses) == [200, 200] + [409] * 6
    assert service.store.active_grant_count("res-1", time.time()) == cap

    # 多轮混合：撤销当前有效者 + 对已失效/全新者重新授权并发，
    # 每轮结束后有效数都必须 <= cap
    for round_no in range(10):
        active_names = [
            service.store.get_user(g.grantee_id).username
            for g in service.store.active_grants_for("res-1", time.time())
        ]
        targets = active_names + names
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futs = []
            for n in active_names:
                futs.append(pool.submit(revoke, n))
            for n in names:
                futs.append(pool.submit(put, n))
            round_status = [f.result() for f in futs]
        assert set(round_status) <= {200, 409}
        count = service.store.active_grant_count("res-1", time.time())
        assert count <= cap, (round_no, count)

    # 全部撤销后名额归零，可重新用满，且第 cap+1 个仍被拒
    for name in names:
        revoke(name)
    assert service.store.active_grant_count("res-1", time.time()) == 0
    assert put("racer0") == 200
    assert put("racer1") == 200
    assert put("racer2") == 409
    print("\n[input] http 8-way concurrent grants + 10 mixed grant/revoke rounds "
          "-> [decision] active count never exceeds cap=2")


def test_revoke_racing_concurrent_reads_is_deterministic(client):
    """撤销成功返回之后的所有读请求必须全部 404，不存在放行窗口。"""
    import concurrent.futures

    c, _ = client
    owner_h = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    friend_tok = _token(c, 'friend', 'friend-pw')
    friend_h = {"Authorization": f"Bearer {friend_tok}"}
    c.put("/resources/res-1/grants", headers=owner_h, json={
        "username": "friend", "actions": ["read"], "expires_in": 600})
    assert c.get("/resources/res-1", headers=friend_h).status_code == 200

    # 撤销完成（200）之后，32 路并发读必须全部 404
    assert c.post("/resources/res-1/grants/revoke",
                    headers=owner_h, json={"username": "friend"}
                    ).status_code == 200

    def read_once(_):
        return c.get("/resources/res-1", headers=friend_h).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        statuses = list(pool.map(read_once, range(64)))
    assert set(statuses) == {404}, statuses
    print("\n[input] revoke then 64 concurrent reads "
          "-> [decision] every read 404, no post-revoke allow window")
