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


def test_regrant_expired_and_revoked_at_cap_rejected_http(client):
    """HTTP：上限已满时，对已到期/已撤销账号重新授权同样 409，且不产生新有效授权。"""
    c, service = client
    owner_h = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    service.store.add_user(User(
        id="u_a3", username="alice",
        password_hash=hash_password("x"), role=Role.GUEST))
    service.store.add_user(User(
        id="u_b3", username="bob",
        password_hash=hash_password("x"), role=Role.GUEST))

    # friend 先拿一条 60s 授权，再把到期时间拨到过去模拟自然到期（不占名额）
    r = c.put("/resources/res-1/grants", headers=owner_h, json={
        "username": "friend", "actions": ["read"], "expires_in": 60})
    assert r.status_code == 200
    service.store.get_grant("res-1", "u_friend").expires_at = time.time() - 1

    # alice / bob 占满 cap=2
    for name in ("alice", "bob"):
        r = c.put("/resources/res-1/grants", headers=owner_h, json={
            "username": name, "actions": ["read"], "expires_in": 600})
        assert r.status_code == 200

    # 对已到期的 friend 重新授权 -> 409，错误体带 limit/active
    r = c.put("/resources/res-1/grants", headers=owner_h, json={
        "username": "friend", "actions": ["read"], "expires_in": 600})
    assert r.status_code == 409
    body = r.json()
    assert body["error"]["code"] == "grant_limit_exceeded"
    assert body["error"]["extra"] == {"limit": 2, "active": 2}
    # 被拒绝后有效授权仍是 alice/bob，friend 的旧记录仍处于到期状态
    active = {g["username"] for g in
              c.get("/resources/res-1/grants", headers=owner_h).json()["grants"]}
    assert active == {"alice", "bob"}

    # 撤销 alice 释放名额后：alice（已撤销）重新授权可以成功（名额由她空出）
    assert c.post("/resources/res-1/grants/revoke", headers=owner_h,
                   json={"username": "alice"}).status_code == 200
    r = c.put("/resources/res-1/grants", headers=owner_h, json={
        "username": "alice", "actions": ["update"], "expires_in": 600})
    assert r.status_code == 200 and r.json()["actions"] == ["update"]
    # 再次占满：已撤销语义不变——friend（仍到期）重新授权依旧 409
    r = c.put("/resources/res-1/grants", headers=owner_h, json={
        "username": "friend", "actions": ["read"], "expires_in": 600})
    assert r.status_code == 409
    active = {g["username"] for g in
              c.get("/resources/res-1/grants", headers=owner_h).json()["grants"]}
    assert active == {"alice", "bob"}
    print("\n[input] http regrant expired friend at cap=2 -> 409; "
          "revoked alice reuses her freed slot; friend still 409")


def test_concurrent_revoke_and_grants_hold_cap_http(client):
    """HTTP 并发：撤销 friend 释放 1 个名额，随后 3 路授权同时抢。

    释放 1 个名额时 3 路并发（friend 重新授权 + 2 个新账号），恰好 1 路成功、
    其余 409；最终有效授权恰好为 cap=2；未参与竞争的既有授权不受任何影响。
    用裸 threading.Thread + join（与并发读测试同模式）：join 返回前每个
    HTTP 请求都已执行完毕，不会有残留线程跨越 fixture 边界污染后续用例。
    """
    import threading

    c, service = client
    owner_h = {"Authorization": f"Bearer {_token(c, 'owner', 'owner-pw')}"}
    service.store.add_user(User(
        id="u_m1", username="m1",
        password_hash=hash_password("x"), role=Role.GUEST))
    service.store.add_user(User(
        id="u_m2", username="m2",
        password_hash=hash_password("x"), role=Role.GUEST))
    service.store.add_user(User(
        id="u_m3", username="m3",
        password_hash=hash_password("x"), role=Role.GUEST))

    # 占满 cap=2：friend + m1
    r = c.put("/resources/res-1/grants", headers=owner_h, json={
        "username": "friend", "actions": ["read"], "expires_in": 600})
    assert r.status_code == 200
    r = c.put("/resources/res-1/grants", headers=owner_h, json={
        "username": "m1", "actions": ["read"], "expires_in": 600})
    assert r.status_code == 200

    gate = threading.Event()
    statuses: list[int] = []
    slock = threading.Lock()
    candidates = ["friend", "m2", "m3"]

    def grantee_loop(name: str) -> None:
        assert gate.wait(5.0)
        r = c.put("/resources/res-1/grants", headers=owner_h, json={
            "username": name, "actions": ["read"], "expires_in": 600})
        assert r.status_code in (200, 409), r.text
        with slock:
            statuses.append(r.status_code)

    threads = [threading.Thread(target=grantee_loop, args=(n,))
               for n in candidates]
    for t in threads: t.start()
    # 先撤销 friend 释放唯一空名额，再开闸让 3 路同时抢
    r = c.post("/resources/res-1/grants/revoke",
                headers=owner_h, json={"username": "friend"})
    assert r.status_code == 200
    gate.set()
    for t in threads: t.join()

    # 1 个空名额：恰好 1 路 200，2 路 409；最终有效授权恰好为 cap=2
    assert statuses.count(200) == 1
    assert statuses.count(409) == 2
    active = service.store.active_grants_for("res-1", time.time())
    assert len(active) == 2
    grantee_ids = {g.grantee_id for g in active}
    assert "u_m1" in grantee_ids  # 未参与竞争的既有授权不受影响
    print(f"\n[input] revoke friend then 3 concurrent grants for 1 slot "
          f"-> [decision] statuses={sorted(statuses)}, cap held at 2")


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
