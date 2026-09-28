"""资源协作授权：临时授权、到期失效、撤销即时生效、并发确定性、
管理权管控、越权与不存在同形、单资源授权上限。

所有时间相关用例通过服务层 now= 参数注入虚拟时钟，保证确定性。
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import main
from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import Resource, Role, User
from app.security import hash_password
from app.services import AuthService, seed_demo_data
from app.store import Store

import time as _time
T0 = float(_time.time()) + 3600  # 虚拟时钟锚点：贴近真实时间且略在未来，
# 这样用 T0 签发的访问令牌（TTL 900s）在随后的真实时间 authenticate 中仍有效


def make_service(*, grant_max_per_resource: int = 50,
                 grant_max_ttl: int = 86400 * 30) -> tuple[AuthService, Store]:
    store = Store()
    seed_demo_data(store)
    settings = Settings(
        login_max_failures=99,
        grant_max_per_resource=grant_max_per_resource,
        grant_max_ttl=grant_max_ttl,
    )
    return AuthService(store, settings), store


def add_user(store: Store, uid: str, name: str, role: Role = Role.VIEWER) -> User:
    u = User(id=uid, username=name, password_hash=hash_password(f"{name}-pw"),
             role=role)
    store.add_user(u)
    return u


# ---------- 授权生效与幂等 ----------

def test_grant_allows_action_without_relogin():
    """授权在对方已有访问令牌的会话上立即生效，无需重新登录。"""
    svc, store = make_service()
    editor = store.get_user("u_editor")  # doc-1 属主是 viewer
    viewer_login = svc.login("viewer", "viewer-pw", "ip", now=T0)
    token = viewer_login.access_token

    # 授权前：viewer 删除 doc-2(editor 的资源) 被默认拒绝
    before = svc.check_resource(store.get_user("u_viewer"),
                                "resource:delete", "doc-2", now=T0)
    assert before.decision.allowed is False

    # editor 不是 doc-1 属主，不能给 doc-1 授权 -> 404（资源对其不可管理）
    with pytest.raises(AuthError) as ex:
        svc.grant_resource_access(editor, "doc-1", "u_viewer", "delete",
                                  T0 + 3600, now=T0)
    assert ex.value.code is ErrorCode.NOT_FOUND

    # doc-2 属主 editor 授权 viewer 删除 doc-2
    grant, created = svc.grant_resource_access(
        store.get_user("u_editor"), "doc-2", "u_viewer",
        "delete", T0 + 3600, now=T0,
    )
    assert created is True

    # 同一个旧令牌（授权前登录拿到的）现在即可执行被授权动作
    user_now, _, _ = svc.authenticate(token)
    view = svc.check_resource(user_now, "resource:delete", "doc-2", now=T0 + 10)
    assert view.decision.allowed is True
    assert "collaboration grant" in view.decision.reason
    print("\n[input] owner grants delete to existing session "
          "-> [decision] granted action usable without re-login")


def test_repeated_grant_is_idempotent_single_row():
    svc, store = make_service()
    owner = store.get_user("u_editor")
    g1, c1 = svc.grant_resource_access(owner, "doc-2", "u_viewer", "read",
                                       T0 + 100, now=T0)
    g2, c2 = svc.grant_resource_access(owner, "doc-2", "u_viewer", "read",
                                       T0 + 200, now=T0 + 10)
    assert c1 is True and c2 is False
    assert g1 is g2 and g2.expires_at == T0 + 200
    rows = store.list_grants_for("doc-2")
    assert len(rows) == 1
    print("\n[input] same grantee+action granted twice "
          "-> [decision] one row renewed, expires_at updated")


def test_grant_to_unknown_user_and_bad_time_rejected():
    svc, store = make_service()
    owner = store.get_user("u_editor")
    with pytest.raises(AuthError) as e1:
        svc.grant_resource_access(owner, "doc-2", "ghost", "read",
                                  T0 + 100, now=T0)
    assert e1.value.code is ErrorCode.INVALID_GRANT
    with pytest.raises(AuthError) as e2:
        svc.grant_resource_access(owner, "doc-2", "u_viewer", "read",
                                  T0 - 1, now=T0)
    assert e2.value.code is ErrorCode.INVALID_GRANT
    with pytest.raises(AuthError) as e3:
        svc.grant_resource_access(owner, "doc-2", "u_viewer", "read",
                                  T0 + 86400 * 30 + 1, now=T0)
    assert e3.value.code is ErrorCode.INVALID_GRANT  # 超过最长有效期
    with pytest.raises(AuthError) as e4:
        svc.grant_resource_access(owner, "doc-2", "editor", "read",
                                  T0 + 100, now=T0)
    assert e4.value.code is ErrorCode.INVALID_GRANT  # 不能给属主自己授权
    print("\n[input] unknown grantee / past expiry / over-max-ttl / self "
          "-> [decision] invalid_grant")


# ---------- 到期自动失效 ----------

def test_grant_expires_automatically_at_deadline():
    svc, store = make_service()
    owner = store.get_user("u_editor")
    viewer = store.get_user("u_viewer")
    svc.grant_resource_access(owner, "doc-2", "u_viewer", "delete",
                              T0 + 100, now=T0)

    allowed = svc.check_resource(viewer, "resource:delete", "doc-2", now=T0 + 99)
    assert allowed.decision.allowed is True
    expired = svc.check_resource(viewer, "resource:delete", "doc-2", now=T0 + 100)
    assert expired.decision.allowed is False  # 边界：expires_at 时刻即失效
    assert "default deny" in expired.decision.reason

    # 到期后该授权不计入上限，可重新授予
    print("\n[input] access before/after expires_at "
          "-> [decision] allowed until deadline, default-deny at/after")


def test_expired_grants_do_not_count_toward_limit():
    svc, store = make_service(grant_max_per_resource=1)
    owner = add_user(store, "u_owner1", "owner1")
    store.add_resource(Resource(id="d-x", owner_id="u_owner1"))
    svc.grant_resource_access(owner, "d-x", "u_viewer", "read",
                              T0 + 10, now=T0)
    # 未到期时上限已满
    with pytest.raises(AuthError) as e:
        svc.grant_resource_access(owner, "d-x", "u_editor", "read",
                                  T0 + 100, now=T0 + 5)
    assert e.value.code is ErrorCode.GRANT_LIMIT_REACHED
    # 到期后名额释放，新授权成功
    grant, created = svc.grant_resource_access(
        owner, "d-x", "u_editor", "read", T0 + 200, now=T0 + 11,
    )
    assert created is True
    print("\n[input] limit full then oldest expires "
          "-> [decision] slot released, new grant accepted")


# ---------- 撤销即时生效 ----------

def test_read_grant_on_non_doc_expires_and_default_gate_stays_closed():
    """非 doc kind：无角色规则可读，授权到期后自动回到默认拒绝。"""
    svc, store = make_service()
    owner = store.get_user("u_editor")
    viewer = store.get_user("u_viewer")
    store.add_resource(Resource(id="s1", owner_id="u_editor", kind="sheet"))

    # 无授权时默认拒绝（不会因为引入授权而放开默认关口）
    assert svc.check_resource(viewer, "resource:read", "s1",
                              now=T0).decision.allowed is False
    svc.grant_resource_access(owner, "s1", "u_viewer", "read",
                              T0 + 60, now=T0)
    assert svc.check_resource(viewer, "resource:read", "s1",
                              now=T0 + 59).decision.allowed is True
    assert svc.check_resource(viewer, "resource:read", "s1",
                              now=T0 + 60).decision.allowed is False
    # update/delete 从未被授予，始终拒绝
    assert svc.check_resource(viewer, "resource:update", "s1",
                              now=T0 + 10).decision.allowed is False
    assert svc.check_resource(viewer, "resource:delete", "s1",
                              now=T0 + 10).decision.allowed is False
    print("\n[input] non-doc sheet grant read ttl=60 "
          "-> [decision] deny/allow/deny; other actions stay denied")


def test_revoke_takes_effect_immediately_with_same_token():
    """撤销后，调用方手里已经拿到的访问凭证立刻不好使（针对该资源动作）。"""
    svc, store = make_service()
    owner = store.get_user("u_editor")
    login = svc.login("viewer", "viewer-pw", "ip", now=T0)
    token = login.access_token
    svc.grant_resource_access(owner, "doc-2", "u_viewer", "delete",
                              T0 + 3600, now=T0)

    user, _, _ = svc.authenticate(token)
    assert svc.check_resource(user, "resource:delete", "doc-2",
                              now=T0 + 1).decision.allowed

    svc.revoke_resource_access(owner, "doc-2", "u_viewer", "delete", now=T0 + 2)

    # 令牌本身仍然有效（会话没结束），但同一个令牌再访问立刻被拒
    user2, _, _ = svc.authenticate(token)
    view = svc.check_resource(user2, "resource:delete", "doc-2", now=T0 + 3)
    assert view.decision.allowed is False
    # 授权行标记为已撤销
    assert store.get_grant("doc-2", "u_viewer", "delete").revoked is True
    print("\n[input] grant revoked mid-session "
          "-> [decision] same token denied immediately (no relogin needed)")


def test_revoke_is_idempotent_and_regrant_works():
    svc, store = make_service()
    owner = store.get_user("u_editor")
    viewer = store.get_user("u_viewer")
    svc.grant_resource_access(owner, "doc-2", "u_viewer", "delete",
                              T0 + 3600, now=T0)
    svc.revoke_resource_access(owner, "doc-2", "u_viewer", "delete", now=T0 + 1)
    with pytest.raises(AuthError) as e:
        svc.revoke_resource_access(owner, "doc-2", "u_viewer", "delete",
                                   now=T0 + 2)
    assert e.value.code is ErrorCode.NOT_FOUND  # 已撤销/不存在口径一致
    # 撤销后可重新授权
    g, created = svc.grant_resource_access(owner, "doc-2", "u_viewer",
                                           "delete", T0 + 7200, now=T0 + 3)
    assert created is True
    assert svc.check_resource(viewer, "resource:delete", "doc-2",
                              now=T0 + 4).decision.allowed
    print("\n[input] double revoke then re-grant "
          "-> [decision] second revoke 404, re-grant works")


def test_grant_listing_only_visible_to_managers():
    svc, store = make_service()
    owner = store.get_user("u_editor")
    other = add_user(store, "u_other", "other", Role.VIEWER)
    svc.grant_resource_access(owner, "doc-2", "u_viewer", "read",
                              T0 + 3600, now=T0)
    rows = svc.list_resource_grants(owner, "doc-2", now=T0)
    assert len(rows) == 1 and rows[0]["active"] is True

    # 非属主非管理员：看不到（与资源不存在同形 404）
    with pytest.raises(AuthError) as e:
        svc.list_resource_grants(other, "doc-2", now=T0)
    assert e.value.code is ErrorCode.NOT_FOUND
    with pytest.raises(AuthError) as e2:
        svc.list_resource_grants(owner, "missing", now=T0)
    assert e2.value.code is ErrorCode.NOT_FOUND

    # admin 可以管理任意资源
    rows_admin = svc.list_resource_grants(store.get_user("u_admin"),
                                          "doc-2", now=T0)
    assert len(rows_admin) == 1
    print("\n[input] list grants by owner/stranger/admin "
          "-> [decision] owner+admin see it, stranger gets 404 like missing")


# ---------- 授权上限 ----------

def test_grant_limit_rejected_with_clear_error():
    svc, store = make_service(grant_max_per_resource=3)
    owner = add_user(store, "u_own", "own")
    store.add_resource(Resource(id="dlim", owner_id="u_own"))
    for i in range(3):
        add_user(store, f"u_g{i}", f"g{i}")
        svc.grant_resource_access(owner, "dlim", f"u_g{i}", "read",
                                  T0 + 3600, now=T0)
    add_user(store, "u_g3", "g3")
    with pytest.raises(AuthError) as e:
        svc.grant_resource_access(owner, "dlim", "u_g3", "read",
                                  T0 + 3600, now=T0)
    assert e.value.code is ErrorCode.GRANT_LIMIT_REACHED
    assert e.value.extra.get("limit") == 3
    # 同一键续期不占用新名额，即使已满也允许
    g, created = svc.grant_resource_access(owner, "dlim", "u_g0", "read",
                                           T0 + 7200, now=T0)
    assert created is False
    # 撤销一条后名额释放
    svc.revoke_resource_access(owner, "dlim", "u_g1", "read", now=T0)
    g2, created2 = svc.grant_resource_access(owner, "dlim", "u_g3", "read",
                                             T0 + 3600, now=T0)
    assert created2 is True
    print("\n[input] exceed per-resource grant cap "
          "-> [decision] 409 grant_limit_reached; renew exempt; revoke frees slot")


# ---------- 并发确定性 ----------

def test_concurrent_grants_same_key_exactly_one_created():
    svc, store = make_service()
    owner = store.get_user("u_editor")
    n = 16
    barrier = threading.Barrier(n)
    results: list[tuple[bool, type]] = []
    results_lock = threading.Lock()

    def worker(i: int):
        barrier.wait()
        try:
            _, created = svc.grant_resource_access(
                owner, "doc-2", "u_viewer", "delete",
                T0 + 3600 + i, now=T0 + i,
            )
            with results_lock:
                results.append((created, type(None)))
        except AuthError as exc:  # pragma: no cover - 不应发生
            with results_lock:
                results.append((False, type(exc)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r[0]]
    assert len(results) == n
    assert len(created) == 1  # 只有一路真正新增
    assert len(store.list_grants_for("doc-2")) == 1  # 始终只有一行
    print(f"\n[input] {n} concurrent grants same key "
          f"-> [decision] exactly 1 created, single row, others renewed")


def test_concurrent_grant_and_revoke_ends_consistent():
    """并发新增与撤销同一键：结束后状态唯一确定（撤销成功则不可再被放行）。"""
    svc, store = make_service()
    owner = store.get_user("u_editor")
    for round_no in range(20):
        # 每轮先重置：确保存在一条可撤销的授权
        svc.grant_resource_access(owner, "doc-2", "u_viewer", "delete",
                                  T0 + 3600, now=T0 + round_no)
        barrier = threading.Barrier(2)

        def do_grant():
            barrier.wait()
            svc.grant_resource_access(
                owner, "doc-2", "u_viewer", "delete",
                T0 + 7200, now=T0 + round_no + 1,
            )

        def do_revoke():
            barrier.wait()
            try:
                svc.revoke_resource_access(
                    owner, "doc-2", "u_viewer", "delete",
                    now=T0 + round_no + 1,
                )
            except AuthError:
                pass  # 撤销撞在撤销之后等交错，允许 404

        tg = threading.Thread(target=do_grant)
        tr = threading.Thread(target=do_revoke)
        tg.start(); tr.start(); tg.join(); tr.join()

        rows = [g for g in store.list_grants_for("doc-2")
                if g.action == "delete" and g.grantee_id == "u_viewer"]
        assert len(rows) == 1  # 永不出现重复行
        row = rows[0]
        # 临界区串行化：行状态与“此刻能否访问”必须严格一致
        viewer = store.get_user("u_viewer")
        view = svc.check_resource(viewer, "resource:delete", "doc-2",
                                  now=T0 + round_no + 2)
        assert view.decision.allowed is (not row.revoked and row.is_active(
            T0 + round_no + 2))
    print("\n[input] 20 rounds concurrent grant vs revoke "
          "-> [decision] single consistent row; access matches row state")


def test_concurrent_revoke_and_reads_no_window_after_revoke():
    """撤销与读/判定并发：撤销一旦完成，之后取得锁的请求全部被拒，无放行窗口。"""
    svc, store = make_service()
    owner = store.get_user("u_editor")
    viewer = store.get_user("u_viewer")
    svc.grant_resource_access(owner, "doc-2", "u_viewer", "delete",
                              T0 + 10_000, now=T0)

    stop = threading.Event()
    barrier = threading.Barrier(2)

    def reader_during_revoke():
        # 撤销进行期间持续判定；任何结果都合法（取决于与撤销的串行顺序），
        # 这里只制造竞争压力，不做越界断言。
        barrier.wait()
        i = 0
        while not stop.is_set():
            svc.check_resource(viewer, "resource:delete", "doc-2",
                               now=T0 + i)
            i += 1

    def revoker():
        barrier.wait()
        svc.revoke_resource_access(owner, "doc-2", "u_viewer", "delete",
                                   now=T0)
        stop.set()

    tr = threading.Thread(target=reader_during_revoke)
    tw = threading.Thread(target=revoker)
    tr.start(); tw.start(); tr.join(); tw.join()

    # 确定性断言：撤销提交完成之后，8 线程 × 200 次判定全部拒绝
    violations: list[bool] = []
    vlock = threading.Lock()

    def post_check(seed: int):
        local_bad = []
        for i in range(200):
            view = svc.check_resource(viewer, "resource:delete", "doc-2",
                                      now=T0 + 1000 + seed + i)
            if view.decision.allowed:
                local_bad.append(True)
        with vlock:
            violations.extend(local_bad)

    threads = [threading.Thread(target=post_check, args=(k,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert violations == []
    print("\n[input] reads racing revoke, then 8x200 post-revoke checks "
          "-> [decision] no request allowed after revoke commits")


def test_concurrent_grants_respect_limit_exactly():
    """并发放置不同授权：成功数恰好等于上限，其余全部 409，绝不超额。"""
    limit = 5
    svc, store = make_service(grant_max_per_resource=limit)
    owner = add_user(store, "u_own2", "own2")
    store.add_resource(Resource(id="dconc", owner_id="u_own2"))
    n = 20
    for i in range(n):
        add_user(store, f"u_c{i}", f"c{i}")
    barrier = threading.Barrier(n)
    created_count = 0
    rejected_count = 0
    clock = {"t": T0}
    clock_lock = threading.Lock()
    count_lock = threading.Lock()

    def worker(i: int):
        nonlocal created_count, rejected_count
        with clock_lock:
            clock["t"] += 1
            req_now = clock["t"]
        barrier.wait()
        try:
            _, created = svc.grant_resource_access(
                owner, "dconc", f"u_c{i}", "read",
                req_now + 3600, now=req_now,
            )
            assert created
            with count_lock:
                created_count += 1
        except AuthError as exc:
            assert exc.code is ErrorCode.GRANT_LIMIT_REACHED
            with count_lock:
                rejected_count += 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert created_count == limit
    assert rejected_count == n - limit
    active = [g for g in store.list_grants_for("dconc") if g.is_active(T0 + 100)]
    assert len(active) == limit
    print(f"\n[input] {n} concurrent distinct grants with cap={limit} "
          f"-> [decision] exactly {limit} created, rest 409")


# ---------- HTTP 层：同形 404、改/删入口、撤销即时 ----------

@pytest.fixture
def client():
    store = Store()
    seed_demo_data(store)
    service = AuthService(store, Settings(login_max_failures=99,
                                          grant_max_per_resource=2))
    main.app.state.service = service
    main.app.state.store = store
    with TestClient(main.app) as c:
        yield c, service, store


def _login(c, username):
    r = c.post("/auth/login",
               json={"username": username, "password": f"{username}-pw"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_unauthorized_and_missing_resource_identical_for_all_methods(client):
    c, _, store = client
    viewer = _login(c, "viewer")   # viewer 对他人资源 update/delete 无角色权
    # PATCH/DELETE：存在但无权 vs 不存在 —— 状态码与响应体必须完全一致
    for method in ("PATCH", "DELETE"):
        existing = c.request(method, "/resources/doc-2", headers=viewer,
                             json={"title": "x"})
        missing = c.request(method, "/resources/no-such-doc", headers=viewer,
                            json={"title": "x"})
        assert existing.status_code == missing.status_code == 404
        assert existing.text == missing.text
        assert existing.json()["error"]["code"] == "not_found"
    print("\n[input] denied vs missing over PATCH/DELETE (HTTP) "
          "-> [decision] identical 404 status and body")


def test_read_grant_gates_non_doc_resource_revoke_hides_like_missing(client):
    """非 doc kind 资源不在角色矩阵内：只有属主/被授权者/admin 可读。

    授权 -> 凭同一令牌可读；撤销 -> 立刻与"资源不存在"完全同形 404。
    """
    c, service, store = client
    owner = _login(c, "editor")
    r = c.post("/auth/login", json={"username": "viewer", "password": "viewer-pw"})
    viewer = {"Authorization": f"Bearer {r.json()['access_token']}"}
    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    # editor 创建一个 sheet 类资源（viewer/editor 角色矩阵不覆盖 sheet）
    r = c.post("/resources", headers=owner, json={"id": "sheet-1", "kind": "sheet"})
    assert r.status_code == 200
    # 授权前：viewer 读不到 -> 404，且与不存在的资源响应体逐字一致
    denied = c.get("/resources/sheet-1", headers=viewer)
    missing = c.get("/resources/no-such-thing", headers=viewer)
    assert denied.status_code == missing.status_code == 404
    assert denied.text == missing.text

    # 授 read -> 同一旧令牌立即可读，无需重新登录
    assert c.put("/resources/sheet-1/grants", headers=owner,
                 json={"grantee": "viewer", "action": "read",
                       "expires_at": exp}).status_code == 200
    r = c.get("/resources/sheet-1", headers=viewer)
    assert r.status_code == 200 and r.json()["kind"] == "sheet"

    # 撤销 -> 同一令牌立刻回到同形 404
    assert c.post("/resources/sheet-1/grants/revoke", headers=owner,
                  json={"grantee": "viewer", "action": "read"}).status_code == 200
    denied2 = c.get("/resources/sheet-1", headers=viewer)
    assert denied2.status_code == 404 and denied2.text == missing.text
    print("\n[input] read grant on non-doc kind: deny/grant/revoke "
          "-> [decision] 404==missing before & after, 200 while granted")


def test_granted_update_and_delete_routes_work(client):
    c, _, store = client
    owner = _login(c, "viewer")     # doc-1 属主
    # 增加一个无角色写权限的协作用户（viewer 对他人资源只能读）
    store.add_user(User(id="u_temp", username="temp",
                        password_hash=hash_password("temp-pw"), role=Role.VIEWER))
    r = c.post("/auth/login", json={"username": "temp", "password": "temp-pw"})
    temp = {"Authorization": f"Bearer {r.json()['access_token']}"}

    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    # 未授权：改/删都是 404
    assert c.patch("/resources/doc-1", headers=temp,
                   json={"title": "new"}).status_code == 404
    assert c.delete("/resources/doc-1", headers=temp).status_code == 404
    # 授权 update 后可改，delete 仍然 404
    assert c.put("/resources/doc-1/grants", headers=owner,
                 json={"grantee": "temp", "action": "update",
                       "expires_at": exp}).json()["status"] == "created"
    r = c.patch("/resources/doc-1", headers=temp, json={"title": "协作标题"})
    assert r.status_code == 200 and r.json()["title"] == "协作标题"
    assert c.delete("/resources/doc-1", headers=temp).status_code == 404
    # 再授权 delete 后可删，删除连带清授权
    assert c.put("/resources/doc-1/grants", headers=owner,
                 json={"grantee": "temp", "action": "delete",
                       "expires_at": exp}).status_code == 200
    assert c.delete("/resources/doc-1", headers=temp).status_code == 200
    assert store.get_resource("doc-1") is None
    assert store.list_grants_for("doc-1") == []
    print("\n[input] grant update/delete via HTTP "
          "-> [decision] same decision pipeline; delete cascades grants")


def test_revoke_via_http_invalidates_existing_token_at_once(client):
    """授 -> 凭旧令牌可操作 -> 撤销 -> 同一令牌立刻 404。"""
    c, _, _ = client
    owner = _login(c, "editor")
    r = c.post("/auth/login", json={"username": "viewer", "password": "viewer-pw"})
    viewer = {"Authorization": f"Bearer {r.json()['access_token']}"}
    exp = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

    c.post("/resources", headers=owner, json={"id": "doc-5"})
    # 授权前：viewer 删 editor 的资源 -> 404
    assert c.delete("/resources/doc-5", headers=viewer).status_code == 404
    assert c.put("/resources/doc-5/grants", headers=owner,
                 json={"grantee": "viewer", "action": "delete",
                       "expires_at": exp}).status_code == 200
    # 授权后同一令牌可删（用副本资源验证，不删撤销测试主体）
    c.post("/resources", headers=owner, json={"id": "doc-6"})
    c.put("/resources/doc-6/grants", headers=owner,
          json={"grantee": "viewer", "action": "delete", "expires_at": exp})
    assert c.delete("/resources/doc-6", headers=viewer).status_code == 200
    # 撤销 doc-5 的授权后，同一令牌立刻不可删，且与不存在同形
    assert c.post("/resources/doc-5/grants/revoke", headers=owner,
                  json={"grantee": "viewer", "action": "delete"}).status_code == 200
    r = c.delete("/resources/doc-5", headers=viewer)
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    print("\n[input] revoke via HTTP then reuse same token "
          "-> [decision] immediate 404, indistinguishable from missing")


def test_grant_management_routes_hidden_from_non_managers(client):
    c, _, _ = client
    editor = _login(c, "editor")   # 非 doc-1 属主、非 admin
    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    assert c.get("/resources/doc-1/grants", headers=editor).status_code == 404
    r = c.put("/resources/doc-1/grants", headers=editor,
              json={"grantee": "viewer", "action": "read", "expires_at": exp})
    assert r.status_code == 404
    r = c.post("/resources/doc-1/grants/revoke", headers=editor,
               json={"grantee": "viewer", "action": "read"})
    assert r.status_code == 404
    # 与不存在资源的响应一致
    assert c.get("/resources/nope/grants", headers=editor).status_code == 404
    print("\n[input] non-manager hits grant endpoints "
          "-> [decision] 404 identical to unknown resource")


def test_grant_limit_enforced_over_http(client):
    c, _, store = client
    owner = _login(c, "viewer")
    from app.security import hash_password
    for i in range(2):
        uid = f"u_h{i}"
        store.add_user(User(id=uid, username=f"h{i}",
                            password_hash=hash_password("x"), role=Role.VIEWER))
    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    r1 = c.put("/resources/doc-1/grants", headers=owner,
               json={"grantee": "h0", "action": "read", "expires_at": exp})
    r2 = c.put("/resources/doc-1/grants", headers=owner,
               json={"grantee": "h1", "action": "read", "expires_at": exp})
    assert r1.status_code == r2.status_code == 200
    r3 = c.put("/resources/doc-1/grants", headers=owner,
               json={"grantee": "admin", "action": "update", "expires_at": exp})
    assert r3.status_code == 409
    assert r3.json()["error"]["code"] == "grant_limit_reached"
    print("\n[input] third active grant over HTTP "
          "-> [decision] 409 grant_limit_reached")


def test_concurrent_delete_resource_and_grant_is_consistent():
    """删除资源 与 新增授权并发：两种交错都必须收敛，无悬挂授权。"""
    svc, store = make_service()
    owner = add_user(store, "u_dl", "dl")
    outcomes: list[str] = []
    olock = threading.Lock()

    for round_no in range(20):
        store.add_resource(Resource(id=f"dr-{round_no}", owner_id="u_dl"))
        barrier = threading.Barrier(2)

        def deleter(rid=f"dr-{round_no}"):
            barrier.wait()
            svc.delete_resource(owner, rid, now=T0 + round_no)
            with olock:
                outcomes.append("deleted")

        def granter(rid=f"dr-{round_no}"):
            barrier.wait()
            try:
                svc.grant_resource_access(
                    owner, rid, "u_viewer", "read",
                    T0 + 3600, now=T0 + round_no,
                )
                with olock:
                    outcomes.append("granted")
            except AuthError as exc:
                # 资源已被删除 -> 管理权校验得到 404
                assert exc.code is ErrorCode.NOT_FOUND
                with olock:
                    outcomes.append("grant_404")

        t1 = threading.Thread(target=deleter)
        t2 = threading.Thread(target=granter)
        t1.start(); t2.start(); t1.join(); t2.join()

        # 终态唯一：资源不存在；且不存在任何指向它的授权行
        assert store.get_resource(f"dr-{round_no}") is None
        assert store.list_grants_for(f"dr-{round_no}") == []
    assert any(o == "deleted" for o in outcomes)
    print("\n[input] 20 rounds delete-resource racing grant "
          "-> [decision] convergent final state, no dangling grants")


def test_granted_update_cannot_escalate_kind_to_role_matrix(client):
    """被授权改 sheet 的协作者不能通过把 kind 改成 doc 来借角色矩阵提权。"""
    c, _, store = client
    owner = _login(c, "editor")
    r = c.post("/auth/login", json={"username": "viewer", "password": "viewer-pw"})
    viewer = {"Authorization": f"Bearer {r.json()['access_token']}"}
    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    r = c.post("/resources", headers=owner,
               json={"id": "sheet-k", "kind": "sheet"})
    assert r.status_code == 200
    # 授 update（sheet 不在 viewer 的角色矩阵里，能改完全是因为授权）
    assert c.put("/resources/sheet-k/grants", headers=owner,
                 json={"grantee": "viewer", "action": "update",
                       "expires_at": exp}).status_code == 200
    # viewer 试图把 kind 改成 doc -> 仅凭协作授权禁止改 kind，
    # 且对外与"资源不存在"同形 404，防止借 kind 切换提权或探测资源
    r = c.patch("/resources/sheet-k", headers=viewer,
                json={"kind": "doc"})
    missing = c.patch("/resources/no-such-sheet", headers=viewer,
                      json={"kind": "doc"})
    assert r.status_code == missing.status_code == 404
    assert r.text == missing.text
    # kind 未被改动；改标题仍在授权范围内
    assert store.get_resource("sheet-k").kind == "sheet"
    r = c.patch("/resources/sheet-k", headers=viewer, json={"title": "新标题"})
    assert r.status_code == 200 and r.json()["title"] == "新标题"
    # 属主自己改 kind 不受限制
    r = c.patch("/resources/sheet-k", headers=owner, json={"kind": "doc"})
    assert r.status_code == 200 and r.json()["kind"] == "doc"
    print("\n[input] grantee flips kind sheet->doc "
          "-> [decision] 403 via grant; title ok; owner may change kind")


def test_disabled_grantee_cannot_use_grant():
    """被授权账号被禁用后，即使授权仍在有效期内也一律拒绝。"""
    svc, store = make_service()
    owner = store.get_user("u_editor")
    viewer = store.get_user("u_viewer")
    store.add_resource(Resource(id="s9", owner_id="u_editor", kind="sheet"))
    svc.grant_resource_access(owner, "s9", "u_viewer", "read",
                              T0 + 3600, now=T0)
    assert svc.check_resource(viewer, "resource:read", "s9",
                              now=T0 + 5).decision.allowed is True
    viewer.disabled = True
    denied = svc.check_resource(viewer, "resource:read", "s9", now=T0 + 6)
    assert denied.decision.allowed is False
    assert denied.decision.via == "disabled"
    print("\n[input] grantee disabled while grant active "
          "-> [decision] denied (disabled checked before grants)")
