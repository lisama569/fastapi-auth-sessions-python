"""资源协作授权：临时授权、到期自动失效、撤销即时生效、幂等、上限与防探测。"""

from __future__ import annotations

import threading

import pytest

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import User
from app.services import AuthService
from app.store import Store


@pytest.fixture
def svc() -> AuthService:
    store = Store()
    settings = Settings(grant_max_active_per_resource=3, grant_max_ttl=3600)
    return AuthService(store, settings)


@pytest.fixture
def world(svc: AuthService):
    """owner(viewer 角色) 拥有 res；guest 是另一个普通 viewer。"""
    from app.models import Resource, Role
    from app.security import hash_password
    svc.store.add_user(User(
        id="u_owner", username="owner", password_hash=hash_password("x"),
        role=Role.VIEWER))
    svc.store.add_user(User(
        id="u_guest", username="guest", password_hash=hash_password("x"),
        role=Role.VIEWER))
    # 无任何资源角色权限的账号（自定义角色名不在矩阵内），用于验证 read 授权本身
    svc.store.add_user(User(
        id="u_plain", username="plain", password_hash=hash_password("x"),
        role=Role.GUEST))
    svc.store.add_resource(Resource(id="res-1", owner_id="u_owner", kind="doc"))
    svc.store.add_resource(Resource(id="res-2", owner_id="u_owner", kind="doc"))
    return svc


def _u(svc, uid):
    return svc.store.get_user(uid)


def test_grant_allows_read_only_for_granted_action(world):
    svc = world
    owner, guest = _u(svc, "u_owner"), _u(svc, "u_guest")
    now = 1000.0

    # 授权前：viewer 角色按矩阵可读任意资源，但改/删别人资源默认拒绝
    assert not svc.authorize_resource(
        guest, "resource:update", "res-1", now)[1].allowed

    svc.grant(owner, "res-1", "guest", ["resource:update"], 60, now=now)

    _, d_upd = svc.authorize_resource(guest, "resource:update", "res-1", now)
    _, d_del = svc.authorize_resource(guest, "resource:delete", "res-1", now)
    assert d_upd.allowed and "collaboration grant" in d_upd.reason
    assert not d_del.allowed  # 只授了 update
    print(f"\n[input] guest granted update on res-1 "
          f"-> [decision] update:{d_upd.reason} | delete:{d_del.reason}")


def test_grant_expires_automatically_without_relogin(world):
    """到期自动失效：同一访问凭证（同一 User/会话语义）无需重新登录即被拒。"""
    svc = world
    owner, plain = _u(svc, "u_owner"), _u(svc, "u_plain")
    svc.grant(owner, "res-1", "plain", ["resource:read"], 100, now=1000.0)

    assert svc.authorize_resource(
        plain, "resource:read", "res-1", now=1099.0)[1].allowed
    # 到期点（expires_at <= now）即拒绝；令牌本身仍有效，只是授权没了
    d = svc.authorize_resource(
        plain, "resource:read", "res-1", now=1100.0)[1]
    assert not d.allowed
    print(f"\n[input] read at t=1099 then t=1100 (expiry) "
          f"-> [decision] allowed then {d.reason}; no relogin involved")


def test_revocation_takes_effect_immediately_with_existing_token(world):
    """撤销后对方手里已有的访问凭证立刻失效（授权不随令牌快照携带）。"""
    svc = world
    owner, guest = _u(svc, "u_owner"), _u(svc, "u_guest")
    svc.grant(owner, "res-1", "guest", ["resource:delete"], 100, now=1000.0)
    assert svc.authorize_resource(
        guest, "resource:delete", "res-1", now=1001.0)[1].allowed

    svc.revoke_grant(owner, "res-1", "guest", now=1002.0)
    d = svc.authorize_resource(
        guest, "resource:delete", "res-1", now=1003.0)[1]
    assert not d.allowed
    print(f"\n[input] grant delete then revoke "
          f"-> [decision] subsequent request {d.reason} immediately")


def test_partial_revoke_keeps_remaining_actions(world):
    svc = world
    owner, guest = _u(svc, "u_owner"), _u(svc, "u_guest")
    svc.grant(owner, "res-1", "guest",
               ["resource:read", "resource:delete"], 100, now=1000.0)
    svc.revoke_grant(owner, "res-1", "guest",
                      actions=["resource:delete"], now=1001.0)
    assert svc.authorize_resource(
        guest, "resource:read", "res-1", now=1001.0)[1].allowed
    assert not svc.authorize_resource(
        guest, "resource:delete", "res-1", now=1001.0)[1].allowed
    # 最后一个动作被摘掉时整条记录标记撤销
    svc.revoke_grant(owner, "res-1", "guest",
                      actions=["resource:read"], now=1002.0)
    assert svc.store.get_grant("res-1", "u_guest").revoked


def test_repeat_grant_is_idempotent_and_extends(world):
    svc = world
    owner, guest = _u(svc, "u_owner"), _u(svc, "u_guest")
    g1 = svc.grant(owner, "res-1", "guest", ["resource:read"], 100, now=1000.0)
    g2 = svc.grant(owner, "res-1", "guest",
                     ["resource:delete"], 50, now=1020.0)
    assert g1 is g2  # 同一记录，未新增
    assert g2.actions == {"resource:read", "resource:delete"}
    assert g2.expires_at == 1100.0  # 取更远的到期时间
    assert svc.store.active_grant_count("res-1", 1020.0) == 1


def test_grant_cap_is_enforced_per_resource(world):
    """单资源有效授权上限：超限明确拒绝；不同资源与到期释放不受影响。"""
    svc = world
    from app.models import Role
    from app.security import hash_password
    owner = _u(svc, "u_owner")
    for i in range(3):
        uid = f"u_g{i}"
        svc.store.add_user(User(id=uid, username=f"g{i}",
                                 password_hash=hash_password("x"),
                                 role=Role.VIEWER))
        svc.grant(owner, "res-1", f"g{i}", ["resource:read"], 100, now=1000.0)

    svc.store.add_user(User(id="u_g3", username="g3",
                             password_hash=hash_password("x"),
                             role=Role.VIEWER))
    with pytest.raises(AuthError) as exc:
        svc.grant(owner, "res-1", "g3", ["resource:read"], 100, now=1000.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    # 另一资源不受此资源上限影响
    svc.grant(owner, "res-2", "g3", ["resource:read"], 100, now=1000.0)
    # 续期/扩动作不被上限拒绝（幂等，不新增条目）
    svc.grant(owner, "res-1", "g0", ["resource:update"], 10, now=1001.0)
    # 一个授权到期后释放名额，可再授
    svc.grant(owner, "res-1", "g3", ["resource:read"], 10, now=1101.0)
    print(f"\n[input] 4th grant at cap=3 -> [decision] "
          f"grant_limit_exceeded; expiry frees a slot")


def test_only_owner_or_admin_can_manage_grants(world):
    svc = world
    from app.models import Role
    guest, owner = _u(svc, "u_guest"), _u(svc, "u_owner")
    svc.store.add_user(User(
        id="u_admin", username="admin", password_hash="x", role=Role.ADMIN))
    admin = _u(svc, "u_admin")

    # 非属主普通角色：查看/新增/撤销一律按 404（与资源不存在同形）
    with pytest.raises(AuthError) as e_list:
        svc.list_grants(guest, "res-1", now=1000.0)
    with pytest.raises(AuthError) as e_put:
        svc.grant(guest, "res-1", "admin", ["resource:read"], 10, now=1000.0)
    with pytest.raises(AuthError) as e_rev:
        svc.revoke_grant(guest, "res-1", "owner", now=1000.0)
    assert all(e.value.code is ErrorCode.NOT_FOUND
               for e in (e_list, e_put, e_rev))

    # admin 角色具备资源管理权限，可以授权与撤销
    svc.grant(admin, "res-1", "guest", ["resource:read"], 10, now=1000.0)
    assert len(svc.list_grants(admin, "res-1", now=1000.0)) == 1
    svc.revoke_grant(admin, "res-1", "guest", now=1001.0)
    assert svc.list_grants(admin, "res-1", now=1001.0) == []
    print("\n[input] guest/admin manage grants on owner's resource "
          "-> [decision] guest 404 indistinct, admin allowed")


def test_grant_endpoint_hides_resource_existence(world):
    """资源不存在 与 无权管理：授权三个入口返回完全一致的 404 not_found。"""
    svc = world
    guest = _u(svc, "u_guest")
    for rid in ("res-1", "does-not-exist"):
        with pytest.raises(AuthError) as e:
            svc.grant(guest, rid, "owner", ["resource:read"], 10, now=1000.0)
        assert e.value.code is ErrorCode.NOT_FOUND
        with pytest.raises(AuthError) as e2:
            svc.list_grants(guest, rid, now=1000.0)
        assert e2.value.code is ErrorCode.NOT_FOUND


def test_invalid_grant_inputs_rejected(world):
    svc = world
    owner = _u(svc, "u_owner")
    # 非法动作 / 空动作
    with pytest.raises(AuthError) as e:
        svc.grant(owner, "res-1", "guest", ["resource:explode"], 10, now=1.0)
    assert e.value.code is ErrorCode.INVALID_GRANT
    # 授权动作不能包含 share（授权不可转授）
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "guest", ["resource:share"], 10, now=1.0)
    # 有效期非法
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "guest", ["resource:read"], 0, now=1.0)
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "guest", ["resource:read"], 99999, now=1.0)
    # 给属主自己授权
    with pytest.raises(AuthError) as e2:
        svc.grant(owner, "res-1", "owner", ["resource:read"], 10, now=1.0)
    assert e2.value.code is ErrorCode.INVALID_GRANT
    # 不存在的被授权人
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "ghost", ["resource:read"], 10, now=1.0)


def test_default_gate_not_loosened_by_grant_feature(world):
    """没有授权的人继续按原口径拒绝：未授 update 的 viewer 不能改/删他人资源。"""
    svc = world
    guest = _u(svc, "u_guest")
    res2_other = svc.authorize_resource(
        guest, "resource:update", "res-2", now=1000.0)
    assert not res2_other[1].allowed


def test_regrant_after_full_revoke_is_active_again(world):
    """整条撤销后再次授权应恢复生效（不残留 revoked 状态），且不占额外名额。"""
    svc = world
    owner, guest = _u(svc, "u_owner"), _u(svc, "u_guest")
    svc.grant(owner, "res-1", "guest", ["resource:delete"], 100, now=1000.0)
    svc.revoke_grant(owner, "res-1", "guest", now=1001.0)
    assert not svc.authorize_resource(
        guest, "resource:delete", "res-1", now=1002.0)[1].allowed

    g = svc.grant(owner, "res-1", "guest",
                    ["resource:delete"], 100, now=2000.0)
    assert not g.revoked and g.actions == {"resource:delete"}
    assert svc.authorize_resource(
        guest, "resource:delete", "res-1", now=2001.0)[1].allowed
    assert svc.store.active_grant_count("res-1", 2001.0) == 1


def test_concurrent_grant_and_revoke_has_deterministic_outcome(world):
    """并发新增/撤销：锁串行化，最终状态确定；撤销成功后读请求必被拒。"""
    svc = world
    owner, guest = _u(svc, "u_owner"), _u(svc, "u_guest")
    errors: list[BaseException] = []

    barrier = threading.Barrier(2)

    def do_grant():
        try:
            barrier.wait()
            for _ in range(50):
                svc.grant(owner, "res-1", "guest",
                         ["resource:delete"], 500, now=2000.0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def do_revoke():
        try:
            barrier.wait()
            for _ in range(50):
                svc.revoke_grant(owner, "res-1", "guest", now=2000.0)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=do_grant)
    t2 = threading.Thread(target=do_revoke)
    t1.start(); t2.start(); t1.join(); t2.join()
    assert errors == []

    # 撤销一旦是最后完成的写操作，随后的判定必须拒绝（无放行窗口）；
    # 这里显式再撤销一次，然后从多个线程同时读，必须全部拒绝。
    svc.revoke_grant(owner, "res-1", "guest", now=3000.0)
    results: list[bool] = []
    rlock = threading.Lock()

    def reader():
        _, d = svc.authorize_resource(
            guest, "resource:delete", "res-1", now=3000.0)
        with rlock:
            results.append(d.allowed)

    ts = [threading.Thread(target=reader) for _ in range(16)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert results == [False] * 16
    print(f"\n[input] 50x grant vs 50x revoke, then 16 concurrent reads "
          f"-> [decision] all denied after final revoke")


def test_concurrent_grant_revoke_against_concurrent_reads_never_diverges(world):
    """新增/撤销并发多轮后最终撤销；最终状态确定，且撤销点后无放行窗口。"""
    svc = world
    owner, guest = _u(svc, "u_owner"), _u(svc, "u_guest")
    svc.grant(owner, "res-1", "guest", ["resource:delete"], 1000, now=1000.0)

    errors: list[BaseException] = []
    elock = threading.Lock()

    def worker(worker_id: int):
        try:
            for i in range(20):
                clock = 2000.0 + worker_id * 100 + i
                svc.grant(owner, "res-1", "guest",
                           ["resource:delete"], 1000, now=clock)
                svc.revoke_grant(owner, "res-1", "guest", now=clock + 1)
        except BaseException as exc:  # noqa: BLE001
            with elock:
                errors.append(exc)

    # 12 线程各自重复 20 轮 grant->revoke，全部在存储锁上串行化
    threads = [threading.Thread(target=worker, args=(w,)) for w in range(12)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert errors == []

    # 最终状态确定：最后再撤销一次，随后立即与并发读全部必须拒绝
    svc.revoke_grant(owner, "res-1", "guest", now=9999.0)
    g = svc.store.get_grant("res-1", "u_guest")
    assert g.revoked and not g.actions

    deny: list[bool] = []
    dlock = threading.Lock()

    def reader():
        _, d = svc.authorize_resource(
            guest, "resource:delete", "res-1", now=9999.0)
        with dlock:
            deny.append(d.allowed)

    rs = [threading.Thread(target=reader) for _ in range(32)]
    for t in rs: t.start()
    for t in rs: t.join()
    assert deny == [False] * 32
    print("\n[input] 12 threads x 20 grant/revoke rounds then revoke + 32 reads "
          "-> [decision] deterministic final state; no allow after revoke")
