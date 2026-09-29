"""资源协作授权：临时授权、到期自动失效、撤销即时生效、幂等、上限与防探测。"""

from __future__ import annotations

import threading

import pytest

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import Resource, Role, User
from app.security import hash_password
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


def _service_with_cap(cap: int) -> AuthService:
    """构造一个单资源有效授权上限为 cap 的独立服务，并铺好 owner + res-1。"""
    store = Store()
    settings = Settings(
        grant_max_active_per_resource=cap, grant_max_ttl=3600)
    svc = AuthService(store, settings)
    store.add_user(User(
        id="u_owner", username="owner", password_hash=hash_password("x"),
        role=Role.VIEWER))
    store.add_resource(Resource(id="res-1", owner_id="u_owner", kind="doc"))
    return svc


def _add_user(svc: AuthService, uid: str, name: str,
              role: Role = Role.GUEST) -> User:
    user = User(id=uid, username=name,
                password_hash=hash_password("x"), role=role)
    svc.store.add_user(user)
    return user


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


def test_regrant_after_expiry_is_rejected_when_slot_taken_cap1():
    """上限=1 的核心漏洞回归：A 授权到期 -> B 占满名额 -> 重新给 A 授权必须拒绝。

    对已失效账号重新授权与给全新账号授权走同一个上限口径；
    被拒绝后该资源的有效授权数仍然是 1，不能叠到 2，更不能继续往上叠。
    """
    svc = _service_with_cap(1)
    owner = _u(svc, "u_owner")
    a = _add_user(svc, "u_a", "alice")
    b = _add_user(svc, "u_b", "bob")

    # 1) 先给 A 授权并让它自然到期
    svc.grant(owner, "res-1", "alice", ["resource:read"], 100, now=1000.0)
    assert svc.store.active_grant_count("res-1", 1100.0) == 0
    assert not svc.authorize_resource(
        a, "resource:read", "res-1", now=1100.0)[1].allowed

    # 2) B 授权把唯一名额占满
    svc.grant(owner, "res-1", "bob", ["resource:read"], 100, now=1100.0)
    assert svc.store.active_grant_count("res-1", 1101.0) == 1

    # 3) 名额满时重新给 A 授权：必须 409，而不是把有效授权叠成 2
    with pytest.raises(AuthError) as exc:
        svc.grant(owner, "res-1", "alice",
                  ["resource:read"], 100, now=1101.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    assert exc.value.extra == {"limit": 1, "active": 1}

    assert svc.store.active_grant_count("res-1", 1101.0) == 1
    # A 的旧授权仍是失效状态，没有被悄悄复活
    assert not svc.authorize_resource(
        a, "resource:read", "res-1", now=1101.0)[1].allowed
    # B 的授权不受影响
    assert svc.authorize_resource(
        b, "resource:read", "res-1", now=1101.0)[1].allowed

    # 4) 继续反复尝试也不能往上叠（此时 B 的授权仍在有效期内：1100..1200）
    for t in range(1102, 1110):
        with pytest.raises(AuthError) as exc2:
            svc.grant(owner, "res-1", "alice",
                      ["resource:read"], 100, now=float(t))
        assert exc2.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    assert svc.store.active_grant_count("res-1", 1150.0) == 1
    print("\n[input] cap=1: A expires, B fills slot, re-grant A x9 "
          "-> [decision] all 409; active count stays 1")


def test_regrant_after_revoke_is_rejected_when_slot_taken_cap1():
    """上限=1：A 授权被整条撤销 -> B 占满名额 -> 重新给 A 授权必须拒绝。"""
    svc = _service_with_cap(1)
    owner = _u(svc, "u_owner")
    a = _add_user(svc, "u_a", "alice")
    b = _add_user(svc, "u_b", "bob")

    # 1) 给 A 授权后由属主整条撤销，名额释放
    svc.grant(owner, "res-1", "alice",
              ["resource:read", "resource:update"], 100, now=1000.0)
    svc.revoke_grant(owner, "res-1", "alice", now=1001.0)
    assert svc.store.active_grant_count("res-1", 1001.0) == 0

    # 2) B 占满唯一名额
    svc.grant(owner, "res-1", "bob", ["resource:delete"], 100, now=1002.0)

    # 3) 重新给已撤销的 A 授权：按新增名额判断，明确拒绝
    with pytest.raises(AuthError) as exc:
        svc.grant(owner, "res-1", "alice",
                  ["resource:read"], 100, now=1003.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    assert svc.store.active_grant_count("res-1", 1003.0) == 1
    assert not svc.authorize_resource(
        a, "resource:read", "res-1", now=1003.0)[1].allowed
    assert svc.authorize_resource(
        b, "resource:delete", "res-1", now=1003.0)[1].allowed
    print("\n[input] cap=1: A revoked, B fills slot, re-grant A "
          "-> [decision] 409; revoked A stays inactive")


def test_rejected_regrant_leaves_no_trace_and_preserves_others():
    """达上限被拒绝的重新授权：不改旧记录、不影响其它授权、不留半条记录。"""
    svc = _service_with_cap(1)
    owner = _u(svc, "u_owner")
    a = _add_user(svc, "u_a", "alice")
    b = _add_user(svc, "u_b", "bob")

    # A 的授权在 t=1000..1100 有效
    svc.grant(owner, "res-1", "alice",
              ["resource:read"], 100, now=1000.0)
    old_a = svc.store.get_grant("res-1", a.id)
    assert old_a is not None
    old_actions = set(old_a.actions)
    old_expires = old_a.expires_at

    # A 到期后 B 占满名额
    svc.grant(owner, "res-1", "bob",
              ["resource:read", "resource:update"], 100, now=1100.0)
    b_grant = svc.store.get_grant("res-1", b.id)
    b_actions_before = set(b_grant.actions)

    # 重新给 A 授权被拒绝（新动作集与旧的不同，用来检测是否被半写入）
    with pytest.raises(AuthError) as exc:
        svc.grant(owner, "res-1", "alice",
                  ["resource:delete"], 100, now=1101.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED

    # A 的旧记录原样保留：仍为失效状态、动作与到期时间均未被改动
    same = svc.store.get_grant("res-1", a.id)
    assert same is old_a
    assert same.actions == old_actions == {"resource:read"}
    assert same.expires_at == old_expires == 1100.0
    assert not svc.authorize_resource(
        a, "resource:read", "res-1", now=1101.0)[1].allowed
    # B 的授权有效范围没有被这次失败请求悄悄改动
    assert svc.store.get_grant("res-1", b.id).actions == b_actions_before
    assert svc.store.active_grant_count("res-1", 1101.0) == 1
    print("\n[input] rejected re-grant with different actions "
          "-> [decision] 409; old expired record and B unchanged")


def test_slot_release_by_expiry_and_revoke_can_be_reused_cap2():
    """上限=2：到期/撤销释放名额后可再授给别人；成功后有效数永远不超过上限。"""
    svc = _service_with_cap(2)
    owner = _u(svc, "u_owner")
    a = _add_user(svc, "u_a", "alice")
    b = _add_user(svc, "u_b", "bob")
    c = _add_user(svc, "u_c", "carol")
    d = _add_user(svc, "u_d", "dave")

    # A、B 占满 2 个名额（错开授权时间，便于只让 A 先到期）
    svc.grant(owner, "res-1", "alice", ["resource:read"], 100, now=1000.0)
    svc.grant(owner, "res-1", "bob", ["resource:read"], 100, now=1050.0)
    assert svc.store.active_grant_count("res-1", 1050.0) == 2
    with pytest.raises(AuthError) as exc:
        svc.grant(owner, "res-1", "carol",
                  ["resource:read"], 100, now=1050.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED

    # A 自然到期（1100）释放名额，B 仍有效（至 1150）-> C 可以拿到名额
    assert svc.store.active_grant_count("res-1", 1100.0) == 1
    svc.grant(owner, "res-1", "carol",
              ["resource:read"], 100, now=1100.0)
    assert svc.store.active_grant_count("res-1", 1100.0) == 2
    assert svc.authorize_resource(
        c, "resource:read", "res-1", now=1101.0)[1].allowed

    # 再次满员：对已到期的 A 重新授权也必须拒绝（不因其曾持名额而破例）
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "alice",
                  ["resource:read"], 100, now=1101.0)

    # B 被撤销释放名额 -> D 可授；成功后仍恰好 2 个有效授权
    svc.revoke_grant(owner, "res-1", "bob", now=1102.0)
    assert svc.store.active_grant_count("res-1", 1102.0) == 1
    svc.grant(owner, "res-1", "dave",
              ["resource:read"], 100, now=1102.0)
    assert svc.store.active_grant_count("res-1", 1103.0) == 2
    active_grantees = {
        g.grantee_id
        for g in svc.store.active_grants_for("res-1", 1103.0)
    }
    assert active_grantees == {"u_c", "u_d"}
    # 被撤销的 B 不再能访问
    assert not svc.authorize_resource(
        b, "resource:read", "res-1", now=1103.0)[1].allowed
    print("\n[input] cap=2 expiry/revoke frees slots for C then D "
          "-> [decision] reuse ok; active never exceeds 2")


def test_regrant_after_release_starts_fresh_with_new_scope():
    """失效后重新授权 = 全新名额语义：按本次动作生效，不与旧记录做并集。"""
    svc = _service_with_cap(3)
    owner = _u(svc, "u_owner")
    a = _add_user(svc, "u_a", "alice")

    svc.grant(owner, "res-1", "alice",
              ["resource:read", "resource:update"], 100, now=1000.0)
    svc.revoke_grant(owner, "res-1", "alice", now=1001.0)

    # 名额释放后重新授权：只授 read；旧的 update 不应复活
    g = svc.grant(owner, "res-1", "alice",
                  ["resource:read"], 100, now=2000.0)
    assert not g.revoked and g.actions == {"resource:read"}
    assert g.granted_at == 2000.0 and g.expires_at == 2100.0
    assert svc.authorize_resource(
        a, "resource:read", "res-1", now=2001.0)[1].allowed
    assert not svc.authorize_resource(
        a, "resource:update", "res-1", now=2001.0)[1].allowed
    # 重新授权只占一个名额（同键覆盖，不叠加条目）
    assert svc.store.active_grant_count("res-1", 2001.0) == 1
    print("\n[input] re-grant revoked A with read only "
          "-> [decision] fresh scope; old update not resurrected")


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


# ---- 上限相关并发：新增 / 重新授权 / 撤销 同时发生时不得超发、不得误拒 ----

def test_concurrent_new_grants_never_exceed_cap():
    """空资源上 N 路并发给全新账号授权：恰好 cap 路成功，其余 409，绝不超发。"""
    cap = 3
    svc = _service_with_cap(cap)
    owner = _u(svc, "u_owner")
    n = 16
    for i in range(n):
        _add_user(svc, f"u_c{i}", f"cand{i}")

    ok: list[str] = []
    rejected: list[str] = []
    errors: list[BaseException] = []
    slock = threading.Lock()
    barrier = threading.Barrier(n)

    def worker(i: int):
        name = f"cand{i}"
        try:
            barrier.wait()
            svc.grant(owner, "res-1", name,
                      ["resource:read"], 500, now=2000.0)
            with slock:
                ok.append(name)
        except AuthError as exc:
            assert exc.code is ErrorCode.GRANT_LIMIT_EXCEEDED
            with slock:
                rejected.append(name)
        except BaseException as exc:  # noqa: BLE001
            with slock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert errors == []
    assert len(ok) == cap
    assert len(rejected) == n - cap
    assert svc.store.active_grant_count("res-1", 2000.0) == cap
    # 成功的账号当前确实可访问；被拒的账号没有留下任何有效授权
    for i in range(n):
        user = _u(svc, f"u_c{i}")
        allowed = svc.authorize_resource(
            user, "resource:read", "res-1", now=2001.0)[1].allowed
        assert allowed is (f"cand{i}" in ok)
    print(f"\n[input] {n} concurrent new grants against cap={cap} "
          f"-> [decision] exactly {cap} ok, {n - cap} rejected, count={cap}")


def test_concurrent_revoke_then_regrant_single_freed_slot():
    """满员资源上撤销与两路重新授权并发：上限在任意交错下都成立。

    最终状态由锁串行化后的"最后一次写入"决定，存在多种合法交错（线程在
    barrier 后可按任意顺序进入临界区），因此本测试只断言调度无关的不变量：
    - 撤销先于重授：alice/carol 中至多一人拿到释放名额，另一人 409；
    - alice 的重授先于撤销：该重授属"有效授权幂等续期"（不占新名额，必成功），
      随后撤销可能再把名额摘掉（最终只剩 bob）或被 carol 接住。
    任何交错下都不可能：超发、alice 与 carol 同时有效、两路重授都被误判超限。
    """
    cap = 2
    svc = _service_with_cap(cap)
    owner = _u(svc, "u_owner")
    _add_user(svc, "u_a", "alice")
    _add_user(svc, "u_b", "bob")
    _add_user(svc, "u_c", "carol")

    # 先用 alice/bob 占满（TTL 覆盖整个并发阶段，期间只有撤销能释放名额）；
    # 随后撤销 alice 释放名额，alice 与 carol 同时争抢这个名额
    svc.grant(owner, "res-1", "alice",
              ["resource:read"], 3000, now=1000.0)
    svc.grant(owner, "res-1", "bob",
              ["resource:read"], 3000, now=1000.0)

    results: dict[str, str] = {}
    errors: list[BaseException] = []
    peak = 0
    rlock = threading.Lock()
    barrier = threading.Barrier(3)

    def do_revoke():
        barrier.wait()
        svc.revoke_grant(owner, "res-1", "alice", now=2000.0)
        with rlock:
            results["revoke"] = "done"

    def do_regrant(name: str):
        try:
            barrier.wait()
            svc.grant(owner, "res-1", name,
                      ["resource:read"], 3000, now=2000.0)
            with rlock:
                results[name] = "ok"
        except AuthError as exc:
            with rlock:
                results[name] = exc.code.value
        except BaseException as exc:  # noqa: BLE001
            with rlock:
                errors.append(exc)
        # 每个操作落盘后立即校验：该资源有效授权数不可能超过上限（抓瞬时超发）
        count = svc.store.active_grant_count("res-1", 2000.0)
        nonlocal peak
        with rlock:
            peak = max(peak, count)
        assert count <= cap

    ts = [
        threading.Thread(target=do_revoke),
        threading.Thread(target=do_regrant, args=("alice",)),
        threading.Thread(target=do_regrant, args=("carol",)),
    ]
    for t in ts: t.start()
    for t in ts: t.join()

    assert errors == []
    assert results["revoke"] == "done"
    assert set(results) == {"revoke", "alice", "carol"}
    assert peak <= cap  # 整个并发过程中没有任何一个时刻超过上限

    active = {g.grantee_id
              for g in svc.store.active_grants_for("res-1", 2001.0)}
    # bob 的授权从未被动过，始终有效
    assert "u_b" in active
    # alice 与 carol 不可能同时持有被释放的那个名额（否则就是超发）
    assert not {"u_a", "u_c"} <= active
    # 至少一路重授成功：不可能把本该成功的名额误判成双双超限
    assert "ok" in (results["alice"], results["carol"])
    # 被拒（409）的那一路最终必须无效——拒绝路径不写入，不可能让它凭空有效
    if results["alice"] == ErrorCode.GRANT_LIMIT_EXCEEDED.value:
        assert "u_a" not in active
    if results["carol"] == ErrorCode.GRANT_LIMIT_EXCEEDED.value:
        assert "u_c" not in active
    # 最终不超过 cap（最后写若是撤销，有效数也可能小于 cap）
    assert len(active) <= cap
    print(f"\n[input] revoke + 2 concurrent regrants (full resource) "
          f"-> [decision] outcomes={results}; peak={peak}; active={sorted(active)}")


def test_concurrent_mixed_grant_regrant_revoke_never_overflows():
    """多轮混合并发：新增 / 对已失效账号重新授权 / 撤销 同时进行，上限恒成立。"""
    cap = 3
    svc = _service_with_cap(cap)
    owner = _u(svc, "u_owner")
    for i in range(12):
        _add_user(svc, f"u_m{i}", f"m{i}")

    errors: list[BaseException] = []
    elock = threading.Lock()
    rounds = 30
    start = threading.Barrier(8)

    def grant_worker(clock_base: int):
        start.wait()
        for r in range(rounds):
            i = (clock_base + r) % 12
            try:
                # ttl 很长，有效状态只由撤销/上限决定，排除自然到期的干扰
                svc.grant(owner, "res-1", f"m{i}",
                          ["resource:read"], 3000,
                          now=3000.0 + clock_base * rounds + r)
            except AuthError as exc:
                assert exc.code is ErrorCode.GRANT_LIMIT_EXCEEDED
            except BaseException as exc:  # noqa: BLE001
                with elock:
                    errors.append(exc)

    def revoke_worker(clock_base: int):
        start.wait()
        for r in range(rounds):
            i = (clock_base + 2 * r) % 12
            svc.revoke_grant(owner, "res-1", f"m{i}",
                             now=3000.0 + clock_base * rounds + r)

    # 5 路新增/重新授权（同键覆盖即"重新授权"）+ 3 路撤销同时跑
    ts = [threading.Thread(target=grant_worker, args=(b,)) for b in range(5)]
    ts += [threading.Thread(target=revoke_worker, args=(b,)) for b in range(3)]
    for t in ts: t.start()
    for t in ts: t.join()

    assert errors == []
    # 任何交错结束后，有效授权数都不得超过上限；条目数本身可能更少（同键覆盖）
    # 取一个晚于全部并发写时刻、但仍在最后一批授权有效期内的时钟：
    # 最晚授权时刻约 4149，+3000 后到期边界约 7149。
    now_final = 6000.0
    active = svc.store.active_grants_for("res-1", now_final)
    assert len(active) <= cap
    # 同键覆盖写保证没有重复条目：每个被授权人最多一条记录
    grantees = [g.grantee_id for g in svc.store.grants.values()
                if g.resource_id == "res-1"]
    assert len(grantees) == len(set(grantees))
    # 再做一次"恢复到满员"的校验：撤销到空之后可正常重新用满名额
    for i in range(12):
        svc.revoke_grant(owner, "res-1", f"m{i}", now=now_final)
    assert svc.store.active_grant_count("res-1", now_final) == 0
    for i in range(cap):
        svc.grant(owner, "res-1", f"m{i}",
                  ["resource:read"], 100, now=now_final)
    assert svc.store.active_grant_count("res-1", now_final) == cap
    with pytest.raises(AuthError) as exc:
        svc.grant(owner, "res-1", "m9",
                  ["resource:read"], 100, now=now_final)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    print(f"\n[input] 5 grant/regrant + 3 revoke threads x {rounds} rounds "
          f"-> [decision] active <= {cap} after every interleaving")
