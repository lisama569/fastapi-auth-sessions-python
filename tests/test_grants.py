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


def _cap_service(svc: AuthService, cap: int) -> AuthService:
    """复用同一 Store 但使用指定单资源授权上限的服务实例（仅改上限口径）。"""
    return AuthService(
        svc.store,
        Settings(grant_max_active_per_resource=cap, grant_max_ttl=3600),
    )


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


def test_regrant_expired_account_checked_against_same_cap(world):
    """上限=1：A 到期后 B 占满名额，再给 A 授权必须 409，有效授权仍为 1。

    回归"已到期账号重新授权跳过上限检查"的漏洞。
    """
    svc = world
    svc2 = _cap_service(svc, 1)  # 同一 Store，上限改为 1
    owner = _u(svc2, "u_owner")
    svc2.grant(owner, "res-1", "plain", ["resource:read"], 100, now=1000.0)
    # A 已到期，名额空闲：B 占满
    svc2.grant(owner, "res-1", "guest", ["resource:read"], 1000, now=2000.0)
    assert svc2.store.active_grant_count("res-1", 2000.0) == 1

    # 已到期的 A 重新授权，按全新授权同口径判定 -> 拒绝
    with pytest.raises(AuthError) as exc:
        svc2.grant(owner, "res-1", "plain",
                    ["resource:read"], 1000, now=2000.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    assert exc.value.extra == {"limit": 1, "active": 1}
    # 被拒绝后：有效授权仍是 B 一条；A 的旧记录保持已到期状态
    assert svc2.store.active_grant_count("res-1", 2000.0) == 1
    old_a = svc2.store.get_grant("res-1", "u_plain")
    assert old_a is not None and old_a.expires_at == 1100.0
    active_now = svc2.list_grants(owner, "res-1", now=2000.0)
    assert [g.grantee_id for g in active_now] == ["u_guest"]
    print("\n[input] cap=1, expired A regranted while B holds the slot "
          "-> [decision] grant_limit_exceeded; only B stays active")


def test_regrant_revoked_account_checked_against_same_cap(world):
    """上限=1：A 被撤销后 B 占满名额，再给 A 授权必须 409。"""
    svc = world
    svc1 = _cap_service(svc, 1)
    owner = _u(svc1, "u_owner")
    svc1.grant(owner, "res-1", "plain", ["resource:read"], 1000, now=1000.0)
    svc1.revoke_grant(owner, "res-1", "plain", now=1001.0)
    svc1.grant(owner, "res-1", "guest", ["resource:update"], 1000, now=1002.0)
    assert svc1.store.active_grant_count("res-1", 1002.0) == 1

    with pytest.raises(AuthError) as exc:
        svc1.grant(owner, "res-1", "plain",
                    ["resource:read"], 1000, now=1003.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    # 旧记录保持撤销状态、动作不被改写；B 的授权范围不受影响
    old_a = svc1.store.get_grant("res-1", "u_plain")
    assert old_a.revoked and old_a.actions == set()
    b = svc1.store.get_grant("res-1", "u_guest")
    assert b.actions == {"resource:update"} and not b.revoked
    assert svc1.store.active_grant_count("res-1", 1003.0) == 1
    print("\n[input] cap=1, revoked A regranted while B holds the slot "
          "-> [decision] grant_limit_exceeded; revoked state untouched")


def test_cap_boundary_rejection_leaves_no_partial_write(world):
    """上限边界：达上限后新授权拒绝；不写半条记录、不改既有授权范围。"""
    svc = world
    owner = _u(svc, "u_owner")
    from app.models import Role
    from app.security import hash_password
    # fixture 上限为 3：guest/plain 占 2 个，再建 3 个新账号
    for i in range(3):
        svc.store.add_user(User(id=f"u_h{i}", username=f"h{i}",
                                 password_hash=hash_password("x"),
                                 role=Role.GUEST))
    svc.grant(owner, "res-1", "guest",
               ["resource:read"], 100, now=1000.0)
    svc.grant(owner, "res-1", "plain",
               ["resource:read"], 100, now=1000.0)
    svc.grant(owner, "res-1", "h0",
               ["resource:read"], 100, now=1000.0)

    with pytest.raises(AuthError) as exc:
        svc.grant(owner, "res-1", "h1",
                    ["resource:delete"], 100, now=1000.0)
    assert exc.value.code is ErrorCode.GRANT_LIMIT_EXCEEDED
    # 被拒绝的新账号没有任何记录
    assert svc.store.get_grant("res-1", "u_h1") is None
    # 已存在的授权范围/有效期未被悄悄改变
    g0 = svc.store.get_grant("res-1", "u_h0")
    assert g0.actions == {"resource:read"} and g0.expires_at == 1100.0
    assert svc.store.active_grant_count("res-1", 1000.0) == 3

    # 处于上限时对三个现存账号续期/扩动作仍然全部允许（不新增名额）
    svc.grant(owner, "res-1", "h0", ["resource:delete"], 10, now=1001.0)
    svc.grant(owner, "res-1", "guest", ["resource:update"], 10, now=1001.0)
    svc.grant(owner, "res-1", "plain", ["resource:update"], 10, now=1001.0)
    assert svc.store.active_grant_count("res-1", 1001.0) == 3


def test_expiry_and_revoke_free_slots_for_reuse(world):
    """到期与撤销都释放名额：空出的名额可授给新人或原账号，计数始终不超上限。"""
    svc = world
    owner = _u(svc, "u_owner")
    from app.models import Role
    from app.security import hash_password
    for i in range(2):
        svc.store.add_user(User(id=f"u_k{i}", username=f"k{i}",
                                 password_hash=hash_password("x"),
                                 role=Role.GUEST))
    # 占满上限 3：guest、plain 长有效期；k0 短 TTL（t=1100 到期释放名额）
    svc.grant(owner, "res-1", "guest", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "plain", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "k0", ["resource:read"], 100, now=1000.0)
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "k1", ["resource:read"], 100, now=1000.0)

    # k0 到期释放名额 -> 新人 k1 可授；原账号 k0 此时重新授权仍需走上限（被拒）
    svc.grant(owner, "res-1", "k1", ["resource:read"], 2000, now=1101.0)
    assert svc.store.active_grant_count("res-1", 1101.0) == 3
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "k0", ["resource:read"], 100, now=1101.0)

    # guest 被撤销释放名额 -> 原账号 guest 重新授权可以成功（名额由它空出）
    svc.revoke_grant(owner, "res-1", "guest", now=1102.0)
    assert svc.store.active_grant_count("res-1", 1102.0) == 2
    g = svc.grant(owner, "res-1", "guest",
                    ["resource:update"], 100, now=1103.0)
    assert not g.revoked and g.actions == {"resource:update"}
    assert g.expires_at == 1203.0
    assert svc.store.active_grant_count("res-1", 1103.0) == 3
    # 重新占满后，无论是新人还是已撤销账号，再授一律拒绝
    with pytest.raises(AuthError):
        svc.grant(owner, "res-1", "k0", ["resource:read"], 100, now=1103.0)
    print("\n[input] expiry/revoke free slots, regrants reuse them "
          "-> [decision] count never above cap; at-cap regrant rejected")


def test_concurrent_new_grants_never_exceed_cap(world):
    """并发新增授权：多轮竞争下每轮成功数恰好填满名额，计数从不超过上限。"""
    svc = world
    owner = _u(svc, "u_owner")
    from app.models import Resource, Role
    from app.security import hash_password
    for i in range(8):
        svc.store.add_user(User(id=f"u_n{i}", username=f"n{i}",
                                 password_hash=hash_password("x"),
                                 role=Role.GUEST))
    errors: list[BaseException] = []
    elock = threading.Lock()

    for round_no in range(10):
        rid = f"res-c{round_no}"
        svc.store.add_resource(
            Resource(id=rid, owner_id="u_owner", kind="doc"))
        samples: list[int] = []
        slock = threading.Lock()
        barrier = threading.Barrier(8)

        def attempt(i: int, rid=rid):
            try:
                barrier.wait()
                svc.grant(owner, rid, f"n{i}",
                           ["resource:read"], 1000, now=5000.0)
            except AuthError as exc:
                if exc.code is not ErrorCode.GRANT_LIMIT_EXCEEDED:
                    with elock:
                        errors.append(exc)
            except BaseException as exc:  # noqa: BLE001
                with elock:
                    errors.append(exc)
            finally:
                with slock:
                    samples.append(svc.store.active_grant_count(rid, 5000.0))

        threads = [threading.Thread(target=attempt, args=(i,))
                   for i in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        # 8 抢 3 个名额：恰好 3 条有效，其余 409；任何时刻计数 <= 3
        assert svc.store.active_grant_count(rid, 5000.0) == 3
        assert max(samples) <= 3
    assert errors == []
    print("\n[input] 10 rounds x 8 concurrent new grants at cap=3 "
          "-> [decision] exactly 3 succeed per round, never over cap")


def test_concurrent_regrant_at_cap_all_renew(world):
    """并发重新授权（续期）同一现存账号：全部成功，不产生 409，名额不增加。"""
    svc = world
    owner = _u(svc, "u_owner")
    from app.models import Role
    from app.security import hash_password
    for i in range(2):
        svc.store.add_user(User(id=f"u_r{i}", username=f"r{i}",
                                 password_hash=hash_password("x"),
                                 role=Role.GUEST))
    # 初始三条授权在风暴时刻 t=2000 仍有效（TTL=2000，t=3000 才到期）
    svc.grant(owner, "res-1", "guest", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "plain", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "r0", ["resource:read"], 2000, now=1000.0)
    assert svc.store.active_grant_count("res-1", 2000.0) == 3

    errors: list[BaseException] = []
    elock = threading.Lock()
    barrier = threading.Barrier(16)

    def renew():
        try:
            barrier.wait()
            svc.grant(owner, "res-1", "r0",
                       ["resource:update"], 1000, now=2000.0)
        except BaseException as exc:  # noqa: BLE001
            with elock:
                errors.append(exc)

    threads = [threading.Thread(target=renew) for _ in range(16)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert errors == []
    assert svc.store.active_grant_count("res-1", 2000.0) == 3
    g = svc.store.get_grant("res-1", "u_r0")
    assert g.actions == {"resource:read", "resource:update"}
    assert g.expires_at == 3000.0
    print("\n[input] 16 concurrent renewals of one grant at cap "
          "-> [decision] all succeed, no spurious grant_limit_exceeded")


def test_concurrent_revoke_racing_new_and_regrants(world):
    """混合风暴：并发撤销释放名额，并发新授权 + 失效账号重新授权抢名额。

    初始占满 3 名额（guest/plain/r1），另有一条 x 的授权早已到期。
    风暴中 2 路撤销（guest/plain）与 4 路授权（x 重新授权 + e/f/h 三个新账号）
    同时竞争。候选都不是被撤账号本身，因此每路撤销确定地释放 1 个名额、
    每次成功授权确定地消耗 1 个名额：任意交错下恰好 2 个授权成功，
    任意时刻有效授权 <= 3，最终恰好填满上限（不超发、不浪费）。
    """
    import time as _time

    svc = world
    owner = _u(svc, "u_owner")
    from app.models import Role
    from app.security import hash_password
    svc.store.add_user(User(id="u_r1", username="r1",
                             password_hash=hash_password("x"), role=Role.GUEST))
    svc.store.add_user(User(id="u_x", username="x",
                             password_hash=hash_password("x"), role=Role.GUEST))
    for name in ("e", "f", "h"):
        svc.store.add_user(User(id=f"u_{name}", username=name,
                                 password_hash=hash_password("x"),
                                 role=Role.GUEST))
    # x 的授权在风暴前已到期（TTL=100：t=900 授，t=1000 到期，不占名额）
    svc.grant(owner, "res-1", "x", ["resource:read"], 100, now=900.0)
    svc.grant(owner, "res-1", "guest", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "plain", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "r1", ["resource:read"], 2000, now=1000.0)
    assert svc.store.active_grant_count("res-1", 2000.0) == 3

    stop = threading.Event()
    barrier = threading.Barrier(7)  # 4 授权 + 2 撤销 + 1 采样
    succeeded: list[str] = []
    slock = threading.Lock()
    samples: list[int] = []
    errors: list[BaseException] = []
    elock = threading.Lock()
    candidates = ["x", "e", "f", "h"]

    def grantee(name: str):
        try:
            barrier.wait()
            while not stop.is_set():
                try:
                    svc.grant(owner, "res-1", name,
                               ["resource:read"], 2000, now=2000.0)
                    with slock:
                        succeeded.append(name)
                    return
                except AuthError as exc:
                    if exc.code is not ErrorCode.GRANT_LIMIT_EXCEEDED:
                        raise
                    if stop.is_set():
                        return  # 落败候选（名额已满），属正常结果
                    stop.wait(0.002)
        except BaseException as exc:  # noqa: BLE001
            with elock:
                errors.append(exc)

    def revoker(name: str):
        barrier.wait()
        svc.revoke_grant(owner, "res-1", name, now=2000.0)

    def sampler():
        barrier.wait()
        while not stop.is_set():
            samples.append(svc.store.active_grant_count("res-1", 2000.0))
            stop.wait(0.001)

    threads = [threading.Thread(target=grantee, args=(n,))
               for n in candidates]
    threads += [threading.Thread(target=revoker, args=(n,))
                for n in ("guest", "plain")]
    threads.append(threading.Thread(target=sampler))
    for t in threads: t.start()
    # 等满 2 个胜出者（2 个名额必然释放），随后停止重试并收尾
    deadline = _time.monotonic() + 5.0
    while len(succeeded) < 2 and _time.monotonic() < deadline:
        _time.sleep(0.01)
    stop.set()
    for t in threads: t.join()
    assert errors == []

    assert len(succeeded) == 2 and len(set(succeeded)) == 2
    assert set(succeeded) <= set(candidates)
    assert svc.store.active_grant_count("res-1", 2000.0) == 3
    assert samples and max(samples) <= 3
    # r1 从未被动过，始终有效；guest/plain 已被撤销
    active_ids = {g.grantee_id for g in svc.list_grants(owner, "res-1", 2000.0)}
    assert "u_r1" in active_ids
    assert "u_guest" not in active_ids and "u_plain" not in active_ids
    print(f"\n[input] 2 revokes racing 1 expired-regrant + 3 new grants "
          f"-> [decision] winners={sorted(succeeded)}, count always <= 3")


def test_concurrent_regrants_after_revoke_and_expiry_fill_freed_slots(world):
    """撤销/到期已释放名额后，并发重新授权（已撤/已过期账号）与新授权抢名额。

    风暴前 guest 被撤销、r1 已到期，只剩 plain 1 条有效（空闲 2 个名额）。
    4 路并发授权——guest（已撤销重新授权）、r1（已到期重新授权）、e/f 新账号
    ——恰好 2 路成功，任意交错下有效授权从不超过上限，最终恰好填满。
    """
    import time as _time

    svc = world
    owner = _u(svc, "u_owner")
    from app.models import Role
    from app.security import hash_password
    svc.store.add_user(User(id="u_r1", username="r1",
                             password_hash=hash_password("x"), role=Role.GUEST))
    for name in ("e", "f"):
        svc.store.add_user(User(id=f"u_{name}", username=name,
                                 password_hash=hash_password("x"),
                                 role=Role.GUEST))
    svc.grant(owner, "res-1", "guest", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "plain", ["resource:read"], 2000, now=1000.0)
    svc.grant(owner, "res-1", "r1", ["resource:read"], 1000, now=1000.0)
    # 风暴前：撤销 guest；r1 到 t=2000 自然到期
    svc.revoke_grant(owner, "res-1", "guest", now=2000.0)
    assert svc.store.active_grant_count("res-1", 2000.0) == 1

    stop = threading.Event()
    barrier = threading.Barrier(5)  # 4 授权 + 1 采样
    succeeded: list[str] = []
    slock = threading.Lock()
    samples: list[int] = []
    errors: list[BaseException] = []
    elock = threading.Lock()
    candidates = ["guest", "r1", "e", "f"]

    def grantee(name: str):
        try:
            barrier.wait()
            while not stop.is_set():
                try:
                    svc.grant(owner, "res-1", name,
                               ["resource:read"], 2000, now=2000.0)
                    with slock:
                        succeeded.append(name)
                    return
                except AuthError as exc:
                    if exc.code is not ErrorCode.GRANT_LIMIT_EXCEEDED:
                        raise
                    if stop.is_set():
                        return  # 落败候选（名额已满），属正常结果
                    stop.wait(0.002)
        except BaseException as exc:  # noqa: BLE001
            with elock:
                errors.append(exc)

    def sampler():
        barrier.wait()
        while not stop.is_set():
            samples.append(svc.store.active_grant_count("res-1", 2000.0))
            stop.wait(0.001)

    threads = [threading.Thread(target=grantee, args=(n,))
               for n in candidates]
    threads.append(threading.Thread(target=sampler))
    for t in threads: t.start()
    deadline = _time.monotonic() + 5.0
    while len(succeeded) < 2 and _time.monotonic() < deadline:
        _time.sleep(0.01)
    stop.set()
    for t in threads: t.join()
    assert errors == []

    assert len(succeeded) == 2 and len(set(succeeded)) == 2
    assert svc.store.active_grant_count("res-1", 2000.0) == 3
    assert samples and max(samples) <= 3
    active_ids = {g.grantee_id for g in svc.list_grants(owner, "res-1", 2000.0)}
    assert "u_plain" in active_ids
    assert {f"u_{n}" for n in succeeded} <= active_ids
    print(f"\n[input] 4 concurrent re/new-grants for 2 freed slots "
          f"-> [decision] winners={sorted(succeeded)}, no over-issue")





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
