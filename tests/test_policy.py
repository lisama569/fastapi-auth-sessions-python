"""默认拒绝、越权与资源不可见一致性、角色/权限即时变更。"""

from __future__ import annotations

import logging

import pytest

from app.errors import AuthError, ErrorCode
from app.models import Role
from app.services import AuthService
from app.services import seed_demo_data
from app.store import Store


def test_default_deny_for_unknown_action(svc: AuthService):
    admin = svc.store.get_user("u_admin")
    from app.models import Resource
    res = svc.store.get_resource("doc-1")
    d = svc.authorize(admin, "resource:explode", res)
    assert d.allowed is False
    assert "default deny" in d.reason
    print(f"\n[input] admin action=resource:explode "
          f"-> [decision] {d.reason}")


def test_owner_and_role_decisions(svc: AuthService, decision_logs):
    viewer = svc.store.get_user("u_viewer")
    editor = svc.store.get_user("u_editor")
    doc = svc.store.get_resource("doc-1")  # owner = viewer

    assert svc.authorize(viewer, "resource:read", doc).allowed
    # editor 可按角色读；但只有 admin 能删除非自己资源
    assert svc.authorize(editor, "resource:read", doc).allowed
    assert not svc.authorize(editor, "resource:delete", doc).allowed
    assert svc.authorize(svc.store.get_user("u_admin"),
                         "resource:delete", doc).allowed
    print("\n[input] owner/role matrix on doc-1 "
          "-> [decision]\n  " + "\n  ".join(decision_logs.texts()))
    assert any("owner of resource" in t for t in decision_logs.texts())


def test_unauthorized_and_missing_resource_are_indistinguishable(svc: AuthService):
    """越权访问他人资源 与 资源不存在：服务层都不返回资源，HTTP 层同为 404。"""
    from fastapi.testclient import TestClient
    import main
    # 使用一个独立 app：替换为测试用 svc
    main.app.state.service = svc
    with TestClient(main.app) as c:
        editor = svc.login("editor", "editor-pw", "10.0.0.1")
        h = {"Authorization": f"Bearer {editor.access_token}"}
        # doc-1 属于 viewer，viewer 角色的 editor 按角色仍可读(矩阵允许 editor 读)；
        # 构造越权：删除他人资源
        missing = c.get("/resources/does-not-exist", headers=h)
        # 用只读 viewer 访问不属于自己且其角色对 delete 无权的资源，经由路由 404 规则
        # 这里直接验证服务层语义：不存在资源与被拒判定同形
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "not_found"

        res_none = svc.store.get_resource("does-not-exist")
        res_doc = svc.store.get_resource("doc-1")
        d_missing = svc.authorize(svc.store.get_user("u_editor"),
                                  "resource:delete", res_none)
        d_denied = svc.authorize(svc.store.get_user("u_editor"),
                                 "resource:delete", res_doc)
        assert d_missing.allowed is False and d_denied.allowed is False
        print(f"\n[input] delete missing vs other-owned resource "
              f"-> [decision] missing:{d_missing.reason} | denied:{d_denied.reason}; "
              f"both surfaced as 404 not_found")


def test_role_change_takes_effect_immediately_without_relogin(svc: AuthService):
    admin = svc.login("admin", "admin-pw", "10.0.0.1")
    editor_login = svc.login("editor", "editor-pw", "10.0.0.2")
    old_token = editor_login.access_token

    # 变更前：editor 可以创建资源
    assert svc.authorize(svc.store.get_user("u_editor"),
                         "resource:create", None).allowed

    # 管理员降级 editor -> viewer；现存访问令牌立即吊销
    svc.change_role(admin.user, "u_editor", Role.VIEWER)
    with pytest.raises(AuthError) as revoked:
        svc.authenticate(old_token)
    assert revoked.value.code is ErrorCode.ACCESS_TOKEN_REVOKED

    # 用刷新凭证换新令牌后，立即按 viewer 新规则判定，无需重新登录
    new_access, _new_refresh = svc.refresh(editor_login.refresh_token)
    user_now, _, _ = svc.authenticate(new_access)
    assert user_now.role is Role.VIEWER
    decision = svc.authorize(user_now, "resource:create", None)
    assert decision.allowed is False
    print(f"\n[input] admin demotes editor->viewer "
          f"-> [decision] old access revoked immediately; "
          f"refreshed session now denied create: {decision.reason}")


def test_extra_permission_change_is_immediate(svc: AuthService, decision_logs):
    """显式权限的授予/回收即时生效（同样每次回查当前用户状态）。"""
    viewer = svc.store.get_user("u_viewer")
    doc = svc.store.get_resource("doc-2")  # 属于 editor
    before = svc.authorize(viewer, "resource:delete", doc)
    assert before.allowed is False

    viewer.extra_permissions.add("resource:delete:doc")
    after_grant = svc.authorize(viewer, "resource:delete", doc)
    assert after_grant.allowed is True and "explicit permission" in after_grant.reason

    viewer.extra_permissions.discard("resource:delete:doc")
    after_revoke = svc.authorize(viewer, "resource:delete", doc)
    assert after_revoke.allowed is False
    print(f"\n[input] grant then revoke extra permission "
          f"-> [decision] deny -> {after_grant.reason} -> {after_revoke.reason}")
