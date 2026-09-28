"""基于角色 + 资源属性 + 显式权限 + 协作授权的判定；默认拒绝。

规则（按顺序评估，命中即决定，全部不命中则拒绝）：
1. 用户被禁用 -> 拒绝
2. extra_permissions 命中 "<action>:<kind>" / "<action>:*" / "*" -> 允许
   （角色或权限变更即时生效，因为每次都读取当前 User）
3. 角色矩阵命中资源无关动作（admin:* 等）-> 允许
4. 资源存在时，属主专属动作（read/update/delete 自己的 doc）允许
5. 资源存在且持有该动作的【有效协作授权】（未撤销且未到期）-> 允许
   授权记录由调用方按服务端当前状态传入，因此撤销/到期对下一次请求立即生效，
   访问令牌不携带授权快照，不需要对方重新登录。
6. 角色矩阵命中资源相关动作 -> 允许
7. 其余一律拒绝（默认拒绝；授权缺失不会放开任何默认关口）
"""

from __future__ import annotations

import logging
import time

from app.models import Decision, Grant, Resource, Role, User

logger = logging.getLogger("auth_sessions.policy")


def _time_now() -> float:
    return time.time()

# 资源无关的动作 -> 允许的角色
ROLE_ACTION: dict[str, set[Role]] = {
    "resource:create": {Role.ADMIN, Role.EDITOR},
    "user:read": {Role.ADMIN},
    "user:change_role": {Role.ADMIN},
}

# 资源相关动作：非属主时允许的角色（按资源 kind 区分；默认 kind="doc"）
# - doc 维持既有口径（viewer 可读、editor 可改、admin 可删）
# - 未列出的 kind 默认不按角色放行，只有属主 / admin / 显式权限 / 协作授权可访问，
#   从而把"谁能读什么"严格限定为属主、固定角色与被明确授权者（默认拒绝）。
ROLE_RESOURCE_ACTION: dict[str, dict[str, set[Role]]] = {
    "resource:read": {
        "doc": {Role.ADMIN, Role.EDITOR, Role.VIEWER},
    },
    "resource:update": {
        "doc": {Role.ADMIN, Role.EDITOR},
    },
    "resource:delete": {
        "doc": {Role.ADMIN},
    },
}

# admin 对任意 kind 的资源具备完整管理权限（在 decide 中以 user.role is ADMIN 放行）

OWNER_ACTIONS = {"resource:read", "resource:update", "resource:delete"}
WILDCARDS = {"*"}

# 协作授权使用的短动作名 <-> 策略动作名
GRANT_ACTIONS: dict[str, str] = {
    "read": "resource:read",
    "update": "resource:update",
    "delete": "resource:delete",
}


def can_manage_grants(user: User, resource: Resource) -> bool:
    """谁能查看/新增/撤销某资源的协作授权：

    1. 持有显式管理权限 grant:manage:<kind> / grant:manage:* / *
    2. 资源属主
    3. admin 角色（对所有资源本来就具备完整管理权限）

    其余角色（editor/viewer 即使可读/改他人资源）不能管理他人资源的授权。
    """
    if user.disabled:
        return False
    if _permission_hits(user, "grant:manage", resource.kind):
        return True
    if resource.owner_id == user.id:
        return True
    return user.role is Role.ADMIN


def _permission_hits(user: User, action: str, kind: str | None) -> list[str]:
    candidates = {action, f"{action}:*", "*"}
    if kind:
        candidates.add(f"{action}:{kind}")
    return sorted(user.extra_permissions & candidates)


def decide(user: User, action: str, resource: Resource | None,
           grants: list[Grant] | None = None, *,
           now: float | None = None, log: bool = True) -> Decision:
    """判定用户对资源可否执行动作；返回带原因的 Decision。

    grants: 该用户在该资源上的授权记录（仅需传入，是否有效由这里统一判断）。
    """
    kind = resource.kind if resource is not None else None
    active_grant: Grant | None = None
    if resource is not None and grants:
        for g in grants:
            if (
                g.resource_id == resource.id
                and g.grantee_id == user.id
                and GRANT_ACTIONS.get(g.action) == action
                and g.is_active(now if now is not None else _time_now())
            ):
                active_grant = g
                break

    if user.disabled:
        d = Decision(False, "user disabled", via="disabled")
    elif hits := _permission_hits(user, action, kind):
        d = Decision(True, f"explicit permission: {'|'.join(hits)}",
                     via="permission")
    elif action in ROLE_ACTION and user.role in ROLE_ACTION[action]:
        d = Decision(True, f"role {user.role.value} grants {action}",
                     via="role")
    elif (
        resource is not None
        and action in OWNER_ACTIONS
        and resource.owner_id == user.id
    ):
        d = Decision(True, f"owner of resource {resource.id} may {action}",
                     via="owner")
    elif active_grant is not None:
        d = Decision(True, (
            f"collaboration grant on {resource.id} "
            f"allows {action} until {active_grant.expires_at:.0f}"
        ), via="grant")
    elif (
        resource is not None
        and action in ROLE_RESOURCE_ACTION
        and (
            user.role is Role.ADMIN
            or user.role in ROLE_RESOURCE_ACTION[action].get(kind, set())
        )
    ):
        d = Decision(True, f"role {user.role.value} grants {action} on {kind}",
                     via="role")
    else:
        d = Decision(False, f"default deny: no rule allows {action}",
                     via="deny")

    if log:
        logger.info(
            "decision user_id=%s role=%s action=%s resource_id=%s "
            "owner=%s allowed=%s reason=%s",
            user.id, user.role.value, action,
            resource.id if resource else "<none>",
            resource.owner_id if resource else "<none>",
            d.allowed, d.reason,
        )
    return d
