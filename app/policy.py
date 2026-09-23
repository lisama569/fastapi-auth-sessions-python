"""基于角色 + 资源属性 + 显式权限的判定；默认拒绝。

规则（按顺序评估，命中即决定，全部不命中则拒绝）：
1. 用户被禁用 -> 拒绝
2. extra_permissions 命中 "<action>:<kind>" / "<action>:*" / "*" -> 允许
   （角色或权限变更即时生效，因为每次都读取当前 User）
3. 角色矩阵命中资源无关动作（admin:* 等）-> 允许
4. 资源存在时，属主专属动作（read/update/delete 自己的 doc）允许
5. 其余一律拒绝（默认拒绝）
"""

from __future__ import annotations

import logging

from app.models import Decision, Resource, Role, User

logger = logging.getLogger("auth_sessions.policy")

# 资源无关的动作 -> 允许的角色
ROLE_ACTION: dict[str, set[Role]] = {
    "resource:create": {Role.ADMIN, Role.EDITOR},
    "user:read": {Role.ADMIN},
    "user:change_role": {Role.ADMIN},
}

# 资源相关动作：非属主时允许的角色（属主默认可 read/update/delete）
ROLE_RESOURCE_ACTION: dict[str, set[Role]] = {
    "resource:read": {Role.ADMIN, Role.EDITOR, Role.VIEWER},
    "resource:update": {Role.ADMIN, Role.EDITOR},
    "resource:delete": {Role.ADMIN},
}

OWNER_ACTIONS = {"resource:read", "resource:update", "resource:delete"}
WILDCARDS = {"*"}


def _permission_hits(user: User, action: str, kind: str | None) -> list[str]:
    candidates = {action, f"{action}:*", "*"}
    if kind:
        candidates.add(f"{action}:{kind}")
    return sorted(user.extra_permissions & candidates)


def decide(user: User, action: str, resource: Resource | None,
           *, log: bool = True) -> Decision:
    """判定用户对资源可否执行动作；返回带原因的 Decision。"""
    kind = resource.kind if resource is not None else None

    if user.disabled:
        d = Decision(False, "user disabled")
    elif hits := _permission_hits(user, action, kind):
        d = Decision(True, f"explicit permission: {'|'.join(hits)}")
    elif action in ROLE_ACTION and user.role in ROLE_ACTION[action]:
        d = Decision(True, f"role {user.role.value} grants {action}")
    elif (
        resource is not None
        and action in OWNER_ACTIONS
        and resource.owner_id == user.id
    ):
        d = Decision(True, f"owner of resource {resource.id} may {action}")
    elif (
        resource is not None
        and action in ROLE_RESOURCE_ACTION
        and user.role in ROLE_RESOURCE_ACTION[action]
    ):
        d = Decision(True, f"role {user.role.value} grants {action} on {kind}")
    else:
        d = Decision(False, f"default deny: no rule allows {action}")

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
