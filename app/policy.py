"""基于角色 + 资源属性 + 显式权限 + 协作授权的判定；默认拒绝。

规则（按顺序评估，命中即决定，全部不命中则拒绝）：
1. 用户被禁用 -> 拒绝
2. extra_permissions 命中 "<action>:<kind>" / "<action>:*" / "*" -> 允许
3. 角色矩阵命中资源无关动作（resource:create 等）-> 允许
4. 资源存在时，属主对自己资源可 read/update/delete/share
5. 资源存在时，当前有效的协作授权命中该动作 -> 允许
   （授权到期/撤销由服务层按服务端当前状态过滤；令牌不携带授权快照）
6. 其余资源相关动作命中角色矩阵 -> 允许
7. 以上都不命中 -> 默认拒绝
"""

from __future__ import annotations

import logging

from app.models import Decision, Grant, Resource, Role, User

logger = logging.getLogger("auth_sessions.policy")

# 资源无关的动作 -> 允许的角色
ROLE_ACTION: dict[str, set[Role]] = {
    "resource:create": {Role.ADMIN, Role.EDITOR},
    "user:read": {Role.ADMIN},
    "user:change_role": {Role.ADMIN},
}

# 资源相关动作：非属主时允许的角色（属主默认可 read/update/delete/share）
ROLE_RESOURCE_ACTION: dict[str, set[Role]] = {
    "resource:read": {Role.ADMIN, Role.EDITOR, Role.VIEWER},
    "resource:update": {Role.ADMIN, Role.EDITOR},
    "resource:delete": {Role.ADMIN},
    # 协作授权管理：属主可管理自己的资源；admin 角色可管理任意资源
    "resource:share": {Role.ADMIN},
}

# 属主默认可执行的资源动作（含协作授权的查看/新增/撤销）
OWNER_ACTIONS = {
    "resource:read",
    "resource:update",
    "resource:delete",
    "resource:share",
}
# 可被临时协作授权的动作（授权本身不能再转授，防止扩散）
GRANTABLE_ACTIONS = {"resource:read", "resource:update", "resource:delete"}
WILDCARDS = {"*"}


def _permission_hits(user: User, action: str, kind: str | None) -> list[str]:
    candidates = {action, f"{action}:*", "*"}
    if kind:
        candidates.add(f"{action}:{kind}")
    return sorted(user.extra_permissions & candidates)


def _grant_hits(user: User, action: str,
                 grants: list[Grant] | None) -> Grant | None:
    """返回命中该动作的当前有效协作授权（调用方须保证 grants 未撤销/未到期）。"""
    if not grants:
        return None
    for grant in grants:
        if grant.grantee_id == user.id and action in grant.actions:
            return grant
    return None


def decide(user: User, action: str, resource: Resource | None,
           grants: list[Grant] | None = None, *, log: bool = True) -> Decision:
    """判定用户对资源可否执行动作；返回带原因的 Decision。

    grants 为该资源当前有效的协作授权（由服务层在存储锁内取快照，
    已剔除撤销/过期记录）；为 None 时视同没有协作授权。
    """
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
        and (grant := _grant_hits(user, action, grants)) is not None
    ):
        d = Decision(
            True,
            f"collaboration grant on {resource.id} allows {action} "
            f"until {grant.expires_at:.0f}",
        )
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
