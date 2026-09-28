"""资源协作授权编排：授权的查看/新增/撤销，以及携带授权快照的资源访问判定。

并发正确性：每个复合方法都在同一把 store.lock 临界区内完成
“取资源 -> 管理权判定 -> 取授权/计数 -> 写入/判定访问”，
因此并发的新增、撤销与读/改/删之间结果确定：
一旦撤销提交成功，之后取得锁的任何请求都不可能再按该授权放行。

到期：不依赖后台任务，所有判定与计数都以当前时间惰性计算；
授权不进入访问令牌，撤销/到期不需要对方重新登录。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import Decision, Grant, Resource, User
from app.policy import GRANT_ACTIONS, can_manage_grants, decide
from app.store import Store

logger = logging.getLogger("auth_sessions.grants")


@dataclass
class AccessView:
    """一次资源访问判定的同锁快照：资源、判定与此刻有效的授权集合。"""

    resource: Resource
    decision: Decision
    grants: list[Grant]


def authorize_resource(store: Store, user: User, policy_action: str,
                       resource_id: str, *, now: float | None = None,
                       log: bool = True) -> AccessView:
    """在同一临界区内取资源 + 取该用户有效授权 + 策略判定。

    不存在资源与无权访问都交回调用方统一映射为 404，避免资源探测。
    """
    now = time.time() if now is None else now
    with store.lock:
        resource = store.get_resource(resource_id)
        if resource is None:
            grants: list[Grant] = []
            decision = decide(user, policy_action, None, None,
                              now=now, log=log)
        else:
            grants = [
                g for g in store.grants_for_user(resource_id, user.id)
                if g.is_active(now)
            ]
            decision = decide(user, policy_action, resource, grants,
                              now=now, log=log)
        return AccessView(resource, decision, grants)


def _resolve_grantee(store: Store, identity: str) -> User:
    """被授权方标识：优先按用户 id，其次按用户名；都不匹配即非法请求。"""
    user = store.get_user(identity)
    if user is None:
        user = store.get_user_by_name(identity)
    if user is None or user.disabled:
        raise AuthError(ErrorCode.INVALID_GRANT, "unknown or disabled grantee")
    return user


def _require_manager(store: Store, actor: User, resource_id: str) -> Resource:
    """加载资源并校验授权管理权；资源不存在与无权管理对外同为 404。"""
    resource = store.get_resource(resource_id)
    if resource is None or not can_manage_grants(actor, resource):
        logger.info(
            "grant management denied actor=%s resource=%s",
            actor.id, resource_id,
        )
        raise AuthError(ErrorCode.NOT_FOUND)
    return resource


def grant_access(store: Store, settings: Settings, actor: User,
                 resource_id: str, grantee_identity: str, action: str,
                 expires_at: float, *, now: float | None = None
                 ) -> tuple[Grant, bool]:
    """新增/续期一条协作授权，幂等返回 (grant, created)。

    同一 (资源, 被授权账号, 动作) 反复授权只更新失效时间与时间戳，不新增条数。
    超过单资源有效授权上限则明确拒绝（409）。
    """
    now = time.time() if now is None else now
    if action not in GRANT_ACTIONS:
        raise AuthError(
            ErrorCode.INVALID_GRANT,
            f"action must be one of {sorted(GRANT_ACTIONS)}",
        )
    if expires_at <= now:
        raise AuthError(ErrorCode.INVALID_GRANT, "expires_at must be in the future")
    if expires_at > now + settings.grant_max_ttl:
        raise AuthError(
            ErrorCode.INVALID_GRANT,
            f"expires_at exceeds max grant ttl ({settings.grant_max_ttl}s)",
        )

    with store.lock:
        resource = _require_manager(store, actor, resource_id)
        grantee = _resolve_grantee(store, grantee_identity)
        if grantee.id == resource.owner_id:
            raise AuthError(
                ErrorCode.INVALID_GRANT,
                "resource owner already has full access; grant is redundant",
            )

        existing = store.get_grant(resource_id, grantee.id, action)
        if existing is not None and existing.is_active(now):
            # 幂等续期：同键反复授权不新增条数
            existing.expires_at = expires_at
            existing.granted_by = actor.id
            existing.granted_at = now
            logger.info(
                "grant renewed resource=%s grantee=%s action=%s until=%.0f",
                resource_id, grantee.id, action, expires_at,
            )
            return existing, False

        active_count = sum(
            1 for g in store.list_grants_for(resource_id) if g.is_active(now)
        )
        if active_count >= settings.grant_max_per_resource:
            logger.warning(
                "grant limit reached resource=%s active=%d limit=%d",
                resource_id, active_count, settings.grant_max_per_resource,
            )
            raise AuthError(
                ErrorCode.GRANT_LIMIT_REACHED,
                f"resource has reached the grant limit "
                f"({settings.grant_max_per_resource})",
                extra={"limit": settings.grant_max_per_resource},
            )

        grant = Grant(
            resource_id=resource_id,
            grantee_id=grantee.id,
            action=action,
            expires_at=expires_at,
            granted_by=actor.id,
            granted_at=now,
        )
        store.put_grant(grant)
        logger.info(
            "grant created resource=%s grantee=%s action=%s until=%.0f by=%s",
            resource_id, grantee.id, action, expires_at, actor.id,
        )
        return grant, True


def revoke_access(store: Store, actor: User, resource_id: str,
                  grantee_identity: str, action: str,
                  *, now: float | None = None) -> None:
    """撤销一条授权；撤销成功后后续请求立即按无授权判定。

    对管理者而言，授权不存在/已失效与资源不可见口径一致（404），
    并发撤销因此天然幂等、结果确定。
    """
    now = time.time() if now is None else now
    if action not in GRANT_ACTIONS:
        raise AuthError(
            ErrorCode.INVALID_GRANT,
            f"action must be one of {sorted(GRANT_ACTIONS)}",
        )
    with store.lock:
        _require_manager(store, actor, resource_id)
        grantee = _resolve_grantee(store, grantee_identity)
        removed = store.revoke_grant(resource_id, grantee.id, action, now)
        if not removed:
            raise AuthError(ErrorCode.NOT_FOUND)
        logger.info(
            "grant revoked resource=%s grantee=%s action=%s by=%s",
            resource_id, grantee.id, action, actor.id,
        )


def list_grants(store: Store, actor: User, resource_id: str,
                *, now: float | None = None) -> list[dict]:
    """列出某资源的授权（含有效/已过期/已撤销状态）；仅管理者可查看。"""
    now = time.time() if now is None else now
    with store.lock:
        _require_manager(store, actor, resource_id)
        rows = sorted(
            store.list_grants_for(resource_id),
            key=lambda g: (g.grantee_id, g.action),
        )
        return [public_grant(g, now) for g in rows]


def public_grant(grant: Grant, now: float) -> dict:
    return {
        "resource_id": grant.resource_id,
        "grantee_id": grant.grantee_id,
        "action": grant.action,
        "expires_at": grant.expires_at,
        "granted_by": grant.granted_by,
        "granted_at": grant.granted_at,
        "revoked": grant.revoked,
        "revoked_at": grant.revoked_at,
        "active": grant.is_active(now),
    }
