"""应用服务层：登录/注销/刷新/访问判定的编排，跨入口复用同一套规则。

HTTP 层（Header / Cookie）只负责取令牌，所有判定都走这里，
保证不同调用入口在同一套鉴权规则下得到一致结果。
"""

from __future__ import annotations

import logging
import secrets
import time

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import Decision, Grant, Resource, Role, Session, User
from app.policy import GRANTABLE_ACTIONS, decide
from app.ratelimit import LoginRateLimiter
from app.security import hash_password, redact, verify_password
from app.store import Store
from app.tokens import (
    issue_tokens,
    revoke_family_tree,
    rotate_refresh,
    verify_access,
)

logger = logging.getLogger("auth_sessions.service")


class LoginResult:
    def __init__(self, access_token: str, refresh_token: str,
                 user: User, session_id: str) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user = user
        self.session_id = session_id


class AuthService:
    def __init__(self, store: Store, settings: Settings,
                 limiter: LoginRateLimiter | None = None) -> None:
        self.store = store
        self.settings = settings
        self.limiter = limiter or LoginRateLimiter(
            settings.login_rate_window,
            settings.login_max_failures,
            settings.login_base_lockout,
            settings.login_max_lockout,
        )

    # ---- 登录 ----
    def login(self, username: str, password: str, source: str,
              now: float | None = None) -> LoginResult:
        """限流检查 -> 凭证校验（统一错误，不暴露账号是否存在）-> 建会话与令牌。"""
        now = time.time() if now is None else now
        self.limiter.check(username, source, now)

        user = self.store.get_user_by_name(username)
        # 即使用户不存在也走一次哈希校验逻辑的等价耗时由 verify 自身保证；
        # 对外错误信息统一为 invalid_credentials
        ok = bool(user) and not user.disabled and verify_password(
            password, user.password_hash  # type: ignore[union-attr]
        )
        if not ok:
            self.limiter.record_failure(username, source, now)
            logger.warning(
                "login failed username=%s source=%s -> invalid_credentials",
                redact(username), source,
            )
            from app.errors import AuthError, ErrorCode
            raise AuthError(ErrorCode.INVALID_CREDENTIALS)

        session_id = secrets.token_urlsafe(18)
        session = Session(id=session_id, user_id=user.id, created_at=now)
        with self.store.lock:
            self.store.add_session(session)
            access_token, refresh_token = issue_tokens(
                self.store, self.settings, user.id, session_id, now=now,
            )
        self.limiter.record_success(username, source)
        logger.info(
            "login ok user_id=%s session_id=%s source=%s",
            user.id, session_id, source,
        )
        return LoginResult(access_token, refresh_token, user, session_id)

    # ---- 注销 ----
    def logout(self, refresh_token: str | None, access_token: str | None) -> None:
        """优先按刷新令牌吊销整族；也尽力吊销访问令牌登记。"""
        from app.errors import AuthError, ErrorCode
        from app.security import digest_token
        from app.tokens import parse_access_token

        if refresh_token:
            rec = self.store.get_refresh(digest_token(refresh_token))
            if rec is not None:
                revoke_family_tree(self.store, rec.family_id, "logout")
            else:
                logger.info("logout: refresh token not recognized")
        if access_token:
            try:
                payload = parse_access_token(access_token, self.settings)
                self.store.revoke_access(payload["jti"], "logout")
                sess = self.store.get_session(payload["sid"])
                if sess is not None and not sess.revoked:
                    # 仅访问令牌时也终结会话，保证旧凭证立刻失效
                    sess.revoked = True
                    sess.revoke_reason = "logout"
                    self.store.revoke_session_accesses(sess.id, "logout")
            except AuthError:
                pass  # 令牌已失效无需报错

    # ---- 刷新 ----
    def refresh(self, raw_refresh: str, now: float | None = None):
        """令牌旋转（并发互斥与重放检测由 tokens 层在存储锁内保证）。"""
        return rotate_refresh(self.store, self.settings, raw_refresh, now)

    # ---- 鉴权 ----
    def authenticate(self, access_token: str):
        return verify_access(self.store, access_token, self.settings)

    def authorize(self, user: User, action: str,
                  resource: Resource | None) -> Decision:
        return decide(user, action, resource)

    def authorize_resource(self, user: User, action: str,
                           resource_id: str, now: float | None = None
                           ) -> tuple[Resource | None, Decision]:
        """资源类动作的统一判定入口（read/update/delete 共用，不另起一套）。

        在同一把存储锁内取"资源 + 当前有效协作授权"快照后再判定，
        因此撤销/到期与读改写请求之间没有放行窗口：
        临界区内看到的授权状态即本次判定的唯一依据。
        """
        now = time.time() if now is None else now
        with self.store.lock:
            resource = self.store.get_resource(resource_id)
            grants = (
                self.store.active_grants_for(resource_id, now)
                if resource is not None else None
            )
            decision = decide(user, action, resource, grants)
        return resource, decision

    # ---- 资源修改 / 删除（与读取同一判定规则，不存在与无权同形 404）----
    def update_resource(self, actor: User, resource_id: str,
                        kind: str, now: float | None = None
                        ) -> tuple[Resource, Decision]:
        resource, decision = self.authorize_resource(
            actor, "resource:update", resource_id, now)
        if resource is None or not decision.allowed:
            raise AuthError(ErrorCode.NOT_FOUND)
        resource.kind = kind
        logger.info(
            "resource updated actor=%s resource_id=%s reason=%s",
            actor.id, resource_id, decision.reason,
        )
        return resource, decision

    def delete_resource(self, actor: User, resource_id: str,
                        now: float | None = None) -> Decision:
        resource, decision = self.authorize_resource(
            actor, "resource:delete", resource_id, now)
        if resource is None or not decision.allowed:
            raise AuthError(ErrorCode.NOT_FOUND)
        # 级联清除该资源全部协作授权
        self.store.delete_resource(resource_id)
        logger.info(
            "resource deleted actor=%s resource_id=%s reason=%s",
            actor.id, resource_id, decision.reason,
        )
        return decision

    # ---- 协作授权管理 ----
    def list_grants(self, actor: User, resource_id: str,
                     now: float | None = None) -> list[Grant]:
        """查看资源的有效授权：仅属主或具管理权限（admin/显式 resource:share）者。"""
        now = time.time() if now is None else now
        with self.store.lock:
            resource = self.store.get_resource(resource_id)
            allowed = resource is not None and decide(
                actor, "resource:share", resource, log=False).allowed
            if resource is None or not allowed:
                # 不存在与无权查看同形，防止借授权端点探测资源
                raise AuthError(ErrorCode.NOT_FOUND)
            return self.store.active_grants_for(resource_id, now)

    def grant(self, actor: User, resource_id: str, grantee_name: str,
               actions: list[str], expires_in: int,
               now: float | None = None) -> Grant:
        """新增/续期协作授权（幂等）。

        - 同一 (资源, 被授权人) 当前授权仍有效时反复授权：动作集合并、
          有效期取更远者，不新增授权条目、不重复计数，不受上限拦截。
        - 新被授权人，以及对"已到期 / 已整条撤销"的账号重新授权：
          一律视为占用一个新的有效名额，按同一个上限口径判断
          （active_grant_count 只数未撤销且未到期的授权，旧的失效记录
          不占名额）；达到上限明确抛出 GRANT_LIMIT_EXCEEDED。
        - "校验属主/管理权限 -> 校验参数 -> 计数上限 -> 写入"在同一把
          存储锁内一次完成，上限检查先于任何写入，因此被拒绝时不会留下
          新的有效授权，也不会改动任何既有授权；与并发撤销/读改写互斥，
          有效授权数在任何串行化交错下都不会超过上限。
        """
        now = time.time() if now is None else now
        wanted = set(actions)
        if not wanted or not wanted <= GRANTABLE_ACTIONS:
            raise AuthError(
                ErrorCode.INVALID_GRANT,
                "actions must be a non-empty subset of "
                "resource:read/resource:update/resource:delete",
            )
        if expires_in <= 0 or expires_in > self.settings.grant_max_ttl:
            raise AuthError(
                ErrorCode.INVALID_GRANT,
                f"expires_in must be in 1..{self.settings.grant_max_ttl} seconds",
            )

        with self.store.lock:
            resource = self.store.get_resource(resource_id)
            if resource is None or not decide(
                    actor, "resource:share", resource, log=False).allowed:
                raise AuthError(ErrorCode.NOT_FOUND)
            grantee = self.store.get_user_by_name(grantee_name)
            if grantee is None or grantee.disabled:
                raise AuthError(
                    ErrorCode.INVALID_GRANT, "grantee account unavailable")
            if grantee.id == resource.owner_id:
                raise AuthError(
                    ErrorCode.INVALID_GRANT,
                    "owner already holds full access to own resource",
                )

            expires_at = now + expires_in
            existing = self.store.get_grant(resource_id, grantee.id)
            is_active = (
                existing is not None
                and not existing.revoked
                and existing.expires_at > now
            )
            if is_active:
                # 幂等续期：同一被授权人的有效授权原地续期/扩动作，
                # 不新增条目、不重复计数，永远不受上限拦截。
                existing.actions |= wanted
                existing.expires_at = max(existing.expires_at, expires_at)
                grant = existing
            else:
                # 新被授权人，或该账号此前的授权已到期/已撤销后重新授权：
                # 统一按"新增一个有效名额"处理，用同一个上限口径判断。
                # active_grant_count 只数未撤销且未到期的记录，因此已失效的
                # 旧记录本身不占名额；名额被其他人占满时重新授权必须明确拒绝。
                # 检查在任何写入之前进行，被拒绝时旧记录与其它授权原样保留。
                active = self.store.active_grant_count(resource_id, now)
                if active >= self.settings.grant_max_active_per_resource:
                    raise AuthError(
                        ErrorCode.GRANT_LIMIT_EXCEEDED,
                        f"resource {resource_id} already has {active} active grants "
                        f"(limit {self.settings.grant_max_active_per_resource})",
                        extra={"limit": self.settings.grant_max_active_per_resource,
                                "active": active},
                    )
                grant = Grant(
                    resource_id=resource_id, grantee_id=grantee.id,
                    actions=set(wanted), granted_at=now, expires_at=expires_at,
                )
                self.store.put_grant(grant)

        logger.info(
            "collaboration grant actor=%s resource_id=%s grantee=%s actions=%s "
            "expires_at=%.0f",
            actor.id, resource_id, grantee.id, ",".join(sorted(grant.actions)),
            grant.expires_at,
        )
        return grant

    def revoke_grant(self, actor: User, resource_id: str,
                      grantee_name: str, actions: list[str] | None = None,
                      now: float | None = None) -> None:
        """撤销协作授权（幂等）。

        - actions 给定时只摘除其中动作；动作集清空（或不给 actions）则整条撤销。
        - 撤销在存储锁内完成并对后续判定立即生效：已经持有访问令牌的
          被授权人下一次请求即被拒，无需重新登录（令牌不含授权快照）。
        - 对无权调用方与不存在资源/授权统一 404，不暴露存在性；
          撤销一个本就不存在的授权视为成功（幂等语义仅对有权管理的调用方）。
        """
        now = time.time() if now is None else now
        dropped = set(actions) if actions is not None else None
        if dropped is not None and not dropped <= GRANTABLE_ACTIONS:
            raise AuthError(
                ErrorCode.INVALID_GRANT, "unknown action in revocation list")

        with self.store.lock:
            resource = self.store.get_resource(resource_id)
            if resource is None or not decide(
                    actor, "resource:share", resource, log=False).allowed:
                raise AuthError(ErrorCode.NOT_FOUND)
            grantee = self.store.get_user_by_name(grantee_name)
            if grantee is None:
                raise AuthError(ErrorCode.NOT_FOUND)
            grant = self.store.get_grant(resource_id, grantee.id)
            if grant is None or grant.revoked or grant.expires_at <= now:
                logger.info(
                    "revoke grant noop actor=%s resource_id=%s grantee=%s "
                    "(no active grant)",
                    actor.id, resource_id, grantee.id,
                )
                return
            if dropped is None:
                grant.actions.clear()
            else:
                grant.actions -= dropped
            if not grant.actions:
                grant.revoked = True
                grant.revoked_at = now

        logger.info(
            "collaboration grant revoked actor=%s resource_id=%s grantee=%s "
            "remaining=%s",
            actor.id, resource_id, grantee.id,
            ",".join(sorted(grant.actions)) if grant.actions else "<none>",
        )

    # ---- 权限即时变更 ----
    def change_role(self, actor: User, user_id: str, new_role: Role) -> User:
        """管理员变更角色：即时生效并立即吊销目标用户现存访问令牌。

        访问令牌无内嵌权限快照，下一次请求即按新角色判定；
        现存令牌一律吊销，强制其用刷新凭证换取新令牌，确保变更立即全面生效。
        """
        from app.errors import AuthError, ErrorCode

        actor_decision = decide(actor, "user:change_role", None)
        if not actor_decision.allowed:
            raise AuthError(ErrorCode.FORBIDDEN, actor_decision.reason)
        target = self.store.get_user(user_id)
        if target is None:
            # 对未授权/不存在统一口径，避免枚举
            raise AuthError(ErrorCode.NOT_FOUND)
        old = target.role
        target.role = new_role
        revoked = self.store.revoke_user_accesses(
            user_id, f"role changed {old.value}->{new_role.value}"
        )
        logger.info(
            "role changed actor=%s target=%s %s->%s access_tokens_revoked=%d",
            actor.id, user_id, old.value, new_role.value, revoked,
        )
        return target


def seed_demo_data(store: Store) -> None:
    """写入演示账号（admin/editor/viewer，密码均为用户名+'-pw'）与示例资源。"""
    demo = [
        ("u_admin", "admin", Role.ADMIN),
        ("u_editor", "editor", Role.EDITOR),
        ("u_viewer", "viewer", Role.VIEWER),
    ]
    for uid, name, role in demo:
        if store.get_user(uid) is None:
            store.add_user(User(
                id=uid, username=name,
                password_hash=hash_password(f"{name}-pw"),
                role=role,
            ))
    if store.get_resource("doc-1") is None:
        store.add_resource(Resource(id="doc-1", owner_id="u_viewer", kind="doc"))
    if store.get_resource("doc-2") is None:
        store.add_resource(Resource(id="doc-2", owner_id="u_editor", kind="doc"))
