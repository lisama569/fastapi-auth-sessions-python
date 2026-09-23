"""应用服务层：登录/注销/刷新/访问判定的编排，跨入口复用同一套规则。

HTTP 层（Header / Cookie）只负责取令牌，所有判定都走这里，
保证不同调用入口在同一套鉴权规则下得到一致结果。
"""

from __future__ import annotations

import logging
import secrets
import time

from app.config import Settings
from app.models import Decision, Resource, Role, Session, User
from app.policy import decide
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
