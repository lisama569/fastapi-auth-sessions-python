"""进程内存储：线程安全；单测与模板运行无需外部依赖。

所有写操作在同一把 RLock 下完成，保证"检查-旋转-写入"这类
复合操作可由上层原子执行（配合 token 级互斥）。
"""

from __future__ import annotations

import threading

from app.models import (
    AccessRecord,
    Grant,
    RefreshRecord,
    Resource,
    Session,
    User,
)

GrantKey = tuple[str, str, str]  # (resource_id, grantee_id, action)


class Store:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, User] = {}
        self.users_by_name: dict[str, str] = {}
        self.sessions: dict[str, Session] = {}
        self.accesses: dict[str, AccessRecord] = {}
        self.refreshes: dict[str, RefreshRecord] = {}   # token_hash -> record
        self.families: dict[str, list[str]] = {}        # family_id -> [token_hash]
        self.resources: dict[str, Resource] = {}
        # 协作授权：(resource_id, grantee_id, action) -> Grant
        self.grants: dict[GrantKey, Grant] = {}

    # ---- 用户 ----
    def add_user(self, user: User) -> None:
        with self.lock:
            self.users[user.id] = user
            self.users_by_name[user.username] = user.id

    def get_user_by_name(self, username: str) -> User | None:
        with self.lock:
            uid = self.users_by_name.get(username)
            return self.users.get(uid) if uid is not None else None

    def get_user(self, user_id: str) -> User | None:
        with self.lock:
            return self.users.get(user_id)

    # ---- 会话 ----
    def add_session(self, session: Session) -> None:
        with self.lock:
            self.sessions[session.id] = session

    def get_session(self, session_id: str) -> Session | None:
        with self.lock:
            return self.sessions.get(session_id)

    # ---- 访问令牌 ----
    def add_access(self, record: AccessRecord) -> None:
        with self.lock:
            self.accesses[record.jti] = record

    def get_access(self, jti: str) -> AccessRecord | None:
        with self.lock:
            return self.accesses.get(jti)

    def revoke_access(self, jti: str, reason: str) -> bool:
        with self.lock:
            rec = self.accesses.get(jti)
            if rec is None or rec.revoked:
                return False
            rec.revoked = True
            return True

    def revoke_session_accesses(self, session_id: str, reason: str) -> int:
        """吊销某会话下所有未吊销的访问令牌，返回吊销数量。"""
        with self.lock:
            count = 0
            for rec in self.accesses.values():
                if rec.session_id == session_id and not rec.revoked:
                    rec.revoked = True
                    count += 1
            return count

    def revoke_user_accesses(self, user_id: str, reason: str) -> int:
        """权限/角色变更后立即吊销该用户全部现存访问令牌。"""
        with self.lock:
            count = 0
            for rec in self.accesses.values():
                if rec.user_id == user_id and not rec.revoked:
                    rec.revoked = True
                    count += 1
            return count

    # ---- 刷新令牌 ----
    def add_refresh(self, record: RefreshRecord) -> None:
        with self.lock:
            self.refreshes[record.token_hash] = record
            self.families.setdefault(record.family_id, []).append(record.token_hash)

    def get_refresh(self, token_hash: str) -> RefreshRecord | None:
        with self.lock:
            return self.refreshes.get(token_hash)

    def family_hashes(self, family_id: str) -> list[str]:
        with self.lock:
            return list(self.families.get(family_id, ()))

    def revoke_family(self, family_id: str, reason: str) -> None:
        """吊销整条刷新族（盗用检测/注销）。"""
        with self.lock:
            for h in self.families.get(family_id, ()):
                rec = self.refreshes.get(h)
                if rec is not None:
                    rec.revoked = True

    # ---- 资源 ----
    def add_resource(self, resource: Resource) -> None:
        with self.lock:
            self.resources[resource.id] = resource

    def get_resource(self, resource_id: str) -> Resource | None:
        with self.lock:
            return self.resources.get(resource_id)

    def delete_resource(self, resource_id: str) -> bool:
        """删除资源并清除其全部授权记录；返回是否命中。"""
        with self.lock:
            existed = self.resources.pop(resource_id, None) is not None
            dead = [k for k in self.grants if k[0] == resource_id]
            for k in dead:
                self.grants.pop(k, None)
            return existed

    # ---- 协作授权 ----
    # 所有方法仅做存储原语；调用方须在持有 store.lock 时编排
    # “查资源 -> 判定管理权 -> 查/计数 -> 写”这一类复合操作，
    # 与刷新令牌旋转使用同一把锁，保证并发结果确定。
    def get_grant(self, resource_id: str, grantee_id: str,
                  action: str) -> Grant | None:
        with self.lock:
            return self.grants.get((resource_id, grantee_id, action))

    def put_grant(self, grant: Grant) -> None:
        with self.lock:
            self.grants[(grant.resource_id, grant.grantee_id,
                         grant.action)] = grant

    def list_grants_for(self, resource_id: str) -> list[Grant]:
        with self.lock:
            return [g for g in self.grants.values() if g.resource_id == resource_id]

    def grants_for_user(self, resource_id: str, grantee_id: str) -> list[Grant]:
        with self.lock:
            return [g for g in self.grants.values()
                    if g.resource_id == resource_id and g.grantee_id == grantee_id]

    def revoke_grant(self, resource_id: str, grantee_id: str, action: str,
                     now: float) -> bool:
        """撤销单条授权；不存在或已撤销返回 False（撤销本身幂等）。"""
        with self.lock:
            g = self.grants.get((resource_id, grantee_id, action))
            if g is None or g.revoked:
                return False
            g.revoked = True
            g.revoked_at = now
            return True


store = Store()
