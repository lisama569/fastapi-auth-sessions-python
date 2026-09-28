"""领域模型：用户、会话、刷新令牌族、资源与策略判定结果。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"
    # 无任何角色矩阵权限的普通账号：只能依赖属主身份或协作授权访问资源
    GUEST = "guest"


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    role: Role
    extra_permissions: set[str] = field(default_factory=set)
    disabled: bool = False


@dataclass
class Session:
    """一次登录对应一个会话；注销/被盗用检测时整族终结。"""

    id: str
    user_id: str
    created_at: float
    revoked: bool = False
    revoke_reason: str | None = None


@dataclass
class RefreshRecord:
    """刷新令牌族中的一次签发记录。

    - rotated: 已被新一代凭证替换（再次出现即重放）
    - revoked: 主动注销或盗用检测导致的吊销
    - next_hash: 旋转链路上的下一代令牌哈希
    """

    family_id: str
    token_hash: str
    issued_at: float
    expires_at: float
    rotated: bool = False
    revoked: bool = False
    next_hash: str | None = None


@dataclass
class AccessRecord:
    """访问令牌在服务端的登记，用于即时吊销与权限即时生效。

    每次请求都回查此记录与会话/用户状态，因此角色变更与吊销
    无需等待令牌自然过期即可生效。
    """

    jti: str
    session_id: str
    user_id: str
    issued_at: float = 0.0
    expires_at: float = 0.0
    revoked: bool = False


@dataclass
class Resource:
    id: str
    owner_id: str
    kind: str = "doc"


@dataclass
class Grant:
    """资源协作授权：属主把自己资源的部分动作临时授予指定账号。

    - actions: 被授权的资源动作集合（resource:read/update/delete）
    - expires_at: 绝对失效时间戳；每次请求实时比较，到期自动失效，无需重登
    - revoked: 撤销后立即失效；判定/撤销都在存储锁内完成，与读写互斥
    """

    resource_id: str
    grantee_id: str
    actions: set[str] = field(default_factory=set)
    granted_at: float = 0.0
    expires_at: float = 0.0
    revoked: bool = False
    revoked_at: float | None = None


@dataclass
class Decision:
    allowed: bool
    reason: str
