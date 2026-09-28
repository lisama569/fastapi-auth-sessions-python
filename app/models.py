"""领域模型：用户、会话、刷新令牌族、资源与策略判定结果。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


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
    title: str = ""


@dataclass
class Grant:
    """资源协作授权：属主把某资源的某一项动作临时授予指定账号。

    - action: 短动作名 read/update/delete（对应 resource:read 等策略动作）
    - expires_at: 明确的失效时刻（epoch 秒）；判定时惰性检查，到点自动失效
    - revoked: 撤销后立即对后续所有请求生效（判定每次回查服务端当前状态）
    主键为 (resource_id, grantee_id, action)，重复授权即幂等更新该行。
    """

    resource_id: str
    grantee_id: str
    action: str
    expires_at: float
    granted_by: str
    granted_at: float
    revoked: bool = False
    revoked_at: float | None = None

    def is_active(self, now: float) -> bool:
        return not self.revoked and self.expires_at > now


@dataclass
class Decision:
    allowed: bool
    reason: str
    # 结构化放行来源：disabled / permission / role / owner / grant / deny
    via: str = "deny"
