"""配置项：令牌、Cookie、跨域、限流参数集中管理，默认值走安全基线。

可通过同名环境变量覆盖（布尔用 1/true/yes，元组用逗号分隔）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def _tuple_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    # 访问 / 刷新令牌生命周期（秒）
    access_token_ttl: int = 900
    refresh_token_ttl: int = 60 * 60 * 24 * 14

    # 签名密钥；生产环境必须通过环境变量覆盖
    token_secret: str = "change-me-in-production"
    token_issuer: str = "fastapi-auth-sessions"

    # 会话 Cookie（默认安全：HttpOnly/SameSite=Lax；生产应置 AUTH_COOKIE_SECURE=1）
    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    cookie_name_access: str = "sid_access"
    cookie_name_refresh: str = "sid_refresh"
    cookie_path: str = "/"

    # CORS：默认不放行任何跨域来源，需显式配置
    cors_allow_origins: tuple[str, ...] = field(default_factory=tuple)
    cors_allow_credentials: bool = True

    # 登录限流：窗口内最大失败次数，命中后基础锁定（秒），逐次翻倍
    login_rate_window: int = 300
    login_max_failures: int = 5
    login_base_lockout: int = 15
    login_max_lockout: int = 300

    # 刷新重放是否吊销整条会话族（盗用检测）
    revoke_family_on_replay: bool = True


def get_settings() -> Settings:
    """从环境变量构造 Settings，缺省值即安全基线。"""
    return Settings(
        access_token_ttl=_int_env("AUTH_ACCESS_TTL", 900),
        refresh_token_ttl=_int_env("AUTH_REFRESH_TTL", 60 * 60 * 24 * 14),
        token_secret=os.environ.get("AUTH_TOKEN_SECRET", "change-me-in-production"),
        token_issuer=os.environ.get("AUTH_TOKEN_ISSUER", "fastapi-auth-sessions"),
        cookie_secure=_bool_env("AUTH_COOKIE_SECURE", False),
        cookie_samesite=os.environ.get("AUTH_COOKIE_SAMESITE", "lax"),
        cors_allow_origins=_tuple_env("AUTH_CORS_ORIGINS", ()),
        cors_allow_credentials=_bool_env("AUTH_CORS_CREDENTIALS", True),
        login_rate_window=_int_env("AUTH_LOGIN_WINDOW", 300),
        login_max_failures=_int_env("AUTH_LOGIN_MAX_FAILURES", 5),
        login_base_lockout=_int_env("AUTH_LOGIN_BASE_LOCKOUT", 15),
        login_max_lockout=_int_env("AUTH_LOGIN_MAX_LOCKOUT", 300),
        revoke_family_on_replay=_bool_env("AUTH_REVOKE_FAMILY_ON_REPLAY", True),
    )
