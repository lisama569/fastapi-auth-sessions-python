"""Configuration with secure defaults, overridable via environment variables.

Environment variables use the ``AUTH_`` prefix, e.g.
``AUTH_ACCESS_TOKEN_TTL_SECONDS=900``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUTH_",
        env_file=".env",
        extra="ignore",
    )

    # --- Token lifetimes -------------------------------------------------
    access_token_ttl_seconds: int = 900           # 15 minutes
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 7  # 7 days

    # --- Secret used to sign access tokens (JWT HS256) -------------------
    # A random per-process default is intentionally *insecure across
    # restarts*: deployments MUST set AUTH_JWT_SECRET explicitly.
    jwt_secret: str = ""
    jwt_issuer: str = "fastapi-auth-sessions"
    jwt_algorithm: str = "HS256"

    # --- Refresh cookie --------------------------------------------------
    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_path: str = "/auth"
    cookie_secure: bool = True
    cookie_samesite: str = "strict"   # strict | lax | none
    cookie_domain: str | None = None

    # --- CORS ------------------------------------------------------------
    # Empty list = no cross-origin allowed. Explicit opt-in only.
    cors_allow_origins: list[str] = []
    cors_allow_credentials: bool = True

    # --- Login rate limiting / backoff -----------------------------------
    login_max_attempts: int = 5
    # After the threshold is reached, wait base * multiplier**(strikes-1).
    login_backoff_base_seconds: float = 1.0
    login_backoff_multiplier: float = 2.0
    login_backoff_max_seconds: float = 300.0
    # A window without failures after which the failure counter resets.
    login_window_seconds: float = 900.0

    # --- Logging ---------------------------------------------------------
    log_level: str = "INFO"
    audit_log_inputs: bool = True


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.jwt_secret:
        # Per-process ephemeral secret; keeps the template runnable out of
        # the box while invalidating tokens after every restart.
        import secrets

        object.__setattr__(settings, "jwt_secret", secrets.token_urlsafe(48))
    return settings
