"""Domain and API models for users, sessions and auth payloads."""

from __future__ import annotations

import time

from pydantic import BaseModel, Field


class User(BaseModel):
    id: str
    username: str
    password_hash: str
    roles: set[str] = Field(default_factory=set)
    permissions: set[str] = Field(default_factory=set)
    disabled: bool = False


class RefreshTokenRecord(BaseModel):
    """Server-side state of a single rotating refresh token."""

    id: str                     # lookup key (hash of presented token)
    family_id: str              # replay chain / session lineage
    session_id: str
    user_id: str
    issued_at: float
    expires_at: float
    revoked: bool = False
    used: bool = False
    replaced_by: str | None = None


class Document(BaseModel):
    id: str
    owner_id: str
    title: str
    content: str = ""


class Session(BaseModel):
    id: str
    user_id: str
    created_at: float
    last_rotated_at: float
    revoked: bool = False
    revoked_reason: str | None = None

    def is_active(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return not self.revoked


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    # Optional: the refresh token may also arrive via cookie.
    refresh_token: str | None = None


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserView(BaseModel):
    """Safe projection of a user: never carries password material."""

    id: str
    username: str
    roles: set[str]
    permissions: set[str]
    disabled: bool

    @classmethod
    def of(cls, user: User) -> UserView:
        return cls(
            id=user.id,
            username=user.username,
            roles=set(user.roles),
            permissions=set(user.permissions),
            disabled=user.disabled,
        )
