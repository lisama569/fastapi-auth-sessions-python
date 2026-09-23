"""Application factory: state, routers, exception handlers, secure CORS."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, get_settings
from app.crypto import hash_password
from app.errors import register_exception_handlers
from app.models import Document, User
from app.ratelimit import LoginRateLimiter
from app.routes_auth import router as auth_router
from app.routes_resources import router as resources_router
from app.store import DataStore


def seed_data(store: DataStore) -> DataStore:
    """Seed demo users/resources so the template is usable out of the box."""
    admin = User(
        id="u-admin",
        username="admin",
        password_hash=hash_password("admin-pass-123"),
        roles={"admin"},
    )
    alice = User(
        id="u-alice",
        username="alice",
        password_hash=hash_password("alice-pass"),
        roles={"editor"},
    )
    bob = User(
        id="u-bob",
        username="bob",
        password_hash=hash_password("bob-pass"),
        roles={"viewer"},
    )
    for user in (admin, alice, bob):
        store.add_user(user)
    store.add_document(
        Document(id="doc-welcome", owner_id="u-alice", title="Welcome",
                 content="Alice's first document")
    )
    return store


def create_app(
    settings: Settings | None = None,
    store: DataStore | None = None,
    *,
    seed: bool = True,
) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))

    app = FastAPI(title="fastapi-auth-sessions-python")
    app.state.settings = settings
    app.state.store = store or DataStore()
    app.state.rate_limiter = LoginRateLimiter(
        max_attempts=settings.login_max_attempts,
        backoff_base=settings.login_backoff_base_seconds,
        backoff_multiplier=settings.login_backoff_multiplier,
        backoff_max=settings.login_backoff_max_seconds,
        window_seconds=settings.login_window_seconds,
    )
    if seed:
        seed_data(app.state.store)

    # CORS: no origins allowed unless explicitly configured. When origins
    # are configured, credentials are permitted and methods are explicit.
    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allow_origins,
            allow_credentials=settings.cors_allow_credentials,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=300,
        )

    register_exception_handlers(app)
    app.include_router(auth_router)
    app.include_router(resources_router)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        # Defense in depth; the API never serves user-controlled HTML.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Cache-Control", "no-store"
        )
        return response

    @app.get("/")
    def read_root():
        return {"status": "ok", "service": "fastapi-auth-sessions"}

    return app
