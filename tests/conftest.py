"""Shared fixtures: isolated app/store/client and logging capture."""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.app import create_app
from app.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        jwt_secret="unit-test-secret-key-0123456789abcdef",
        cookie_secure=False,          # TestClient is plain HTTP
        cookie_samesite="lax",
        login_max_attempts=3,
        login_backoff_base_seconds=1.0,
        login_backoff_multiplier=2.0,
        login_backoff_max_seconds=60.0,
        login_window_seconds=900.0,
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=3600,
    )


@pytest.fixture
def app(settings):
    return create_app(settings=settings, seed=True)


@pytest.fixture
def store(app):
    return app.state.store


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def audit_records(caplog):
    """Capture structured audit records and print inputs + decision basis.

    Tests can inspect ``records`` and the captured lines are printed by
    pytest on failure so the input and the decision basis are visible.
    """
    caplog.set_level(logging.INFO, logger="auth.audit")
    return caplog


def login(client, username: str, password: str):
    """Log in and return (access_token, raw_refresh_token, response)."""
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return (
        response.json()["access_token"],
        response.cookies.get(client.app.state.settings.refresh_cookie_name),
        response,
    )


def auth_header(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def helper():
    class _H:
        login = staticmethod(login)
        auth_header = staticmethod(auth_header)

    return _H
