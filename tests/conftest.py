"""测试夹具：每个用例独立 Store/AuthService；捕获策略判定日志以便断言"判定依据"。"""

from __future__ import annotations

import logging

import pytest

from app.config import Settings
from app.services import AuthService, seed_demo_data
from app.store import Store


class DecisionLogHandler(logging.Handler):
    """收集判定日志，测试可断言输入与判定依据。"""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def texts(self) -> list[str]:
        return [self.format(r) for r in self.records]


@pytest.fixture
def settings() -> Settings:
    return Settings(
        login_max_failures=5,
        login_base_lockout=10,
        login_max_lockout=100,
        login_rate_window=300,
    )


@pytest.fixture
def svc(settings: Settings) -> AuthService:
    store = Store()
    seed_demo_data(store)
    return AuthService(store, settings)


@pytest.fixture
def decision_logs(monkeypatch: pytest.MonkeyPatch):
    """把 policy 日志同时收集到内存，并在失败时由 caplog/pytest 打印。"""
    handler = DecisionLogHandler()
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    logger = logging.getLogger("auth_sessions.policy")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    yield handler
    logger.removeHandler(handler)
