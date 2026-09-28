"""应用入口：保持模板原有启动方式（fastapi dev main.py / uvicorn main:app）。"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.errors import ERROR_STATUS, AuthError, ErrorCode
from app.routes import router
from app.services import AuthService, seed_demo_data
from app.store import store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("auth_sessions")

settings = get_settings()

app = FastAPI(title="FastAPI Auth & Sessions Template", version="0.1.0")

# CORS 默认不放行任何来源；仅在显式配置时启用（凭证模式不允许 *）
if settings.cors_allow_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allow_origins),
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

app.state.settings = settings
app.state.store = store
app.state.service = AuthService(store, settings)
seed_demo_data(store)

app.include_router(router)


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    """统一输出稳定错误码；日志只记码/路径/来源，绝不记录密码或令牌。"""
    status = ERROR_STATUS[exc.code]
    headers: dict[str, str] = {}
    detail = {"code": exc.code.value, "message": str(exc)}
    if exc.code is ErrorCode.RATE_LIMITED:
        retry = exc.extra.get("retry_after")
        if retry:
            headers["Retry-After"] = str(retry)
    logger.warning(
        "auth reject path=%s code=%s status=%d",
        request.url.path, exc.code.value, status,
    )
    return JSONResponse(
        status_code=status, content={"error": detail}, headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request,
                             exc: RequestValidationError) -> JSONResponse:
    # 校验错误同样不回显输入原文，仅回字段级原因
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "validation_error", "details": exc.errors()}},
    )


@app.get("/")
def read_root():
    return {"status": "ok", "service": "fastapi-auth-sessions"}
