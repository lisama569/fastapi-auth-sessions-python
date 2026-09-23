"""FastAPI 依赖：从 Authorization 头或 Cookie 统一取令牌，复用 AuthService。

两种入口共用同一提取/校验逻辑，因此 Header 调用方与浏览器 Cookie
会话在同一套规则下得到完全一致的判定。
"""

from __future__ import annotations

from fastapi import Request

from app.errors import AuthError, ErrorCode
from app.services import AuthService


def get_service(request: Request) -> AuthService:
    """获取当前请求使用的 AuthService（测试可覆盖 app.state.service）。"""
    service = getattr(request.app.state, "service", None)
    if service is None:  # pragma: no cover - 防御性分支
        raise AuthError(ErrorCode.UNAUTHENTICATED, "service not configured")
    return service


def client_ip(request: Request) -> str:
    """来源标识：优先取反代链路上的首个 X-Forwarded-For，回退到连接对端。"""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def extract_access_token(request: Request) -> str:
    """Bearer 头优先，其次访问令牌 Cookie；均无 -> UNAUTHENTICATED。"""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    cookie_name = get_service(request).settings.cookie_name_access
    token = request.cookies.get(cookie_name, "")
    if token:
        return token
    raise AuthError(ErrorCode.UNAUTHENTICATED, "missing access token")


def extract_refresh_token(request: Request) -> str:
    """刷新令牌 Cookie 优先（浏览器场景），其次 JSON 字段 refresh_token。"""
    cookie_name = get_service(request).settings.cookie_name_refresh
    token = request.cookies.get(cookie_name, "")
    if token:
        return token
    body = getattr(request.state, "json_body", None)
    if isinstance(body, dict) and body.get("refresh_token"):
        return str(body["refresh_token"])
    raise AuthError(ErrorCode.UNAUTHENTICATED, "missing refresh token")


async def get_current_user(request: Request) :
    """解析访问令牌并完成服务端鉴权，返回 User（异常由全局处理器映射）。"""
    service = get_service(request)
    token = extract_access_token(request)
    user, _session, _record = service.authenticate(token)
    request.state.user_id = user.id
    return user
