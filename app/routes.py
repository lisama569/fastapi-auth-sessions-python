"""HTTP 入口：登录/刷新/注销/资源/管理；所有入口共用 AuthService 规则。"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from app.deps import (
    client_ip,
    extract_refresh_token,
    get_current_user,
    get_service,
)
from app.errors import AuthError, ErrorCode
from app.models import Resource, Role
from app.services import AuthService

logger = logging.getLogger("auth_sessions.routes")

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RefreshBody(BaseModel):
    refresh_token: str | None = None


class LogoutBody(BaseModel):
    refresh_token: str | None = None


class CreateResourceBody(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    kind: str = Field(default="doc", max_length=32)


class RoleBody(BaseModel):
    role: Role


def _set_session_cookies(response: Response, service: AuthService,
                         access: str, refresh: str) -> None:
    """写入默认安全的会话 Cookie：HttpOnly + SameSite + 可选 Secure。"""
    s = service.settings
    common = {
        "path": s.cookie_path,
        "httponly": True,
        "samesite": s.cookie_samesite,
        "secure": s.cookie_secure,
    }
    response.set_cookie(
        s.cookie_name_access, access,
        max_age=s.access_token_ttl, **common,
    )
    response.set_cookie(
        s.cookie_name_refresh, refresh,
        max_age=s.refresh_token_ttl, **common,
    )


def _clear_session_cookies(response: Response, service: AuthService) -> None:
    s = service.settings
    response.delete_cookie(s.cookie_name_access, path=s.cookie_path)
    response.delete_cookie(s.cookie_name_refresh, path=s.cookie_path)


def _public_user(user) -> dict:
    """用户对外视图：绝不包含密码哈希等敏感字段。"""
    return {"id": user.id, "username": user.username, "role": user.role.value}


@router.post("/auth/login")
async def login(request: Request, body: LoginBody, response: Response,
                service: AuthService = Depends(get_service)):
    result = service.login(body.username, body.password, client_ip(request))
    _set_session_cookies(response, service,
                         result.access_token, result.refresh_token)
    # 响应体中令牌仅用于非浏览器调用方；生产可按需关闭
    return {
        "token_type": "bearer",
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "user": _public_user(result.user),
        "expires_in": service.settings.access_token_ttl,
    }


@router.post("/auth/refresh")
async def refresh(request: Request, response: Response,
                  body: RefreshBody | None = None,
                  service: AuthService = Depends(get_service)):
    request.state.json_body = body.model_dump() if body is not None else {}
    raw = extract_refresh_token(request)
    access, new_refresh = service.refresh(raw)
    _set_session_cookies(response, service, access, new_refresh)
    return {
        "token_type": "bearer",
        "access_token": access,
        "refresh_token": new_refresh,
        "expires_in": service.settings.access_token_ttl,
    }


@router.post("/auth/logout")
async def logout(request: Request, response: Response,
                 body: LogoutBody | None = None,
                 service: AuthService = Depends(get_service)):
    data = body.model_dump() if body is not None else {}
    refresh_cookie = request.cookies.get(service.settings.cookie_name_refresh)
    access_cookie = request.cookies.get(service.settings.cookie_name_access)
    service.logout(
        refresh_cookie or data.get("refresh_token"),
        access_cookie,
    )
    _clear_session_cookies(response, service)
    return {"status": "logged_out"}


@router.get("/me")
async def me(request: Request, user=Depends(get_current_user)):
    return _public_user(user)


@router.get("/resources/{resource_id}")
async def read_resource(resource_id: str, request: Request,
                        user=Depends(get_current_user),
                        service: AuthService = Depends(get_service)):
    resource = service.store.get_resource(resource_id)
    decision = service.authorize(user, "resource:read", resource)
    # 关键防探测设计：资源不存在与无权访问对调用方完全同形（404, not_found），
    # 不泄露资源是否存在
    if resource is None or not decision.allowed:
        logger.info(
            "resource read hidden resource_id=%s user_id=%s reason=%s",
            resource_id, user.id,
            "missing" if resource is None else decision.reason,
        )
        raise AuthError(ErrorCode.NOT_FOUND)
    return {
        "id": resource.id,
        "kind": resource.kind,
        "owner_id": resource.owner_id,
        "decision": decision.reason,
    }


@router.post("/resources")
async def create_resource(body: CreateResourceBody, request: Request,
                          user=Depends(get_current_user),
                          service: AuthService = Depends(get_service)):
    # 创建动作无具体资源上下文，策略按角色/显式权限判定（默认拒绝）
    decision = service.authorize(user, "resource:create", None)
    if not decision.allowed:
        raise AuthError(ErrorCode.FORBIDDEN, decision.reason)
    resource = Resource(id=body.id, owner_id=user.id, kind=body.kind)
    service.store.add_resource(resource)
    return {"id": resource.id, "owner_id": resource.owner_id,
            "kind": resource.kind, "decision": decision.reason}


@router.post("/admin/users/{user_id}/role")
async def change_role(user_id: str, body: RoleBody,
                      user=Depends(get_current_user),
                      service: AuthService = Depends(get_service)):
    target = service.change_role(user, user_id, body.role)
    return {"id": target.id, "role": target.role.value}
