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

# HTTP 入参用短动作名，服务/策略层统一用 resource:<action> 全限定名
_SHORT_ACTIONS = {
    "read": "resource:read",
    "update": "resource:update",
    "delete": "resource:delete",
}


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


class UpdateResourceBody(BaseModel):
    kind: str = Field(min_length=1, max_length=32)


class GrantBody(BaseModel):
    """新增/续期协作授权；actions 为 read/update/delete 的子集。"""

    username: str = Field(min_length=1, max_length=64)
    actions: list[str] = Field(min_length=1)
    expires_in: int = Field(gt=0)


class RevokeGrantBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    # 省略或为 None 表示整条撤销；给出时只摘除列出的动作
    actions: list[str] | None = None


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
    resource, decision = service.authorize_resource(
        user, "resource:read", resource_id)
    # 关键防探测设计：资源不存在与无权访问对调用方完全同形（404, not_found），
    # 不泄露资源是否存在（含协作授权到期/撤销后的访问）
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


@router.patch("/resources/{resource_id}")
async def update_resource(resource_id: str, body: UpdateResourceBody,
                          request: Request,
                          user=Depends(get_current_user),
                          service: AuthService = Depends(get_service)):
    # 与读取走同一套判定（角色/属主/协作授权）；不存在与无权同形 404
    resource, decision = service.update_resource(user, resource_id, body.kind)
    return {
        "id": resource.id,
        "kind": resource.kind,
        "owner_id": resource.owner_id,
        "decision": decision.reason,
    }


@router.delete("/resources/{resource_id}", status_code=204)
async def delete_resource(resource_id: str, request: Request,
                         user=Depends(get_current_user),
                         service: AuthService = Depends(get_service)):
    service.delete_resource(user, resource_id)
    return Response(status_code=204)


def _public_grant(grant) -> dict:
    """授权对外视图：不含任何令牌/敏感信息。"""
    return {
        "resource_id": grant.resource_id,
        "username": None,  # 由调用处补充（视图层不直接持有用户表）
        "grantee_id": grant.grantee_id,
        "actions": sorted(
            a.removeprefix("resource:") for a in grant.actions
        ),
        "granted_at": int(grant.granted_at),
        "expires_at": int(grant.expires_at),
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


# ---- 资源协作授权 ----
# 路径放在 /resources/{id} 命名空间下；属主或具管理权限（admin 角色、
# 显式 resource:share 权限）才能查看/新增/撤销，其余调用方与资源不存在同形 404。
@router.get("/resources/{resource_id}/grants")
async def list_grants(resource_id: str, request: Request,
                       user=Depends(get_current_user),
                       service: AuthService = Depends(get_service)):
    grants = service.list_grants(user, resource_id)
    items = []
    for grant in grants:
        view = _public_grant(grant)
        grantee = service.store.get_user(grant.grantee_id)
        view["username"] = grantee.username if grantee else None
        items.append(view)
    return {"resource_id": resource_id, "grants": items}


@router.put("/resources/{resource_id}/grants")
async def put_grant(resource_id: str, body: GrantBody, request: Request,
                     user=Depends(get_current_user),
                     service: AuthService = Depends(get_service)):
    actions = [_SHORT_ACTIONS.get(a, a) for a in body.actions]
    grant = service.grant(
        user, resource_id, body.username,
        actions, body.expires_in,
    )
    return _public_grant(grant) | {"username": body.username}


@router.post("/resources/{resource_id}/grants/revoke")
async def revoke_grant(resource_id: str, body: RevokeGrantBody,
                        request: Request,
                        user=Depends(get_current_user),
                        service: AuthService = Depends(get_service)):
    actions = (
        [_SHORT_ACTIONS.get(a, a) for a in body.actions]
        if body.actions is not None else None
    )
    service.revoke_grant(
        user, resource_id, body.username, actions)
    return {"status": "revoked", "resource_id": resource_id,
            "username": body.username}
