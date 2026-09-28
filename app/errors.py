"""可区分的拒绝原因：错误码 -> HTTP 状态码 + 对外信息。

错误码保持稳定且语义互斥，调用方可据此区分：凭证错误、过期、
被吊销、刷新重放、限流、未认证、越权、资源不存在。
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    INVALID_CREDENTIALS = "invalid_credentials"        # 账号/密码错误（提示统一，不暴露账号是否存在）
    UNAUTHENTICATED = "unauthenticated"                # 未携带或无法识别令牌
    ACCESS_TOKEN_EXPIRED = "access_token_expired"      # 访问令牌过期
    ACCESS_TOKEN_REVOKED = "access_token_revoked"      # 访问令牌被吊销（注销/权限变更/会话终结）
    REFRESH_TOKEN_EXPIRED = "refresh_token_expired"    # 刷新令牌过期
    REFRESH_TOKEN_REVOKED = "refresh_token_revoked"    # 刷新令牌被吊销（主动注销/盗用族吊销）
    REFRESH_TOKEN_REPLAY = "refresh_token_replay"      # 已旋转的刷新凭证被再次使用（疑似被盗）
    FORBIDDEN = "forbidden"                            # 已认证但无权限
    NOT_FOUND = "not_found"                            # 资源不存在（或无权查看时同样返回，避免差异暴露）
    RATE_LIMITED = "rate_limited"                      # 登录失败过多，处于退避锁定
    INVALID_GRANT = "invalid_grant"                    # 授权请求非法（给自己授权/未知账号/失效时间非法）
    GRANT_LIMIT_REACHED = "grant_limit_reached"        # 单资源有效授权条数超过上限


class AuthError(Exception):
    """业务鉴权异常，携带稳定错误码用于可区分的拒绝原因。"""

    def __init__(self, code: ErrorCode, message: str | None = None,
                 *, extra: dict | None = None) -> None:
        self.code = code
        self.extra = extra or {}
        super().__init__(message or code.value)


ERROR_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_CREDENTIALS: 401,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.ACCESS_TOKEN_EXPIRED: 401,
    ErrorCode.ACCESS_TOKEN_REVOKED: 401,
    ErrorCode.REFRESH_TOKEN_EXPIRED: 401,
    ErrorCode.REFRESH_TOKEN_REVOKED: 401,
    ErrorCode.REFRESH_TOKEN_REPLAY: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.INVALID_GRANT: 422,
    ErrorCode.GRANT_LIMIT_REACHED: 409,
}
