"""密码哈希、令牌随机串与脱敏工具（不引入额外依赖，使用标准库）。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

_PBKDF2_ROUNDS = 200_000


def hash_password(password: str) -> str:
    """pbkdf2-hmac-sha256 加盐哈希，格式 pbkdf2_sha256$rounds$salt$hash。"""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS
    )
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ROUNDS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    """恒定时间校验密码；格式非法时返回 False，不抛出。"""
    try:
        algo, rounds_b64, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_b64)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, rounds
    )
    return hmac.compare_digest(candidate, expected)


def new_token(nbytes: int = 32) -> str:
    """生成高强度随机刷新令牌（只返回明文一次，库存哈希）。"""
    return secrets.token_urlsafe(nbytes)


def digest_token(token: str) -> str:
    """计算令牌的 sha256 摘要，用于库存比对（明文不落库）。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sign(data: bytes, secret: str) -> str:
    """计算 hmac-sha256 签名（hex）。"""
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


def redact(value: str | None, keep: int = 4) -> str:
    """日志脱敏：仅保留少量尾部字符；空值显示为 <none>。"""
    if not value:
        return "<none>"
    if len(value) <= keep:
        return "***"
    return "***" + value[-keep:]


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
