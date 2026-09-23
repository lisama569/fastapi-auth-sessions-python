# fastapi-auth-sessions-python

一个可复用的 FastAPI 认证 / 会话 / 访问控制模板。所有调用入口（Bearer 访问令牌、
HttpOnly Cookie 刷新令牌、管理接口、示例资源接口）共用同一套鉴权规则，拒绝结果
带**可区分的机器可读错误码**，并通过结构化审计日志解释每次判定的输入与依据。

## 能力总览

- **登录与双令牌签发**：短寿命 JWT 访问令牌（HS256，默认 15 分钟）+ 不透明
  刷新令牌（仅存 SHA-256 摘要，默认 7 天，HttpOnly Cookie）。
- **刷新轮换与重放检测**：刷新令牌一次性使用，轮换是原子操作；旧凭证被再次
  提交即判定为重放，**整条令牌族（含已轮换出的新凭证）立即吊销**（盗用响应）。
- **即时生效的状态校验**：每次请求都回查会话状态与用户**安全版本号**。注销 /
  管理员吊销立即失效；角色、权限、禁用状态变更后提升安全版本号，已签发的访问
  令牌在下一次请求即按新规则被拒，无需等待过期或重新登录。
- **可区分的拒绝原因**：过期、被吊销、重放、凭证缺失/损坏、签名错误、用户被
  禁用、限流等分别返回不同 `error.code`（见下表）。
- **RBAC + 资源属性判定**：角色聚合权限、用户可直接拥有权限；资源型权限还需
  满足属主等属性约束；**默认拒绝**一切未明确允许的操作。
- **不暴露资源存在性**：对已认证但无权的调用方，访问他人/不存在的资源返回
  完全相同的 `404 not_found`。
- **登录限流与指数退避**：按「账号 + 来源 IP」计数，达到阈值后即使密码正确也
  返回 `429` 与 `Retry-After`，退避按乘数指数增长并设上限；安静窗口后重置。
- **安全默认值**：刷新 Cookie 默认 `Secure` + `HttpOnly` + `SameSite=Strict`；
  CORS 默认不允许任何跨域来源，需显式配置；响应带 `nosniff`/`DENY`/`no-store`
  等头；密码用 scrypt 加盐哈希；日志与响应自动脱敏，不出现密码或令牌明文。

## 目录结构

```
app/
  config.py            # 环境变量配置（AUTH_ 前缀），全部安全默认值
  errors.py            # 错误码枚举 + 统一 JSON 错误处理器
  logging_utils.py     # 敏感字段脱敏 + 结构化审计日志（输入/判定/依据）
  crypto.py            # scrypt 密码哈希、令牌级随机 ID（纯标准库）
  models.py            # User / Session / RefreshTokenRecord / Document / DTO
  store.py             # 带锁内存存储：原子轮换、族吊销、安全版本号
  ratelimit.py         # 账号+来源维度的指数退避限流器
  tokens.py            # JWT 签发/校验、实时状态校验、刷新轮换与重放判定
  permissions.py       # 角色/权限/资源约束策略引擎（默认拒绝）
  deps.py              # FastAPI 依赖：主体提取、授权辅助
  routes_auth.py       # /auth/login /refresh /logout /me 与用户安全管理
  routes_resources.py  # /documents 示例：RBAC + 属主约束 + 统一 404
  app.py               # create_app：装配状态、路由、CORS、异常处理器
main.py                # 模板原有入口：app = create_app()
tests/                 # 并发刷新、重放、即时权限变更、限流退避等测试
```

## 快速开始

依赖与启动方式保持模板原样（uv）：

```bash
uv sync
uv run uvicorn main:app --reload
# 或
uv run fastapi dev main.py
```

开箱即有三个演示账号（仅用于本地）：

| 账号  | 密码            | 角色   |
|-------|-----------------|--------|
| admin | `admin-pass-123`| admin  |
| alice | `alice-pass`    | editor |
| bob   | `bob-pass`      | viewer |

### 典型调用

```bash
# 1) 登录（访问令牌在 JSON；刷新令牌在 HttpOnly Cookie）
curl -i -c cookies.txt -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'

# 2) 携带访问令牌访问
curl -H "Authorization: Bearer <access_token>" http://127.0.0.1:8000/auth/me

# 3) 刷新（Cookie 自动带上；也可在 JSON 里传 refresh_token）
curl -i -b cookies.txt -c cookies.txt -X POST http://127.0.0.1:8000/auth/refresh

# 4) 注销（吊销会话与整条刷新令牌族，并清除 Cookie）
curl -b cookies.txt -X POST http://127.0.0.1:8000/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

## 认证与刷新流程

```
登录 ──► 校验密码(scrypt) ──► 建 Session(sv=当前安全版本)
      ├─► JWT 访问令牌 {sub, sid, jti, sv, type=access, iat, exp}
      └─► 不透明刷新令牌（服务端仅存 SHA-256 摘要）+ HttpOnly Cookie

受保护请求 ──► 验签/过期 ──► 用户存在且未禁用 ──► 会话存在且未吊销
          └─► 令牌 sv >= 当前安全版本？  否则按 session_revoked 拒绝

刷新 ──► 摘要查找记录
      ├─ 族已标记盗用      -> 401 token_replayed
      ├─ 过期              -> 401 token_expired
      ├─ 已吊销(注销/管理) -> 401 session_revoked
      ├─ 原子抢占旧记录成功 -> 签发新访问令牌 + 新一代刷新令牌
      └─ 抢占失败(已被用)  -> 标记整族盗用并 401 token_replayed
```

并发刷新时，`DataStore.rotate_refresh_token` 在同一把锁内完成「旧记录标记
used + 新记录落库」，因此同一刷新凭证被 N 个请求同时使用时**恰好一个成功**，
其余全部得到 `token_replayed`，且不会留下任何新的有效会话（测试
`test_concurrent_refresh_exactly_one_wins` 用 24 个线程断言）。

### 拒绝错误码

| code                     | 含义                                   | 典型 HTTP |
|--------------------------|----------------------------------------|-----------|
| `invalid_credentials`    | 用户名或密码错误（两者不区分）          | 401       |
| `missing_token`          | 未提供凭证                              | 401       |
| `malformed_token`        | 令牌无法解析 / Authorization 头格式错   | 401       |
| `unsupported_token_type` | 令牌类型不是 access                     | 401       |
| `bad_signature`          | 签名或发行者校验失败                    | 401       |
| `token_expired`          | 访问/刷新令牌过期                       | 401       |
| `session_revoked`        | 注销、管理员吊销，或令牌安全版本过期    | 401       |
| `session_not_found`      | 会话/刷新凭证未知                       | 401       |
| `token_replayed`         | 刷新凭证已被使用（重放），族已吊销      | 401       |
| `user_disabled`          | 账号被禁用                              | 403       |
| `forbidden`              | 已认证但缺少动作权限（列表/创建等）     | 403       |
| `not_found`              | 资源不存在或无权访问（统一响应）        | 404       |
| `rate_limited`           | 登录失败过多，需退避（带 Retry-After）  | 429       |

## 权限判定规则

1. 有效权限 = 用户直接权限 ∪ 各角色映射权限（`admin / editor / viewer`）。
2. 动作未出现在有效权限中 → **默认拒绝**。
3. 资源型动作（`doc:read`、`doc:write`）还必须通过资源约束（默认：属主）。
4. `admin` 等全局角色免除资源约束；`doc:delete` 仅全局角色持有。
5. 针对具体资源的拒绝与资源不存在返回相同 404，避免枚举。

角色/权限/禁用通过 `PUT /auth/users/{id}/security`（需 `user:manage`）修改，
成功后安全版本号 +1：旧访问令牌因 `sv` 落后在下一请求即被拒；用户重新登录
后新规则立即生效，无需等待旧令牌过期。

## 关键配置项（环境变量，前缀 `AUTH_`）

| 变量                              | 默认值        | 说明                          |
|-----------------------------------|---------------|-------------------------------|
| `AUTH_JWT_SECRET`                 | 每次启动随机*  | 生产必须显式设置              |
| `AUTH_ACCESS_TOKEN_TTL_SECONDS`   | `900`         | 访问令牌寿命                  |
| `AUTH_REFRESH_TOKEN_TTL_SECONDS`  | `604800`      | 刷新令牌寿命                  |
| `AUTH_REFRESH_COOKIE_NAME`        | `refresh_token`| 刷新 Cookie 名               |
| `AUTH_COOKIE_SECURE`              | `true`        | 仅 HTTPS 发送                 |
| `AUTH_COOKIE_SAMESITE`            | `strict`      | `strict`/`lax`/`none`         |
| `AUTH_COOKIE_DOMAIN`              | 未设置        | Cookie Domain                 |
| `AUTH_CORS_ALLOW_ORIGINS`         | `[]`          | JSON 列表，空=禁止跨域        |
| `AUTH_LOGIN_MAX_ATTEMPTS`         | `5`           | 触发锁定的失败次数            |
| `AUTH_LOGIN_BACKOFF_BASE_SECONDS` | `1.0`         | 初始退避                       |
| `AUTH_LOGIN_BACKOFF_MULTIPLIER`   | `2.0`         | 退避乘数（指数）              |
| `AUTH_LOGIN_BACKOFF_MAX_SECONDS`  | `300.0`       | 退避上限                      |
| `AUTH_LOGIN_WINDOW_SECONDS`       | `900.0`       | 失败计数重置窗口              |

\* 未设置 `AUTH_JWT_SECRET` 时使用进程内随机密钥，保证模板开箱可跑，但重启后
所有令牌失效。

## 本地验证

```bash
# 全量单测（并发刷新 / 重放 / 即时权限变更 / 限流退避 / 统一 404 等）
uv run pytest -q

# 查看审计日志：每次判定都会打印输入与依据，敏感字段显示为 ***REDACTED***
uv run pytest tests/test_concurrency.py -s -q
```

测试覆盖：

- `tests/test_concurrency.py`：24 线程并发刷新仅一个成功、其余可区分地失败；
  重放旧代令牌会让最新合法令牌也失效；管理员吊销即时生效。
- `tests/test_auth_flow.py`：登录、错误码区分（缺失/损坏/坏签名/过期/吊销/
  重放）、轮换链、注销失效、敏感信息不进日志与响应。
- `tests/test_authorization.py`：默认拒绝、属主约束、越权与不存在同形 404、
  角色与直接权限变更后旧令牌立即失效并给出可区分原因。
- `tests/test_ratelimit.py`：阈值锁定、指数退避与上限、按账号+来源隔离、
  窗口重置、Cookie 安全位与 CORS 默认值。
