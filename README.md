# FastAPI 认证、会话与访问控制模板

在 FastAPI 骨架上提供一套可复用的认证 / 会话 / 访问控制能力。HTTP 入口
（`Authorization: Bearer` 头与浏览器 Cookie）只负责取凭证，**所有判定都收敛到
`AuthService` 与策略层**，因此不同调用入口在同一套规则下得到一致且可解释的结果。

- 纯标准库实现密码哈希（PBKDF2-HMAC-SHA256）与令牌签名（HMAC-SHA256），无需额外依赖
- 进程内线程安全存储，开箱即用；存储接口可替换为数据库/Redis 实现
- 启动方式与依赖管理保持模板原样：`uv sync` + `fastapi dev main.py`

## 快速开始

```bash
uv sync                       # 安装依赖（含 dev 的 pytest）
fastapi dev main.py           # 或 uvicorn main:app --reload
uv run pytest -s              # 运行测试（-s 可看到输入与判定依据日志）
```

演示账号（密码均为 `<用户名>-pw`）：

| 账号   | 角色   | 密码       |
|--------|--------|------------|
| admin  | admin  | admin-pw   |
| editor | editor | editor-pw  |
| viewer | viewer | viewer-pw  |

示例资源：`doc-1` 属主为 viewer，`doc-2` 属主为 editor。

## 一、登录与令牌流程

### 令牌职责分离

- **访问令牌（access token）**：短期（默认 15 分钟），HMAC 签名的紧凑串，
  载荷只含 `jti / sid(会话) / sub(用户) / iat / exp`，**不含权限快照**。
  每次请求都回查服务端登记（`AccessRecord`）、会话与用户当前状态，
  因此吊销与权限变更即时生效。
- **刷新令牌（refresh token）**：长期（默认 14 天）的 256bit 随机串，
  明文只在签发时出现一次，服务端**仅存 SHA-256 摘要**，无法从存储还原。

### 登录

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pw"}'
```

成功后响应体含 `access_token / refresh_token / expires_in`，同时写入两个
`HttpOnly`、`SameSite=Lax` 的会话 Cookie。账号不存在与密码错误返回**完全相同**
的 `invalid_credentials`，避免账号枚举。

### 刷新（轮换 + 重放检测）

```bash
curl -X POST http://127.0.0.1:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<上一代刷新令牌>"}'
# 浏览器场景直接依赖 Cookie，无需请求体
```

- 刷新成功即**轮换**：旧凭证标记 `rotated` 并与新凭证建立链路，返回新一代访问+刷新令牌。
- “检查旧凭证 → 标记 → 签发下一代”在存储锁内一次完成，因此**同一刷新凭证并发使用时
  有且仅有一个请求成功**，其余请求不会产生任何新的有效会话。
- 已轮换的旧凭证再次出现判定为**重放（疑似被盗）**：默认立即吊销整条令牌族、
  终结会话并吊销其全部访问令牌（含刚刚被并发胜出者签发的新令牌）。
- 拒绝原因互斥可区分：

| 场景 | 错误码 | HTTP |
|------|--------|------|
| 刷新凭证无法识别 | `unauthenticated` | 401 |
| 刷新凭证已过期 | `refresh_token_expired` | 401 |
| 已注销 / 族吊销 / 会话终结 | `refresh_token_revoked` | 401 |
| 旧凭证重放（被盗用） | `refresh_token_replay` | 401 |
| 访问令牌过期 | `access_token_expired` | 401 |
| 访问令牌被吊销 | `access_token_revoked` | 401 |
| 登录失败过多退避中 | `rate_limited`（带 `Retry-After`） | 429 |

### 注销

```bash
curl -X POST http://127.0.0.1:8000/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<刷新令牌>"}'
```

注销吊销整条刷新族、终结会话、吊销该会话全部访问令牌，并清除会话 Cookie。
仅提供访问令牌时同样会终结会话。注销、被盗用处置后，旧凭证立即失效。

## 二、权限判定规则

判定逻辑位于 `app/policy.py`，**默认拒绝**：任何未被明确规则允许的动作一律拒绝。
按顺序评估：

1. 用户被禁用 → 拒绝
2. 显式权限命中 `action:kind` / `action:*` / `*` → 允许
   （写入 `User.extra_permissions`，变更在**下一次请求立即生效**）
3. 资源无关动作命中角色矩阵 → 允许
4. 资源相关动作：属主对自己资源可 `read/update/delete`
5. 其余命中角色矩阵 → 允许
6. 以上都不命中 → 默认拒绝

角色矩阵（可在 `policy.py` 中调整）：

| 动作 | admin | editor | viewer |
|------|:-----:|:------:|:------:|
| `resource:create`（无资源上下文） | ✓ | ✓ | ✗ |
| `resource:read` | ✓ | ✓ | ✓ |
| `resource:update`（非属主） | ✓ | ✓ | ✗ |
| `resource:delete`（非属主） | ✓ | ✗ | ✗ |
| `user:change_role` | ✓ | ✗ | ✗ |

### 权限 / 角色即时变更

`POST /admin/users/{user_id}/role`（仅 admin）变更角色时：

- 判定永远基于服务端当前用户状态，访问令牌不携带权限快照；
- 同时**立即吊销目标用户全部现存访问令牌**，其客户端需用刷新凭证换取新令牌，
  换得的会话即刻按新角色判定——**不需要重新登录**。

### 防资源探测

`GET /resources/{id}` 对“资源不存在”与“存在但无权访问”返回**同形的
`404 not_found`**，未授权方无法据状态差异判断资源是否存在。

## 三、登录限流与退避

- 以 **(账号, 来源 IP)** 双维度计数，互不影响（见 `app/ratelimit.py`）。
- 滑动窗口内失败达到阈值（默认 5 次 / 300 秒）→ 进入锁定，返回 `429 rate_limited`
  与 `Retry-After` 头。
- 锁定过期后重新计数，但历史触发次数保留，锁定时长按指数升级：
  15s → 30s → 60s → 120s → …，封顶（默认 300s）。
- 登录成功立即清零该维度计数。

## 四、安全基线

- 密码：PBKDF2-HMAC-SHA256（200k 轮）+ 每用户随机盐，恒定时间校验。
- 敏感信息：密码与令牌**不写入日志**（日志仅记录用户标识摘要、令牌 id、错误码），
  也不出现在错误响应中；用户名在失败日志中脱敏。
- Cookie：默认 `HttpOnly` + `SameSite=Lax`，`Secure` 可经配置开启（生产应开启）。
- CORS：默认不放行任何来源；仅当显式配置来源时才启用中间件，凭证模式不使用通配来源。
- 刷新令牌仅存哈希；重放即整族吊销。

## 五、关键配置项（环境变量）

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `AUTH_ACCESS_TTL` | `900` | 访问令牌有效期（秒） |
| `AUTH_REFRESH_TTL` | `1209600` | 刷新令牌有效期（秒） |
| `AUTH_TOKEN_SECRET` | `change-me-in-production` | HMAC 签名密钥，**生产必须覆盖** |
| `AUTH_TOKEN_ISSUER` | `fastapi-auth-sessions` | 令牌签发者校验值 |
| `AUTH_COOKIE_SECURE` | `false` | 是否仅 HTTPS 传输 Cookie（生产置 `true`） |
| `AUTH_COOKIE_SAMESITE` | `lax` | SameSite 策略（`lax`/`strict`/`none`） |
| `AUTH_CORS_ORIGINS` | 空 | 允许的跨域来源，逗号分隔；为空即不放行 |
| `AUTH_CORS_CREDENTIALS` | `true` | 是否允许跨域携带凭证 |
| `AUTH_LOGIN_WINDOW` | `300` | 失败计数滑动窗口（秒） |
| `AUTH_LOGIN_MAX_FAILURES` | `5` | 触发退避的失败阈值 |
| `AUTH_LOGIN_BASE_LOCKOUT` | `15` | 首次锁定时长（秒），逐轮翻倍 |
| `AUTH_LOGIN_MAX_LOCKOUT` | `300` | 退避封顶时长（秒） |
| `AUTH_REVOKE_FAMILY_ON_REPLAY` | `true` | 重放时是否吊销整条刷新族 |

## 六、本地验证方法

```bash
uv run pytest -s
```

测试覆盖：

- `tests/test_auth_flow.py`：登录、刷新轮换、注销；过期/吊销/重放拒绝原因可区分；
  密码不出现在令牌、存储与响应中。
- `tests/test_concurrent_refresh.py`：**16 路并发刷新同一凭证仅 1 路成功**；
  串行旋转链后重放旧凭证导致整族失效（另含 100 轮 ×12 线程压力脚本验证）。
- `tests/test_policy.py`：默认拒绝、属主/角色矩阵、越权与不存在同形 404、
  **角色与显式权限变更即时生效**。
- `tests/test_ratelimit.py`：阈值触发、双维度隔离、指数退避升级、成功清零、
  HTTP 429 与 `Retry-After`。
- `tests/test_http_integration.py`：Cookie 会话全链路、Header 与 Cookie 入口结果一致、
  CORS 默认不放行、响应不回显密码。

`-s` 会打印每个用例的 `[input] ... -> [decision] ...`，即输入与策略判定依据。

手工验证（服务启动后）：

```bash
# 1) 登录拿令牌
TOK=$(curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pw"}' | jq -r .access_token)
# 2) 访问自己的资源
curl -s localhost:8000/resources/doc-1 -H "Authorization: Bearer $TOK"
# 3) 越权创建 -> 403 forbidden（默认拒绝）
curl -i -X POST localhost:8000/resources -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"id":"x"}'
# 4) 连续 5 次错误密码 -> 第 6 次 429 且带 Retry-After
```

## 目录结构

```
main.py              应用入口、CORS、统一错误处理（保持原启动方式）
app/config.py        环境变量配置与安全默认值
app/errors.py        稳定错误码 -> HTTP 状态映射（可区分拒绝原因）
app/security.py      密码哈希、随机令牌、HMAC、日志脱敏
app/models.py        用户 / 会话 / 刷新记录 / 访问登记 / 资源 / 判定结果
app/store.py         线程安全进程内存储
app/tokens.py        令牌签发/校验/原子旋转/重放吊销
app/policy.py        角色 + 资源属性 + 显式权限的默认拒绝策略
app/ratelimit.py     (账号, IP) 维度失败计数与指数退避
app/services.py      登录/注销/刷新/鉴权/角色变更编排、演示数据
app/deps.py          Bearer/Cookie 统一取凭证依赖
app/routes.py        HTTP 入口
tests/               并发、重放、即时变更、限流退避等测试
```
