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
5. 持有该资源该动作的**有效协作授权**（未撤销、未到期）→ 允许（见第三节）
6. 其余命中角色矩阵（按资源 kind；仅 `doc` 适用下表） → 允许
7. 以上都不命中 → 默认拒绝

角色矩阵（可在 `policy.py` 中调整；仅适用于 `kind="doc"`，其它 kind
默认不按角色放行，只认属主/admin/显式权限/协作授权）：

| 动作 | admin | editor | viewer |
|------|:-----:|:------:|:------:|
| `resource:create`（无资源上下文） | ✓ | ✓ | ✗ |
| `resource:read`（doc，非属主） | ✓ | ✓ | ✓ |
| `resource:update`（doc，非属主） | ✓ | ✓ | ✗ |
| `resource:delete`（doc，非属主） | ✓ | ✗ | ✗ |
| `user:change_role` | ✓ | ✗ | ✗ |

admin 对任意 kind 的资源始终拥有读/改/删与授权管理权。

### 权限 / 角色即时变更

`POST /admin/users/{user_id}/role`（仅 admin）变更角色时：

- 判定永远基于服务端当前用户状态，访问令牌不携带权限快照；
- 同时**立即吊销目标用户全部现存访问令牌**，其客户端需用刷新凭证换取新令牌，
  换得的会话即刻按新角色判定——**不需要重新登录**。

### 防资源探测

`GET/PATCH/DELETE /resources/{id}` 对“资源不存在”与“存在但无权访问”返回
**同形的 `404 not_found`**（状态码与响应体逐字一致），未授权方无法据状态差异
判断资源是否存在。

## 三、资源协作授权（临时授权 / 到期 / 撤销）

在角色与属主规则之上增加一层**资源级、账号级、动作级**的临时授权，编排位于
`app/grants.py`，判定仍收敛在 `app/policy.py`，不另起一套规则。

### 谁能授权

只有以下三类主体能查看 / 新增 / 撤销某资源的授权（`can_manage_grants`）：

1. 资源**属主**；
2. **admin** 角色（对所有资源本来就具备完整管理权限）；
3. 持有显式权限 `grant:manage:<kind>` / `grant:manage:*` / `*` 的账号。

其他人（包括能读/改他人 `doc` 的 editor）访问授权接口得到的是与“资源不存在”
**完全一致的 404**，既看不到也改不了。

### 授权内容、有效期与撤销

- 一项授权 = `(资源, 被授权账号, 动作)`；动作仅限 `read / update / delete`。
- 必须指定明确的 `expires_at`（ISO 8601，建议带时区；不带时区按 UTC）：
  - 必须晚于当前时间，否则 `422 invalid_grant`；
  - 不得超过最长有效期（默认 30 天，`AUTH_GRANT_MAX_TTL`），否则同样 `422`。
- **到期自动失效**：无后台任务，判定时按当前时间惰性检查，`expires_at`
  时刻起立即失效。授权数据**不写入访问令牌**，因此到期与撤销都**不需要对方
  重新登录**，下一次请求即按新状态判定。
- **撤销即时生效**：撤销后被授权方手里已有的访问凭证对该资源动作立刻失效
  （令牌本身仍可用于其它有权访问的资源，只有该授权被收回）。
- 默认关口保持关闭：没有任何规则允许时一律拒绝，引入授权不会放宽默认口径。

### 幂等与并发行为

所有复合操作（取资源 → 管理权判定 → 查授权/计数 → 写入/访问判定）都在
**同一把存储锁临界区**内完成：

- 同一账号同一动作反复授权是**幂等**的：只更新同一行的 `expires_at`，
  响应 `status` 分别为 `created` / `renewed`，不增加条数。
- 并发对同一键新增/撤销：临界区串行化，**结束状态唯一确定**；撤销一旦提交
  成功，之后取得锁的读/改/删请求不可能再被该授权放行。
- 并发对不同账号新增：成功条数恰好等于上限，其余明确拒绝，绝不超额。
- 撤销与资源删除撞上：两种交错都收敛，资源删除时连带清除全部授权，
  不留下悬挂授权。

### 授权上限

单个资源的**有效授权条数**有明确上限（默认 **50**，`AUTH_GRANT_MAX_PER_RESOURCE`）。
已过期与已撤销的授权不计入；对同一键续期不占新名额。超限时返回
`409 grant_limit_reached`（响应中带 `limit`），撤销或到期释放名额后可再授予。

### 与现有角色规则的兼容

策略评估顺序为：禁用检查 → 显式权限 → 资源无关角色矩阵 → **属主** →
**有效协作授权** → 资源角色矩阵 → 默认拒绝。既有角色矩阵对 `kind="doc"`
保持原口径不变；对矩阵未覆盖的资源 kind（如 `sheet`），默认只有属主、
admin、显式权限或被授权者可访问。

### 接口

| 方法/路径 | 说明 |
|-----------|------|
| `GET /resources/{id}` | 读取（同形 404 防探测） |
| `PATCH /resources/{id}` | 修改 `title` / `kind`（与读取同一判定管线） |
| `DELETE /resources/{id}` | 删除（连带清除授权；同形 404） |
| `GET /resources/{id}/grants` | 查看授权列表（仅管理者；否则 404） |
| `PUT /resources/{id}/grants` | 新增/续期授权，幂等，body：`grantee, action, expires_at` |
| `POST /resources/{id}/grants/revoke` | 撤销授权，body：`grantee, action` |

`grantee` 可传用户 id 或用户名；给属主自己授权返回 `422 invalid_grant`。
撤销一个不存在/已撤销/已过期的授权返回 404（与不可见资源同口径，天然幂等）。

> 仅凭协作授权获得的修改权**不能变更资源 `kind`**（防止把资源改到更宽松的
> 角色矩阵上提权）；该类请求同样返回同形 404。属主与管理员改 kind 不受限。

```bash
# 属主 editor 临时授权 viewer 删除 doc-2，2 小时后失效
EXP=$(python3 -c "from datetime import datetime,timezone,timedelta;\
print((datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())")
curl -X PUT localhost:8000/resources/doc-2/grants \
  -H "Authorization: Bearer $EDITOR_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"grantee\":\"viewer\",\"action\":\"delete\",\"expires_at\":\"$EXP\"}"
# viewer 此刻即可删除（无需重新登录）；撤销则立刻失效
curl -X POST localhost:8000/resources/doc-2/grants/revoke \
  -H "Authorization: Bearer $EDITOR_TOKEN" -H 'Content-Type: application/json' \
  -d '{"grantee":"viewer","action":"delete"}'
```

## 四、登录限流与退避

- 以 **(账号, 来源 IP)** 双维度计数，互不影响（见 `app/ratelimit.py`）。
- 滑动窗口内失败达到阈值（默认 5 次 / 300 秒）→ 进入锁定，返回 `429 rate_limited`
  与 `Retry-After` 头。
- 锁定过期后重新计数，但历史触发次数保留，锁定时长按指数升级：
  15s → 30s → 60s → 120s → …，封顶（默认 300s）。
- 登录成功立即清零该维度计数。

## 五、安全基线

- 密码：PBKDF2-HMAC-SHA256（200k 轮）+ 每用户随机盐，恒定时间校验。
- 敏感信息：密码与令牌**不写入日志**（日志仅记录用户标识摘要、令牌 id、错误码），
  也不出现在错误响应中；用户名在失败日志中脱敏。
- Cookie：默认 `HttpOnly` + `SameSite=Lax`，`Secure` 可经配置开启（生产应开启）。
- CORS：默认不放行任何来源；仅当显式配置来源时才启用中间件，凭证模式不使用通配来源。
- 刷新令牌仅存哈希；重放即整族吊销。

## 六、关键配置项（环境变量）

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
| `AUTH_GRANT_MAX_PER_RESOURCE` | `50` | 单个资源的有效协作授权条数上限 |
| `AUTH_GRANT_MAX_TTL` | `2592000` | 单次授权允许的最长有效期（秒，默认 30 天） |

## 七、本地验证方法

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
- `tests/test_grants.py`：协作授权生效/幂等续期、**到期自动失效**、
  **撤销后同一令牌立刻失效**、并发新增/撤销/删除的确定性、
  越权与资源不存在同形 404、**超过单资源上限返回 409**、非属主不可管理授权。
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

# 5) 协作授权：editor 授权 viewer 临时删除 doc-2（详见第三节）
ETOK=$(curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor","password":"editor-pw"}' | jq -r .access_token)
EXP=$(python3 -c "from datetime import datetime,timezone,timedelta;\
print((datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())")
curl -s -X PUT localhost:8000/resources/doc-2/grants \
  -H "Authorization: Bearer $ETOK" -H 'Content-Type: application/json' \
  -d "{\"grantee\":\"viewer\",\"action\":\"delete\",\"expires_at\":\"$EXP\"}"
curl -i -X DELETE localhost:8000/resources/doc-2 -H "Authorization: Bearer $TOK"
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
app/policy.py        角色 + 资源属性 + 显式权限 + 协作授权的默认拒绝策略
app/grants.py        资源协作授权：查看/新增/撤销/同锁访问判定、上限与并发编排
app/ratelimit.py     (账号, IP) 维度失败计数与指数退避
app/services.py      登录/注销/刷新/鉴权/角色变更编排、演示数据
app/deps.py          Bearer/Cookie 统一取凭证依赖
app/routes.py        HTTP 入口
tests/               并发、重放、即时变更、限流退避等测试
```
