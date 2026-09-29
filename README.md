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
4. 资源相关动作：属主对自己资源可 `read/update/delete/share`
5. 当前有效的协作授权命中该动作 → 允许（详见第三章）
6. 其余命中角色矩阵 → 允许
7. 以上都不命中 → 默认拒绝

角色矩阵（可在 `policy.py` 中调整）：

| 动作 | admin | editor | viewer | guest |
|------|:-----:|:------:|:------:|:-----:|
| `resource:create`（无资源上下文） | ✓ | ✓ | ✗ | ✗ |
| `resource:read` | ✓ | ✓ | ✓ | ✗ |
| `resource:update`（非属主） | ✓ | ✓ | ✗ | ✗ |
| `resource:delete`（非属主） | ✓ | ✗ | ✗ | ✗ |
| `resource:share`（管理协作授权） | ✓ | ✗ | ✗ | ✗ |
| `user:change_role` | ✓ | ✗ | ✗ | ✗ |

> `guest` 是无任何矩阵权限的演示角色：属主身份与协作授权之外一律默认拒绝。
> 属主对自己的资源天然拥有 read/update/delete/share；协作授权只在矩阵之外
> 增量放行 read/update/delete，详见第三章。

### 权限 / 角色即时变更

`POST /admin/users/{user_id}/role`（仅 admin）变更角色时：

- 判定永远基于服务端当前用户状态，访问令牌不携带权限快照；
- 同时**立即吊销目标用户全部现存访问令牌**，其客户端需用刷新凭证换取新令牌，
  换得的会话即刻按新角色判定——**不需要重新登录**。

### 防资源探测

`GET /resources/{id}` 对“资源不存在”与“存在但无权访问”返回**同形的
`404 not_found`**，未授权方无法据状态差异判断资源是否存在。
新增的 `PATCH/DELETE /resources/{id}` 以及全部授权端点遵守同一口径。

## 三、资源协作授权（临时授权）

在角色/属主/显式权限之外增加一层**资源级临时授权**：属主可以把自己名下
某个资源的部分动作（读/改/删）临时授予指定账号，带明确失效时间；到期或撤销
即时生效，无需对方重新登录。判定仍收敛在 `app/policy.py`，默认关口不因引入
授权而放开。

### HTTP 接口

| 方法/路径 | 作用 | 可调用方 |
|-----------|------|-----------|
| `GET /resources/{id}/grants` | 查看当前有效授权 | 属主 / admin 角色 / 显式 `resource:share` 权限 |
| `PUT /resources/{id}/grants` | 新增或续期授权（幂等） | 同上 |
| `POST /resources/{id}/grants/revoke` | 撤销授权（可只摘部分动作，幂等） | 同上 |
| `PATCH /resources/{id}` | 修改资源（当前仅 `kind`） | 与读同一套判定：属主 / 角色 / 协作授权 |
| `DELETE /resources/{id}` | 删除资源（级联清除其授权，204） | 同上 |

授权请求体：

```json
{
  "username": "friend",
  "actions": ["read", "update"],
  "expires_in": 3600
}
```

- `actions` 只能取 `read / update / delete` 的**非空子集**（对应策略动作
  `resource:read/resource:update/resource:delete`）；授权能力本身不可转授
  （不能授 `share`）。非法动作返回 `422 invalid_grant`。
- `expires_in` 为相对秒数，必须为正且不超过上限（默认 366 天，
  可由 `AUTH_GRANT_MAX_TTL` 调整），否则 `422 invalid_grant`。
- 撤销请求省略 `actions` 表示整条撤销；给出数组则只摘除其中动作，
  最后一个动作被摘掉时整条标记为撤销。撤销不存在/已失效的授权仍返回 200（幂等）。

### 谁能授权

策略新增资源相关动作 `resource:share`（查看/新增/撤销授权都走它）：

- **属主**对自己的资源天然可 share；
- **admin 角色**可管理任意资源的授权（管理员本来就具备资源 update/delete 管理权）；
- 其余角色（含 editor/viewer/guest）一律拒绝；显式权限 `resource:share:<kind>`
  等也按现有显式权限规则生效。
- 无权方调用任一授权端点，与访问不存在的资源返回**字节级一致的 `404 not_found`**，
  无法借授权端点探测资源是否存在；给属主自己授权返回 `422 invalid_grant`。

### 有效期、到期与撤销怎么算

- 授权记录 `(resource_id, grantee_id)` 为唯一键，保存动作集合与绝对失效
  时间戳 `expires_at`。
- 每次资源请求都在**服务端实时比较** `expires_at` 与当前时间：到点即视为
  不存在，下一次请求立刻被拒。访问令牌载荷不含授权快照，**对方无需重新登录，
  也不会被强制刷新**，只是该动作不再被允许。
- 撤销在存储锁内落盘后，对后续请求**立即生效**：对方手里已有的访问凭证
  继续可用（登录态不受影响），但用它访问该资源对应动作时按未授权处理，
  对无权方呈现与“资源不存在”一致的 404。
- 对同一账号重复 `PUT` 授权按该账号当前是否持有**有效**授权区分语义：
  - **授权仍有效时再次 `PUT`（续期 / 扩动作）**：幂等原地更新同一条记录，
    动作取并集、失效时间取更远者，不新增条目、不重复占用名额，永不受上限拦截。
  - **授权已到期或已被整条撤销后再次 `PUT`（重新授权）**：等同一次**全新授权**，
    动作与有效期完全以本次请求为准（不会与旧记录做并集、旧动作不会复活），
    记录仍写回同一个 `(resource_id, grantee_id)` 键（因此条目不重复），
    但必须按**新增一个有效名额**走同一套上限判断。
- 部分撤销（只摘动作）后记录仍是有效授权：此时再 `PUT` 属于第一种“续期”，
  动作在剩余动作上取并集；只有动作被摘空、整条标记撤销或到期后才是“重新授权”。

### 并发行为

所有授权写入（新增/续期/重新授权/撤销）与每次资源判定都在同一把进程内
`RLock` 临界区完成：

- 资源判定在临界区内一次性取“资源 + 当前有效授权”快照后再决策，
  因此**撤销成功返回之后，不会再有任何读/改/删请求被放行**，不存在
  “撤销已 200、随后请求反而放行”的窗口；
- 并发新增、重新授权与撤销被锁串行化，最终状态由实际落盘的最后一条写操作决定，
  结果确定；但“先占名额再判断”不存在的窗口——计数与写入在同一临界区内完成；
- **“数当前有效名额 → 比上限 → 写入新授权”在同一临界区内一次完成**，
  因此并发新增/重新授权时，有且仅有不超过上限的请求成功，其余得到
  `409 grant_limit_exceeded`；任何交错（含与撤销并发）都不会把有效授权数
  顶到上限以上，也不会把名额空着时本应成功的一次授权误判成超限。

### 有效授权上限

- 单个资源的有效授权按**不同被授权人**计数：一条授权记录
  `(resource_id, grantee_id)` 在「未撤销 **且** `expires_at > 当前服务端时间`」
  时恰好占 1 个名额，否则不占。默认上限 **50**
  （`AUTH_GRANT_MAX_PER_RESOURCE` 可调）。达到上限后，无论是给**全新账号**
  授权，还是给授权**已到期 / 已被整条撤销**的账号**重新授权**，都按同一口径
  拒绝为 `409 grant_limit_exceeded`（响应体 `error.extra` 带
  `{"limit":..,"active":..}`）——重新授权不会因该账号曾经持过名额而破例。
- 唯一不受上限拦截的是**对当前仍有效授权的幂等续期 / 扩动作**（同一被授权人，
  原地更新，不新增名额）。
- **名额释放**：某条授权自然到期（下一次计数/判定时即不再计入，无需后台清理）
  或被整条撤销后名额立即空出，可再授给任意账号（包括原来的被授权人，此时按
  全新授权处理）。无论走“到期”还是“撤销”哪条路径，一次授权成功后该资源的
  有效授权数都不会超过配置上限。
- **被拒绝不留痕**：上限检查先于任何写入发生。达上限被拒的请求不会新建授权、
  不会把已到期/已撤销的旧记录悄悄复活或改写其动作/有效期，也不会影响其它账号
  的既有授权。
- 上限是**按资源独立**计数的，不影响属主对自己其他资源的授权。

### 与现有角色规则如何兼容

策略评估顺序（见 `app/policy.py`，命中即决定）：

1. 用户禁用 → 拒绝
2. 显式权限命中 `action:kind / action:* / *` → 允许
3. 资源无关动作命中角色矩阵（如 `resource:create`）→ 允许
4. **属主**对自己资源的 read/update/delete/**share** → 允许
5. 当前有效**协作授权**命中该动作 → 允许
6. 角色矩阵（editor 可改非己资源、admin 可删、viewer 可读等）→ 允许
7. 全部不命中 → 默认拒绝

协作授权只能在角色规则之外“加白名单”，永远不能让默认拒绝变宽松；
新增的无矩阵权限角色 `guest` 用于演示“只有被明确授权才能访问”的账号。

```bash
# 属主 viewer 临时授权 friend 读/改 doc-1 一小时
curl -X PUT localhost:8000/resources/doc-1/grants \
  -H "Authorization: Bearer $OWNER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"friend","actions":["read","update"],"expires_in":3600}'
# friend 无需重新登录即可访问；属主随时查看/撤销
curl localhost:8000/resources/doc-1/grants -H "Authorization: Bearer $OWNER_TOKEN"
curl -X POST localhost:8000/resources/doc-1/grants/revoke \
  -H "Authorization: Bearer $OWNER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"friend"}'
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
| `AUTH_GRANT_MAX_PER_RESOURCE` | `50` | 单资源有效协作授权（按被授权人计数）上限 |
| `AUTH_GRANT_MAX_TTL` | `31622400` | 单次协作授权最长有效期（秒，默认 366 天） |

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
- `tests/test_http_integration.py`：Cookie 会话全链路、Header 与 Cookie 入口结果一致、
  CORS 默认不放行、响应不回显密码。
- `tests/test_grants.py`：协作授权服务层——授权动作隔离、**到期自动失效（无需重登）**、
  **撤销立即生效**、部分撤销、**幂等续期**、**单资源上限拒绝（409）**、
  只有属主/admin 可管理、越权与不存在同形 404、非法入参 422、
  **上限=1 时到期/撤销后重新授权仍被正确拦截（核心漏洞回归）**、
  **被拒绝的重新授权不留痕且不改既有授权**、到期/撤销释放名额后复用、
  **并发新增/重新授权/撤销确定性**（16 路抢名额恰好 cap 路成功；
  撤销与两路重授并发全程不超 cap、不误拒；8 线程 ×30 轮混合压力
  + 撤销后 32 路并发读全部拒绝）。
- `tests/test_grants_http.py`：HTTP 全链路——被授权 guest 授权前后可读/到期 404
  且响应体与资源不存在**逐字节一致**、撤销后旧令牌立即被拒、PATCH/DELETE 与读同规则、
  非属主探测授权端点同形 404、上限 409（`error.extra` 带 limit/active）、
  **已到期账号重新授权与全新账号同一上限口径**、非法载荷 422、
  **8 路并发授权 + 10 轮混合授权/撤销后有效数恒不超上限**、撤销后 64 路并发读全 404。

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
# 5) 协作授权：属主把 doc-1 的修改权临时授给别人，到期/撤销即失效
#    （见“三、资源协作授权”小节完整示例）
```

单资源有效授权上限可以直接起一个小上限的服务端到端验证
（下面把上限设成 1，复现“到期/撤销后重新授权也不能超发”）：

```bash
AUTH_GRANT_MAX_PER_RESOURCE=1 uv run fastapi dev main.py
# 另开终端：属主 viewer 登录拿 OWNER_TOKEN（见上），并准备两个被授权账号
TOK=$(curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pw"}' | jq -r .access_token)
# editor/admin 是现成账号；这里用 editor 做 A、admin 做 B（仅用于演示计数）
curl -i -X PUT localhost:8000/resources/doc-1/grants -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor","actions":["read"],"expires_in":1}'   # 200，A 占唯一名额
sleep 1                                                          # 让 A 自然到期
curl -i -X PUT localhost:8000/resources/doc-1/grants -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","actions":["read"],"expires_in":3600}' # 200，B 占满名额
curl -i -X PUT localhost:8000/resources/doc-1/grants -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor","actions":["read"],"expires_in":3600}' # 409 grant_limit_exceeded
# 409 响应体形如 {"error":{"code":"grant_limit_exceeded",
#   "message":"...already has 1 active grants (limit 1)","extra":{"limit":1,"active":1}}}
# 名额被 B 占着时，重新给已到期的 A 授权也被拒；先撤销 B 释放名额后 A 即可重新授权
curl -s -X POST localhost:8000/resources/doc-1/grants/revoke -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"username":"admin"}'
curl -s -X PUT localhost:8000/resources/doc-1/grants -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor","actions":["read"],"expires_in":3600}'   # 200，名额复用
curl -s localhost:8000/resources/doc-1/grants -H "Authorization: Bearer $TOK"
# -> grants 里只有 editor 一个有效被授权人
```

## 目录结构

```
main.py              应用入口、CORS、统一错误处理（保持原启动方式）
app/config.py        环境变量配置与安全默认值
app/errors.py        稳定错误码 -> HTTP 状态映射（可区分拒绝原因）
app/security.py      密码哈希、随机令牌、HMAC、日志脱敏
app/models.py        用户 / 会话 / 刷新记录 / 访问登记 / 资源 / 协作授权 / 判定结果
app/store.py         线程安全进程内存储（含授权原子原语）
app/tokens.py        令牌签发/校验/原子旋转/重放吊销
app/policy.py        角色 + 资源属性 + 显式权限 + 协作授权的默认拒绝策略
app/ratelimit.py     (账号, IP) 维度失败计数与指数退避
app/services.py      登录/注销/刷新/鉴权/角色变更/协作授权编排、演示数据
app/deps.py          Bearer/Cookie 统一取凭证依赖
app/routes.py        HTTP 入口
tests/               并发、重放、即时变更、限流退避等测试
```
