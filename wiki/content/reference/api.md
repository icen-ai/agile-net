# REST API

节点管理面接口。基路径 `/api/v1`，JSON 内容，JWT Bearer 认证。
anet-svc 单端口统一 Web：`/` 管理端 SPA、`/client` 客户端 SPA、`/api/v1/client/*`
客户端 SPA 管理接口（同 AdminAuth 共享登录）。

## 基础约定

| 项 | 值 |
| --- | --- |
| 认证 | `Authorization: Bearer <jwt>`（`/api/v1/auth/*` 公开端点除外） |
| 角色 | 管理面仅 `admin` 一种身份；AdminAuth 强制 scope 三档（ro/rules/full） |
| 时间 | ISO 8601（`2026-07-31T12:00:00Z`） |
| ID | UUIDv4 |
| 分页 | `page`（≥1）、`page_size`（1~100），响应含 `items/total/page/page_size` |

统一响应体：

```json
// 成功
{ "code": 0, "data": { } }
// 失败
{ "code": 40001, "message": "name already exists" }
```

错误码段见「参考 → 错误码」。

## Auth（公开）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/auth/init` | 首次初始化管理员（仅无 admin 时可用） |
| POST | `/api/v1/auth/login` | 登录（管理员；限流+锁定） |
| POST | `/api/v1/auth/refresh` | 刷新令牌（轮换 refresh） |
| POST | `/api/v1/auth/logout` | 登出（吊销 refresh） |
| GET | `/api/v1/auth/me` | 当前身份（含 scope） |
| PUT | `/api/v1/auth/password` | 修改管理员密码 |
| POST | `/api/v1/auth/admin-bootstrap` | 管理引导票据换取 scoped 管理会话 |

## 管理：规则 / 组

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/api/v1/admin/rules` | 列表（类型/搜索/分页）/ 创建 |
| PUT/DELETE | `/api/v1/admin/rules/{id}` | 更新 / 删除 |
| POST | `/api/v1/admin/rules/batch` | 批量导入（JSON/NDJSON） |
| GET/POST | `/api/v1/admin/groups` | 列表 / 创建（`e2e_required` 标记 E2E 强制组） |
| GET/PUT/DELETE | `/api/v1/admin/groups/{id}` | 详情 / 更新 / 删除 |
| GET | `/api/v1/admin/groups/{id}/detail` | 组身份总览：扇入令牌 + 扇出对端 |
| PUT | `/api/v1/admin/groups/{id}/rules` | 整组绑定规则 |

## 管理：统一签发（delegation）

资源主直接向消费者签发接入凭据（令牌即身份，无账号层）。四维度：入口
`entry_mode`（direct 直连签发者本机 listener / relay 经容灾集合会合点）× 信任档
（明文 / E2E / E2E+管理档 `admin_scope`）× 路由 `mode`（dedicated 专线 / split 分流）×
并发 `concurrency`（single 踢旧 / multi 并存 ≤ max_sessions，签发时读
node_config `delegation_max_sessions` 快照，默认 8）。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/admin/delegation/tokens` | 已签列表（组名已解析、容灾集合逐上游注册状态、entry_mode/concurrency/max_sessions、lifecycle 徽标） |
| POST | `/api/v1/admin/delegation/tokens` | 签发（明文与 `anet://connect` 分享链接仅此一次） |
| DELETE | `/api/v1/admin/delegation/tokens/{id}` | 吊销（在线上游发吊销帧，活动会话即踢） |

## 管理：节点 / 令牌 / 审计

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/admin/node/status` | 节点状态（角色/连接/可管理上游/24h 流量序列） |
| GET | `/api/v1/admin/node/logs` | 内存日志缓冲 |
| GET | `/api/v1/admin/node/metrics` | 系统资源指标 |
| PUT | `/api/v1/admin/node/settings` | 节点设置（名称/公网地址） |
| POST | `/api/v1/admin/node/kick` | 踢除下游节点会话 |
| GET | `/api/v1/admin/node/events` | WebSocket 实时事件流（`consumer.online/offline` 等；升级后首条消息认证） |
| GET/POST | `/api/v1/admin/node/relay-tokens` | 令牌列表 / 创建（`group_id` 收敛组、`expose_control`+`control_scope`） |
| PUT/DELETE | `/api/v1/admin/node/relay-tokens/{id}` | 更新（暴露开关/档位；`group_id` 三态）/ 吊销（踢会话） |
| GET/POST | `/api/v1/admin/admins` | 管理员列表 / 创建 |
| DELETE | `/api/v1/admin/admins/{id}` | 删除管理员 |
| GET | `/api/v1/admin/audit-logs` | 审计日志（动作过滤/分页） |

## 管理：扇出（connector）

扇出对端为一等入库资源：TOML `[[connectors]]` 仅启动导入（name 取 upstream_addr，组 = 不收敛），
运行时以数据库为准，以下操作均即时生效。`group_id` 挂权限组即对端收敛（缺省 = 不收敛）。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/api/v1/admin/connectors` | 列表（含实时状态与所属组）/ 创建（`advertise` 为字符串数组） |
| PUT/DELETE | `/api/v1/admin/connectors/{id}` | 更新（**全量替换**语义；token 留空 = 保留原值）/ 删除 |
| POST | `/api/v1/admin/connectors/{id}/enable` | 启用（装配起连） |
| POST | `/api/v1/admin/connectors/{id}/disable` | 禁用（断开连接，记录保留） |

扇出 token 是对端签发的连接凭据：AES-256-GCM 加密落库（可逆例外之一），创建后不回显。

## 速率与约束

- 登录按 IP 限流（默认 5 次/分钟，连续失败 5 次锁 15 分钟，`[limits]` 可调）
- 密码/令牌明文仅在创建响应中返回一次；二维码 10 分钟缓存
- WebSocket `/api/v1/admin/node/events` 需 admin JWT

## 客户端 Web 远程面 API (anet-gui 开关C)

当 `anet-gui` 开启「Web 远程面」时，本地 HTTP 服务（默认 `127.0.0.1:59291`）暴露客户端管理 REST API。

- **管理员初始化与登录**：`/api/v1/auth/init` / `/api/v1/auth/login`
- **节点与网络控制**：`GET/POST /api/v1/nodes`（节点列表与发起连接）
- **敏感导出约束**：凭据与接入链接导出属敏感操作，请求必须携带 `confirm=true`（如 `GET /api/v1/credentials/export?confirm=true`），否则返回 `40001` 错误码要求二次确认，并记入客户端审计。
