# 数据库 Schema

节点使用 SQLite（WAL 模式，`r2d2` 连接池：file 池 8 / memory 池 1），启动时执行版本化迁移
（`_migration` 表记录，新迁移追加 `MIGRATIONS` 尾部，严禁修改已发布迁移）。

## 当前版本：v5

### v1 initial_schema

| 表 | 说明 | 关键列 |
| --- | --- | --- |
| `admin` | 管理员 | `username` 唯一，`password`（argon2id） |
| `rule` | 路由规则 | `type`（ip-cidr/host）、`value`、`resolve`，UNIQUE(type,value) |
| `group` | 权限组 | `name` 唯一 |
| `group_rule` | 组-规则绑定 | (group_id, rule_id) 主键，级联删除 |
| `account` | 客户端账号 | `username` 唯一、`password`（argon2id）、`group_id`、`enabled`、`tunnel_token_hash`（SHA-256）、`last_seen_at` |
| `relay_token` | Relay 令牌 | `token_hash` 唯一（SHA-256）、`token_prefix`、`group_id`（扇入收敛挂载点，NULL = 不收敛）、`last_used_at` |
| `node_config` | 节点配置 KV | `jwt_secret`、`node_name`、`public_host`、`connector_token_key` 等 |
| `audit_log` | 审计 | `operator`、`action`、`target`、`detail`、`ip`，90 天留存 |
| `traffic_log` | 流量（按小时聚合） | UNIQUE(account_id, hour) |
| `refresh_token` | 刷新令牌 | `jti_hash`（SHA-256）、`subject`、`role`、`expires_at`、`revoked` |

### v2 admin_console_and_tickets

- `account.admin_console`（默认 0）：「管理此节点」授权
- `admin_ticket`：管理引导票据——`ticket_hash`（SHA-256）、`kind`（account/relay）、
  `subject`、`scope`（ro/rules/full）、`uses/max_uses`、`expires_at`

### v3 relay_token_expose_control

- `relay_token.expose_control`（默认 0）：允许该下游中继管理本节点
- `relay_token.control_scope`（默认 `full`）：管理授权档位

### v4 peer_acl_connector

- `relay_token.group_id`（NULL = 不收敛，放行一切）：扇入对端的收敛挂载点
- `connector`：扇出对端入库（一等资源）——`name` 唯一、`upstream_addr`、`token_enc`
  （AES-256-GCM 加密，见下）、`sni_hostname`、`insecure`、`advertise`（逗号拼接；API 入参为字符串数组）、
  `group_id`（扇出收敛挂载点）、`enabled`、`remark`
- TOML `[[connectors]]` 降级为启动导入（name 取 upstream_addr，组 = 不收敛），运行时以本表为准

### v5 connector_cert_paths

- `connector.ca_cert_path` / `connector.pinned_cert_path`：证书固定能力对齐 core
  `ConnectorConfig`（空串 = 不使用，优先级 pinned > ca > insecure）

## 安全落库约定

- 密码一律 argon2id（64MB/t=3/p=4），严禁明文
- 账号密码 / Relay Token / 隧道令牌 / 管理票据：库中只存 SHA-256 哈希，明文仅创建时返回一次
- 扇出 token（`connector.token_enc`）：**全库唯一可逆例外**——连接凭据由对端签发、连接时
  必须使用明文，AES-256-GCM 加密落库（格式 `v1:nonce_b64:ct_b64`）；机器密钥
  `node_config.connector_token_key` 首用生成并持久化（与 `jwt_secret` 同机制）；
  创建后永不回显，审计不落明文与密文
- JWT 密钥首启生成并持久化于 `node_config.jwt_secret`
- 审计与日志严禁记录任何密码/Token 明文
