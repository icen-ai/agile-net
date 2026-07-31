# 数据库 Schema

节点使用 SQLite（WAL 模式，`r2d2` 连接池：file 池 8 / memory 池 1），启动时执行版本化迁移
（`_migration` 表记录，新迁移追加 `MIGRATIONS` 尾部，严禁修改已发布迁移）。

## 当前版本：v3

### v1 initial_schema

| 表 | 说明 | 关键列 |
| --- | --- | --- |
| `admin` | 管理员 | `username` 唯一，`password`（argon2id） |
| `rule` | 路由规则 | `type`（ip-cidr/host）、`value`、`resolve`，UNIQUE(type,value) |
| `group` | 权限组 | `name` 唯一 |
| `group_rule` | 组-规则绑定 | (group_id, rule_id) 主键，级联删除 |
| `account` | 客户端账号 | `username` 唯一、`password`（argon2id）、`group_id`、`enabled`、`tunnel_token_hash`（SHA-256）、`last_seen_at` |
| `relay_token` | Relay 令牌 | `token_hash` 唯一（SHA-256）、`token_prefix`、`last_used_at` |
| `node_config` | 节点配置 KV | `jwt_secret`、`node_name`、`public_host` 等 |
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

## 安全落库约定

- 密码一律 argon2id（64MB/t=3/p=4），严禁明文
- 账号密码 / Relay Token / 隧道令牌 / 管理票据：库中只存 SHA-256 哈希，明文仅创建时返回一次
- JWT 密钥首启生成并持久化于 `node_config.jwt_secret`
- 审计与日志严禁记录任何密码/Token 明文
