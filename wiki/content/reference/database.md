# 数据库 Schema

节点使用 SQLite（WAL 模式，`r2d2` 连接池：file 池 8 / memory 池 1），启动时执行版本化迁移
（`_migration` 表记录，新迁移追加 `MIGRATIONS` 尾部，严禁修改已发布迁移）。

## 当前版本：基线 v1

预发布迁移链已塌缩为单一基线，直接建最终形态（**无 account / traffic_log 表**——账号体系
已整体删除，消费者接入统一为委托令牌）。

| 表 | 说明 | 关键列 |
| --- | --- | --- |
| `admin` | 管理员 | `username` 唯一，`password`（argon2id） |
| `rule` | 路由规则 | `type`（ip-cidr/host）、`value`、`resolve`，UNIQUE(type,value) |
| `group` | 权限组 | `name` 唯一、`e2e_required`（E2E 强制组）、`adopted_node`/`adopted_name`（采纳血缘） |
| `group_rule` | 组-规则绑定 | (group_id, rule_id) 主键，级联删除 |
| `relay_token` | 扇入令牌 | `token_hash` 唯一（SHA-256）、`token_prefix`、`group_id`（组集 CSV，NULL = 不收敛）、`expose_control`/`control_scope`、`rate_limit_kbps`、`expires_at`/`max_uses`/`used_count` |
| `delegated_token` | 委托令牌（统一签发） | `token_hash` 唯一（SHA-256）、`label`、`groups`（JSON 组 ID 数组）、`hint_map`（entrust 词）、`e2e_key_enc`（AES-256-GCM）、`mode`（dedicated/split）、`admin_scope`、`entry_mode`（direct/relay）、`concurrency`（single/multi）、`max_sessions`、`expires_at`/`max_uses`/`used_count` |
| `delegated_token_reg` | 容灾集合注册 | (token_id, connector_id) 主键、`is_primary`（relay 入口逐上游一行，恰一主入口） |
| `connector` | 扇出对端（一等资源） | `name` 唯一、`upstream_addr`、`token_enc`（AES-256-GCM）、`sni_hostname`、`insecure`、`advertise`、`group_id`（组集 CSV）、`enabled`、`ca_cert_path`/`pinned_cert_path`/`pinned_fingerprint`、`push_groups` |
| `node_config` | 节点配置 KV | `jwt_secret`、`node_name`、`public_host`、`connector_token_key`、`delegation_max_sessions`（默认 8，签发并发上限快照源）等 |
| `audit_log` | 审计 | `operator`、`action`、`target`、`detail`、`ip`，90 天留存 |
| `admin_ticket` | 管理引导票据 | `ticket_hash`（SHA-256）、`kind`、`subject`、`scope`（ro/rules/full）、`uses/max_uses`、`expires_at` |
| `refresh_token` | 刷新令牌 | `jti_hash`（SHA-256）、`subject`、`role`、`expires_at`、`revoked` |
| `node_traffic_log` | 节点级三维流量序列 | `dim`（fanin/fanout/transit）、`src`/`dst`、`hour` 本地时间桶，UNIQUE(dim,src,dst,hour)，30 天留存 |

TOML `[[connectors]]` 仅启动导入（name 取 upstream_addr，组 = 不收敛），运行时以
`connector` 表为准。

## 安全落库约定

- 管理员密码一律 argon2id（64MB/t=3/p=4），严禁明文
- Relay Token / 委托令牌 / 管理票据：库中只存 SHA-256 哈希，明文仅创建时返回一次
- 可逆例外仅两处（AES-256-GCM，格式 `v1:nonce_b64:ct_b64`；机器密钥
  `node_config.connector_token_key` 首用生成并持久化，与 `jwt_secret` 同机制）：
  ①扇出 token（`connector.token_enc`）——连接凭据由对端签发、连接时必须使用明文；
  ②委托令牌 E2E 主密钥（`delegated_token.e2e_key_enc`）——签发端解包 E2E 信封必须
  可恢复 HKDF(token)。创建后永不回显，审计不落明文与密文
- JWT 密钥首启生成并持久化于 `node_config.jwt_secret`
- 审计与日志严禁记录任何密码/Token 明文
