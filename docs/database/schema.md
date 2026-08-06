# 数据库设计

SQLite 嵌入式数据库，单文件 `agile-net.db`，随 Node 进程启动时自动建表。
**基线 v1**：预发布迁移链（v1~v15）已塌缩为单一基线，直接建最终形态（无 account /
traffic_log 表）；版本表机制保留供正式发布后升级（只在 MIGRATIONS 末尾追加，严禁改基线）。

## 设计原则

1. **简洁** — 只存必要数据，运行时状态（在线/连接数）全在内存
2. **外键约束** — SQLite 外键默认关闭，启动时执行 `PRAGMA foreign_keys = ON`
3. **迁移** — 版本号递增，`_migration` 表记录已执行的迁移
4. **时间** — 全部存 UTC ISO 8601 文本，SQLite 原生 `datetime()` 函数可直接操作；
   令牌生命周期时间一律 `db::normalize_expiry` 规范化 UTC Z 秒级
5. **ID** — UUIDv4 文本格式，应用层生成

## 表关系

```
┌─────────┐     ┌─────────┐     ┌──────────────┐     ┌─────────┐
│  admin  │     │  rule   │────<│ group_rule   │>────│  group  │
└─────────┘     └─────────┘     └──────────────┘     └────┬────┘
                                                          │（组集 CSV 引用，无 FK）
              ┌───────────────────┬──────────────────────┼──────────────┐
              ▼                   ▼                      ▼              ▼
       ┌─────────────┐     ┌────────────┐      ┌─────────────────┐
       │ relay_token │     │ connector  │      │ delegated_token │────┐
       └─────────────┘     └─────┬──────┘      └─────────────────┘    │
                                 ▲                                    ▼
                                 └──────────────┌─────────────────────┐
                                                │ delegated_token_reg │
                                                └─────────────────────┘

┌─────────────┐  ┌──────────────┐  ┌───────────────┐  ┌────────────┐  ┌──────────────┐
│ node_config │  │  audit_log   │  │ refresh_token │  │ admin_ticket│  │node_traffic_log│
└─────────────┘  └──────────────┘  └───────────────┘  └────────────┘  └──────────────┘
```

## DDL

### _migration — 迁移记录

```sql
CREATE TABLE _migration (
    version   INTEGER PRIMARY KEY,
    name      TEXT    NOT NULL,
    applied_at TEXT   NOT NULL DEFAULT (datetime('now'))
);
```

### admin — 管理员

```sql
CREATE TABLE admin (
    id         TEXT PRIMARY KEY,            -- UUIDv4
    username   TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,               -- argon2id hash
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### rule — 路由规则

```sql
CREATE TABLE rule (
    id         TEXT    PRIMARY KEY,          -- UUIDv4
    type       TEXT    NOT NULL CHECK(type IN ('ip-cidr', 'host')),
    value      TEXT    NOT NULL,             -- CIDR 或域名
    resolve    INTEGER NOT NULL DEFAULT 0,
    remark     TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),

    UNIQUE(type, value)
);

CREATE INDEX idx_rule_type ON rule(type);
```

### group — 权限组

```sql
CREATE TABLE "group" (
    id           TEXT PRIMARY KEY,            -- UUIDv4
    name         TEXT NOT NULL UNIQUE,
    remark       TEXT NOT NULL DEFAULT '',
    e2e_required INTEGER NOT NULL DEFAULT 0,  -- E2E 强制组（仅可挂委托令牌）
    adopted_node TEXT NOT NULL DEFAULT '',    -- 采纳血缘：来源端点 node_id（空 = 本地手工组）
    adopted_name TEXT NOT NULL DEFAULT '',    -- 采纳血缘：源组名
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
```

`e2e_required` 组仅可挂委托令牌（扇入令牌/扇出连接写入口统一拦截，fail-closed）；
采纳组（adopted_node 非空）为只读活镜像，漂移写跟随源规则/E2E 标记。

### group_rule — 权限组与规则多对多关联

```sql
CREATE TABLE group_rule (
    group_id TEXT NOT NULL REFERENCES "group"(id) ON DELETE CASCADE,
    rule_id  TEXT NOT NULL REFERENCES rule(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, rule_id)
);

CREATE INDEX idx_group_rule_rule ON group_rule(rule_id);
```

### relay_token — 扇入令牌

```sql
CREATE TABLE relay_token (
    id              TEXT PRIMARY KEY,            -- UUIDv4
    token_hash      TEXT NOT NULL UNIQUE,        -- sha256(token)，不存明文
    token_prefix    TEXT NOT NULL,               -- 展示用前缀 "psk_xxxx****"
    remark          TEXT NOT NULL DEFAULT '',
    last_used_at    TEXT,
    expose_control  INTEGER NOT NULL DEFAULT 0,  -- 允许持令牌对端中继管理本节点
    control_scope   TEXT NOT NULL DEFAULT 'full',-- 管理授权档位 ro / rules / full
    group_id        TEXT,                        -- 逗号分隔组集（多组 ACL 并集；无 FK）
    rate_limit_kbps INTEGER,                     -- 会话带宽配额（读写合并令牌桶）
    expires_at      TEXT,                        -- 生命周期：NULL = 永不过期
    max_uses        INTEGER,                     -- 生命周期：NULL = 不限用量
    used_count      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
```

过期/用尽按未知令牌拒（fail-closed），命中即累 used_count。

### delegated_token — 委托令牌（统一签发）

```sql
CREATE TABLE delegated_token (
    id           TEXT PRIMARY KEY,            -- UUIDv4
    token_hash   TEXT NOT NULL UNIQUE,        -- sha256(token)，不存明文
    token_prefix TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',    -- 备注（导入方可见，链接 account=d:<label>）
    groups       TEXT NOT NULL DEFAULT '[]',  -- JSON 组 ID 数组
    hint_map     TEXT NOT NULL DEFAULT '[]',  -- JSON [{hint, groups}]（entrust 词；透明档为空）
    e2e_key_enc  TEXT NOT NULL DEFAULT '',    -- E2E 主密钥 AES-256-GCM（可逆例外②）
    mode         TEXT NOT NULL DEFAULT 'dedicated',  -- dedicated 专线 / split 分流
    admin_scope  TEXT NOT NULL DEFAULT '',    -- '' / ro / rules / full（管理档）
    entry_mode   TEXT NOT NULL DEFAULT 'relay' CHECK(entry_mode IN ('direct','relay')),
    concurrency  TEXT NOT NULL DEFAULT 'single' CHECK(concurrency IN ('single','multi')),
    max_sessions INTEGER NOT NULL DEFAULT 8,  -- 签发时 node_config.delegation_max_sessions 快照
    expires_at   TEXT,
    max_uses     INTEGER,
    used_count   INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- relay 入口的容灾集合注册：逐上游 connector 一行（is_primary=1 恰一行）；
-- 每次扇出（重）连自动重注册，随会话清空/吊销即断。direct 入口无 reg 行。
CREATE TABLE delegated_token_reg (
    token_id     TEXT NOT NULL REFERENCES delegated_token(id) ON DELETE CASCADE,
    connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
    is_primary   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_id, connector_id)
);
```

四维度：入口 `entry_mode`（direct 直连签发者本机 listener 自注册 / relay 经容灾集合
会合点）× 信任档（明文 / E2E / E2E+管理档）× 路由 `mode` × 并发 `concurrency`
（single 踢旧 / multi 并存 ≤ max_sessions）。

### connector — 扇出连接（一等资源）

```sql
CREATE TABLE connector (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,
    upstream_addr      TEXT NOT NULL,
    token_enc          TEXT NOT NULL,          -- AES-256-GCM（可逆例外①）
    sni_hostname       TEXT NOT NULL DEFAULT '',
    insecure           INTEGER NOT NULL DEFAULT 0,
    advertise          TEXT NOT NULL DEFAULT '',
    group_id           TEXT,                   -- 逗号分隔组集（同 relay_token 语义；无 FK）
    enabled            INTEGER NOT NULL DEFAULT 1,
    remark             TEXT NOT NULL DEFAULT '',
    ca_cert_path       TEXT NOT NULL DEFAULT '',
    pinned_cert_path   TEXT NOT NULL DEFAULT '',
    pinned_fingerprint TEXT NOT NULL DEFAULT '',
    push_groups        TEXT NOT NULL DEFAULT '',-- 策略上送组（逗号分隔组名）
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_connector_group ON connector(group_id);
```

### node_config — 节点配置（KV 存储）

```sql
CREATE TABLE node_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- 预设记录
-- key: 'node_name',               value: '办公网跳板'
-- key: 'jwt_secret',              value: 'random_generated'
-- key: 'config_version',          value: '1'
-- key: 'delegation_max_sessions', value: '8'          -- 统一签发并发上限快照源
-- key: 'connector_token_key',     value: 'random_generated'  -- 可逆存储机器密钥
-- key: 'public_host' / 'public_api_url',             -- 公网身份与反代端点
-- ...
```

### refresh_token — 刷新令牌吊销表

```sql
CREATE TABLE refresh_token (
    jti_hash   TEXT PRIMARY KEY,            -- sha256(jti)
    subject    TEXT NOT NULL,               -- admin id
    role       TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

refresh 时轮换（旧 jti 立即吊销）；改密/删管理员/登出时批量吊销。

### admin_ticket — 管理引导票据

```sql
CREATE TABLE admin_ticket (
    id          TEXT PRIMARY KEY,
    ticket_hash TEXT NOT NULL UNIQUE,       -- sha256(ticket)，明文仅签发时返回一次
    kind        TEXT NOT NULL CHECK(kind IN ('relay')),
    subject     TEXT NOT NULL,
    scope       TEXT NOT NULL DEFAULT 'full' CHECK(scope IN ('ro','rules','full')),
    uses        INTEGER NOT NULL DEFAULT 0,
    max_uses    INTEGER NOT NULL DEFAULT 1,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_admin_ticket_exp ON admin_ticket(expires_at);
```

一次性/限时凭据，经 relay 暴露控制面或委托管理通道换取 scoped admin 会话
（TTL 1 小时、max_uses 100，按握手/配置拉取即铸即用）。

### audit_log — 审计日志

```sql
CREATE TABLE audit_log (
    id         TEXT PRIMARY KEY,            -- UUIDv4
    admin_id   TEXT,                         -- 可为 NULL（系统操作）
    operator   TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    ip         TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_time ON audit_log(created_at);
```

#### 审计 action 枚举

| action | 说明 |
|--------|------|
| `admin.login` | 管理员登录 |
| `admin.logout` | 管理员登出 |
| `group.create` / `group.update` / `group.delete` | 权限组管理 |
| `group.e2e_required` | E2E 强制组标记变更 |
| `group.update_rules` | 更新权限组规则 |
| `rule.create` / `rule.update` / `rule.delete` / `rule.batch_import` | 规则管理 |
| `relay_token.create` / `relay_token.delete` / `relay_token.set_group` | 扇入令牌管理 |
| `connector.*` | 扇出连接管理 |
| `node.update_settings` | 更新节点设置 |
| `federation.adopt` | 一键采纳上送组 |
| `delegation.issue` | 签发委托令牌（不记明文） |
| `delegation.revoke` | 吊销委托令牌（签发端/中继端均落） |
| `delegation.register` | 扇出会话注册委托令牌（中继端，issuer + label） |

严禁记录任何密码/Token 明文与密文。

### node_traffic_log — 节点级三维流量序列

```sql
CREATE TABLE node_traffic_log (
    id         TEXT PRIMARY KEY,
    dim        TEXT NOT NULL CHECK(dim IN ('fanin','fanout','transit')),
    src        TEXT NOT NULL DEFAULT '',  -- fanin=对端 node_id / fanout=connector name / transit=起始端
    dst        TEXT NOT NULL DEFAULT '',  -- 仅 transit 使用：结束端（下游对端 node_id / "local"）
    hour       TEXT NOT NULL,             -- 本地时间桶 '2026-08-02 09:00'
    bytes_up   INTEGER NOT NULL DEFAULT 0,
    bytes_down INTEGER NOT NULL DEFAULT 0,

    UNIQUE(dim, src, dst, hour)
);

CREATE INDEX idx_node_traffic_hour ON node_traffic_log(hour);
```

节点数据面视角：后台采样任务每分钟把实时计数（扇入对端会话 / 扇出 connector 会话 /
中继途径对 TransitMeter）差分入库，status API 的 `traffic_24h` 按 dim 跨标识汇总输出；
留存 30 天（日级清理任务）。

## 数据库连接管理

```rust
// r2d2_sqlite 连接池（file 池 8 / memory 池 1，WAL）
conn.execute_batch("PRAGMA journal_mode = WAL;")?;      // 读写并发
conn.execute_batch("PRAGMA foreign_keys = ON;")?;
conn.execute_batch("PRAGMA busy_timeout = 5000;")?;     // 等锁 5s
```

## 数据量预估

| 表 | 预期行数 | 说明 |
|----|---------|------|
| admin | 1-3 | 极少 |
| rule | 10-100 | 手动管理 |
| group | 3-20 | 按团队/角色 |
| group_rule | 30-500 | 多对多 |
| relay_token | 1-10 | 扇入对端数 |
| delegated_token | 1-50 | 消费者签发数 |
| connector | 1-10 | 扇出对端数 |
| audit_log | 持续增长 | 90 天清理 |
| node_traffic_log | 持续增长 | 24h * (对端+connector+途径对) / 小时，30 天清理 |
| node_config | 10-30 | KV |

SQLite 完全胜任，无需 PostgreSQL。
