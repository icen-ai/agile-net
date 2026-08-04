# 数据库设计

SQLite 嵌入式数据库，单文件 `agile-net.db`，随 Node 进程启动时自动建表和迁移。

## 设计原则

1. **简洁** — 只存必要数据，运行时状态（在线/连接数）全在内存
2. **外键约束** — SQLite 外键默认关闭，启动时执行 `PRAGMA foreign_keys = ON`
3. **迁移** — 版本号递增，`_migration` 表记录已执行的迁移
4. **时间** — 全部存 UTC ISO 8601 文本，SQLite 原生 `datetime()` 函数可直接操作
5. **ID** — UUIDv4 文本格式，应用层生成

## 表关系

```
┌─────────┐     ┌─────────┐     ┌──────────────┐     ┌─────────┐
│  admin  │     │  rule   │────<│ group_rule   │>────│  group  │
└─────────┘     └─────────┘     └──────────────┘     └────┬────┘
                                                          │
                                                     ┌────┴────┐
                                                     │ account │
                                                     └────┬────┘
                                                          │
                                                     ┌────┴────────┐
                                                     │ audit_log   │
                                                     └─────────────┘

┌──────────────┐     ┌─────────────┐     ┌────────────────┐
│ relay_token  │     │ node_config │     │ _migration     │
└──────────────┘     └─────────────┘     └────────────────┘

                     ┌──────────────┐
                     │ traffic_log  │
                     └──────────────┘
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

CREATE UNIQUE INDEX idx_admin_username ON admin(username);
```

### rule — 路由规则

```sql
CREATE TABLE rule (
    id         TEXT    PRIMARY KEY,          -- UUIDv4
    type       TEXT    NOT NULL CHECK(type IN ('ip-cidr', 'host')),
    value      TEXT    NOT NULL,             -- CIDR 或域名
    resolve    INTEGER NOT NULL DEFAULT 0,   -- 0=false, 1=true
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
    id         TEXT PRIMARY KEY,            -- UUIDv4
    name       TEXT NOT NULL UNIQUE,
    remark     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX idx_group_name ON "group"(name);
```

### group_rule — 权限组与规则多对多关联

```sql
CREATE TABLE group_rule (
    group_id TEXT NOT NULL REFERENCES "group"(id) ON DELETE CASCADE,
    rule_id  TEXT NOT NULL REFERENCES rule(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, rule_id)
);

CREATE INDEX idx_group_rule_rule ON group_rule(rule_id);
```

### account — 客户端账号

```sql
CREATE TABLE account (
    id                TEXT PRIMARY KEY,          -- UUIDv4
    username          TEXT NOT NULL UNIQUE,
    password          TEXT NOT NULL,             -- argon2id hash
    group_id          TEXT NOT NULL REFERENCES "group"(id),
    enabled           INTEGER NOT NULL DEFAULT 1,   -- 0=disabled, 1=enabled
    remark            TEXT NOT NULL DEFAULT '',
    tunnel_token_hash TEXT,                      -- sha256(tunnel_token)，数据面认证，登录/刷新时轮换
    last_seen_at      TEXT,                      -- 最近认证/心跳时间
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX idx_account_username ON account(username);
CREATE INDEX idx_account_group ON account(group_id);
CREATE INDEX idx_account_enabled ON account(enabled);
```

### relay_token — 节点间认证 Token

```sql
CREATE TABLE relay_token (
    id           TEXT PRIMARY KEY,            -- UUIDv4
    token_hash   TEXT NOT NULL UNIQUE,        -- sha256(token)，不存明文
    token_prefix TEXT NOT NULL,               -- 展示用前缀 "psk_xxxx****"
    remark       TEXT NOT NULL DEFAULT '',
    last_used_at TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### refresh_token — 刷新令牌吊销表

```sql
CREATE TABLE refresh_token (
    jti_hash   TEXT PRIMARY KEY,            -- sha256(jti)
    subject    TEXT NOT NULL,               -- admin/account id
    role       TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

refresh 时轮换（旧 jti 立即吊销）；禁用账号/重置密码/登出时批量吊销。

### node_config — 节点配置（KV 存储）

```sql
CREATE TABLE node_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 预设记录
-- key: 'node_name',        value: '办公网跳板'
-- key: 'jwt_secret',       value: 'random_generated'
-- key: 'config_version',   value: '1'
-- key: 'listener.enabled', value: 'true'
-- key: 'listener.port',    value: '443'
-- key: 'connector.enabled',value: 'false'
-- ...
```

### audit_log — 审计日志

```sql
CREATE TABLE audit_log (
    id         TEXT PRIMARY KEY,            -- UUIDv4
    admin_id   TEXT,                         -- 可为 NULL（系统操作）
    action     TEXT NOT NULL,               -- 操作类型
    target     TEXT,                         -- 操作对象 ID
    detail     TEXT,                         -- JSON 详情
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
| `account.create` | 创建账号 |
| `account.update` | 更新账号 |
| `account.delete` | 删除账号 |
| `account.reset_password` | 重置密码 |
| `account.disable` | 禁用账号 |
| `account.enable` | 启用账号 |
| `group.create` | 创建权限组 |
| `group.update` | 更新权限组 |
| `group.delete` | 删除权限组 |
| `group.update_rules` | 更新权限组规则 |
| `rule.create` | 创建规则 |
| `rule.update` | 更新规则 |
| `rule.delete` | 删除规则 |
| `rule.batch_import` | 批量导入规则 |
| `relay_token.create` | 创建 relay token |
| `relay_token.delete` | 删除 relay token |
| `node.update_settings` | 更新节点设置 |
| `federation.adopt` | 一键采纳上送组（federation P1） |
| `delegation.issue` | 签发委托令牌（federation P2，不记明文） |
| `delegation.revoke` | 吊销委托令牌（签发端/中继端均落） |
| `delegation.register` | 扇出会话注册委托令牌（中继端，issuer + label） |

### delegated_token — 委托令牌（v10，federation P2/P3）

```sql
CREATE TABLE delegated_token (
    id           TEXT PRIMARY KEY,            -- UUIDv4
    token_hash   TEXT NOT NULL UNIQUE,        -- sha256(token)，不存明文
    token_prefix TEXT NOT NULL,               -- 展示用前缀 "psk_xxxx"
    label        TEXT NOT NULL DEFAULT '',    -- 备注（导入方可见，链接 account=d:<label>）
    groups       TEXT NOT NULL DEFAULT '[]',  -- JSON 组 ID 数组（注册时 resolve 为组名）
    hint_map     TEXT NOT NULL DEFAULT '[]',  -- JSON [{hint, groups}]（E2E 粗路由词表）
    e2e_key_enc  TEXT NOT NULL DEFAULT '',    -- E2E 主密钥 AES-256-GCM（可逆例外②）
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE delegated_token_reg (
    token_id     TEXT NOT NULL REFERENCES delegated_token(id) ON DELETE CASCADE,
    connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
    is_primary   INTEGER NOT NULL DEFAULT 0,  -- 主入口标记（每令牌恰一行 = 1）
    PRIMARY KEY (token_id, connector_id)
);

-- v10 同时：ALTER TABLE "group" ADD COLUMN e2e_required INTEGER NOT NULL DEFAULT 0;
-- e2e_required 组仅可挂委托令牌（账号/扇入令牌/扇出连接四写入口统一拦截）
```

注册走扇出会话控制帧（协议 v3 Ctrl）：生命周期随会话（吊销即断），中继侧零落库；
容灾集合逐上游一行，connector 重连自动重注册。

### traffic_log — 流量统计（按小时聚合）

```sql
CREATE TABLE traffic_log (
    id         TEXT PRIMARY KEY,
    account_id TEXT REFERENCES account(id) ON DELETE SET NULL,
    hour       TEXT NOT NULL,               -- '2025-07-30T14:00:00Z' 按小时对齐
    bytes_tx   INTEGER NOT NULL DEFAULT 0,
    bytes_rx   INTEGER NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,

    UNIQUE(account_id, hour)
);

CREATE INDEX idx_traffic_hour ON traffic_log(hour);
CREATE INDEX idx_traffic_account ON traffic_log(account_id);
```

流量在内存中实时累加，每分钟 flush 到此表（按小时聚合 upsert）。

### node_traffic_log — 节点级三维流量序列（v6）

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

按账号流量仍在 `traffic_log`（客户端心跳上报），本表为节点数据面视角：
后台采样任务每分钟把实时计数（扇入对端会话 / 扇出 connector 会话 / 中继途径对 TransitMeter）
差分入库，status API 的 `traffic_24h` 按 dim 跨标识汇总输出；留存 30 天（日级清理任务）。

## 迁移策略

```rust
const MIGRATIONS: &[(u32, &str, &str)] = &[
    (1, "initial_schema", include_str!("../migrations/001_initial.sql")),
    (2, "add_traffic_log", include_str!("../migrations/002_traffic.sql")),
    // ...
];

pub fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migration (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );"
    )?;

    let applied: HashSet<u32> = conn
        .prepare("SELECT version FROM _migration")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;

    for (version, name, sql) in MIGRATIONS {
        if !applied.contains(version) {
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO _migration (version, name) VALUES (?, ?)",
                params![version, name],
            )?;
        }
    }
    Ok(())
}
```

## 数据库连接管理

```rust
// Node 启动时
let conn = Connection::open("agile-net.db")?;
conn.execute_batch("PRAGMA journal_mode = WAL;")?;      // 读写并发
conn.execute_batch("PRAGMA foreign_keys = ON;")?;
conn.execute_batch("PRAGMA busy_timeout = 5000;")?;      // 等锁 5s
run_migrations(&conn)?;

// 使用 r2d2-sqlite 连接池（多线程读，单写）
let manager = SqliteConnectionManager::file("agile-net.db");
let pool = Pool::builder().max_size(8).build(manager)?;
```

## 数据量预估

| 表 | 预期行数 | 说明 |
|----|---------|------|
| admin | 1-3 | 极少 |
| rule | 10-100 | 手动管理 |
| group | 3-20 | 按团队/角色 |
| account | 10-200 | 按人 |
| group_rule | 30-500 | 多对多 |
| relay_token | 1-10 | 下游节点数 |
| audit_log | 持续增长 | 90 天清理 |
| traffic_log | 持续增长 | 24h * account_count / 小时 |
| node_traffic_log | 持续增长 | 24h * (对端+connector+途径对) / 小时，30 天清理 |
| node_config | 10-30 | KV |

SQLite 完全胜任，无需 PostgreSQL。
