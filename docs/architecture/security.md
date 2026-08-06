# 安全与认证设计

## 认证体系总览

```
                 ┌──────────────┐
                 │   Node DB    │
                 │  (SQLite)    │
                 └──────┬───────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
         Admin Auth          Relay Auth
         (JWT)               (PSK Token)
```

管理面只有 Admin 一种身份（管理端 SPA `/` 与客户端 SPA `/client` 共用同一 AdminAuth 登录）；
数据面只有 relay PSK 一种身份——消费者接入用的委托令牌（delegated token）与节点间扇入
用的 relay token 同构同强度，令牌即身份，无账号层。

## Admin 认证

管理员通过 Web UI 操作节点。

### 登录流程

```
POST /api/v1/auth/login
{ "username": "admin", "password": "hashed" }

→ 验证 argon2 哈希
→ 签发 JWT (access_token 15min + refresh_token 7d)
→ 后续请求 Authorization: Bearer <access_token>
```

### 密码存储

```rust
// argon2id — 抗 GPU/ASIC，OWASP 推荐
let config = argon2::Config {
    variant: argon2::Variant::Argon2id,
    mem_cost: 65536,    // 64 MB
    time_cost: 3,
    lanes: 4,
    ..Default::default()
};
let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config)?;
```

密码强度策略两端统一（≥10 位 + 大小写 + 数字），唯一实现
`api::handlers::auth::validate_password_strength`。

### JWT 结构

```json
{
  "sub": "admin_id",
  "role": "admin",
  "exp": 1720000000,
  "iat": 1719999100,
  "jti": "unique-id"
}
```

签名算法：HS256，密钥从节点首次初始化时生成并存数据库（`node_config.jwt_secret`，
**绝不硬编码**）；refresh token jti 哈希落库，支持吊销轮换。

## Relay 认证（数据面）

节点间扇入与消费者接入都走 relay PSK，不走 JWT：

```
Connector/Client → TLS → AuthFrame { "token": "psk_xxx" }
Listener 比对令牌哈希（常数时间比较）
```

- **relay token**：Admin 在管理面签发（`psk_` + 48 位，SHA-256 哈希落库，明文仅创建时
  返回一次），授权下游节点连入；可挂权限组做对端收敛（Peer ACL），可选
  `expose_control` 暴露控制面。
- **delegated token（统一签发）**：资源主直接向消费者签发，同强度同存储；四维度见下。

## 统一签发（delegated token）信任模型

消费者接入不再有任何账号/口令，只有委托令牌。签发四维度：

| 维度 | 档位 | 安全语义 |
|------|------|---------|
| 入口 `entry_mode` | `direct` / `relay` | direct = 消费者直连签发者本机 listener，自注册进签发者本地持久注册表——TLS 已端到端（消费者↔签发者），**信任档锁明文**，无中继可泄露；relay = 经扇出容灾集合会合点，注册随上游会话存活 |
| 信任档 | 明文 / E2E / E2E+管理档 | 引用组含 `e2e_required` 组时自动携带 entrust 路由词（`en_<令牌哈希前12hex>`），消费者全部 Open 端到端加密（HKDF(token) 密钥层次），中继只见不透明路由词、零规则泄露；管理档（`admin_scope` ro/rules/full）的引导票据经 E2E 配置通道下发，**绝不明文过中继** |
| 路由 `mode` | `dedicated` / `split` | 专线 = 全量路由；分流 = 词表经 E2E 配置通道（保留目标 `__anet_delegation_config__`）下发，要求 E2E 组 |
| 并发 `concurrency` | `single` / `multi` | single = 同令牌新会话踢旧留新；multi = 多会话并存，listener 按 `max_sessions`（签发时 node_config `delegation_max_sessions` 快照，默认 8）上限执法，超限拒开 |

生命周期：签发可选 `expires_at` / `max_uses`；过期/用尽后注册同步停止上送，签发端
数据面（DelegationEngine `alive()` 门）同步硬拒，fail-closed。

## Token 生命周期

| Token 类型 | 有效期 | 刷新方式 |
|-----------|--------|---------|
| admin access_token | 15 min | refresh_token 刷新 |
| admin refresh_token | 7 天 | 重新登录 |
| relay psk / delegated token | 不过期（可选 expires_at/max_uses） | Admin 手动轮换/重签 |

## 令牌体系（与实现一致）

| 令牌 | 格式 | 存储 |
|------|------|------|
| admin access_token | JWT HS256 | 内存 |
| admin refresh_token | JWT HS256 | jti 哈希落库，可吊销/轮换 |
| relay psk | `psk_` + 48 位 | SHA-256 哈希落库，列表仅显示前缀 |
| delegated token | `psk_` + 48 位 | SHA-256 哈希落库；E2E 主密钥 HKDF(token) AES-256-GCM 加密落库（可逆例外） |
| 管理密码 | 用户自设 | argon2id 哈希落库（64MB / t=3 / p=4） |

可逆存储例外（全库仅两处，均为 AES-256-GCM `v1:nonce_b64:ct_b64`，机器密钥
`node_config.connector_token_key` 首用生成并持久化）：①扇出 connector 的连接凭据
（对端签发、连接必须用明文）；②委托令牌 E2E 主密钥（签发端解包 E2E 信封必须可恢复）。

## 接入链接

一切可分享的技术字段打包进一条 `anet://` 链接（入口地址 + 凭证 + 入口证书指纹三件套）：

```
anet://connect?
  server=relay-b.example.com&
  port=54430&
  account=d%3Aalice&
  password=psk_xxx&
  fp=aa11...&
  entry=relay-b.example.com%3A54430%2Crelay-c.example.com%3A54430&
  entryfp=aa11%2Cbb22
```

E2E 令牌另携带 `en=<entrust 词>`；分流档 `emode=split`；管理档 `eadmin=1`。
扇入令牌分享为 `anet://fanout?...`。生成一律 `anet://`，为唯一 scheme。

## 安全加固

### 频率限制

```
登录接口: 5 次/分钟/IP，失败 5 次锁定 15 分钟（core::util::LoginRateLimiter 唯一实现）
隧道认证: 按 IP 限流（20 次/分钟）+ 随机延迟惩罚
```

数据面 token 比较必须常数时间（`constant_time_eq`）。

### 审计日志

所有管理操作写入 `audit_log` 表（含 detail 与来源 IP），**严禁记录任何密码/Token 明文**：

```sql
INSERT INTO audit_log (admin_id, action, target, detail, ip, created_at)
VALUES (?, 'delegation.issue', 'uuid', 'label=... groups=2', '1.2.3.4', datetime('now'));
```

### TLS 证书

- 生产推荐一：**ACME 自动证书**（Let's Encrypt，TLS-ALPN-01）——与 Relay 端口多路复用，
  ALPN 为 `acme-tls/1` 的连接出示挑战证书、其余出示正式证书，签发与续期全程免停机热替换；
  账户凭据持久化于 `node_config.acme.account`，证书落盘 `certs/acme-*.pem`
- 生产推荐二：手动放置证书（`listener.cert_path` / `key_path`），对端使用**证书固定 (pinning)** 或私有 CA 校验
- 证书固定：节点启动日志输出证书 SHA-256 指纹，带外分发；扇出 `pinned_fingerprint` 钉入后仅信任该证书，抗 MITM
- 开发：证书缺失时自动生成自签证书并**持久化**到 `./certs/`（重启不变，pinning 保持稳定）
- `insecure = true`（跳过校验）仅限开发调试，启动时打印醒目警告
- 信任策略优先级：pinned_fingerprint > pinned_cert_path > ca_cert_path > insecure > 系统 CA
  （relay 证书为自签拟态证书，系统 CA 恒失败——生产扇出必须钉指纹而非勾 insecure）
