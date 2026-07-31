# 安全与认证设计

## 认证体系总览

```
                 ┌──────────────┐
                 │   Node DB    │
                 │  (SQLite)    │
                 └──────┬───────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
     Admin Auth    Client Auth    Relay Auth
     (JWT)         (JWT)          (PSK Token)
```

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

签名算法：HS256，密钥从节点首次初始化时生成并存数据库。

## Client 认证

客户端连接节点获取配置和建立隧道。

### 登录流程

```
POST /api/v1/auth/login
{ "username": "account_id", "password": "generated_pass" }

→ 验证 argon2 哈希
→ 检查账号状态 (enabled)
→ 签发 JWT (role: "client")
→ 客户端拿到 token 后：
  1. GET /api/v1/client/config — 拉取路由规则
  2. 建立 TLS 隧道连接
```

### 隧道认证（数据面）

客户端建立隧道时，不复用 HTTP JWT，走独立的隧道认证：

```
TCP → TLS 1.3 →
AuthFrame { "account_id": "xxx", "token": "tunnel_token" }
→ 节点验证 → AuthResult { ok: true }
→ 隧道建立，开始转发数据
```

`tunnel_token` 在登录时随 JWT 一起下发，生命周期更长（30d），避免隧道频繁重连认证。

## Relay 认证（节点间）

节点间使用预共享 Token（PSK），不走 JWT：

```
Connector → TLS → AuthFrame { "token": "psk_xxx" }
Listener 比对本地配置的 authorized_tokens 列表
```

PSK 由 Admin 在上游节点管理面生成，手动配置到下游节点。

## Token 生命周期

| Token 类型 | 有效期 | 刷新方式 |
|-----------|--------|---------|
| admin access_token | 15 min | refresh_token 刷新 |
| admin refresh_token | 7 天 | 重新登录 |
| client access_token | 1 小时 | refresh_token 刷新 |
| client refresh_token | 30 天 | 重新登录 |
| client tunnel_token | 30 天 | 随 access_token 刷新时一起刷新 |
| relay psk | 不过期 | Admin 手动轮换 |

## 账号密码生成

Admin 创建客户端账号时，**服务端自动生成 sk 风格强密码**（类似 API Secret Key 的长度与复杂度）：

```
sk- + 48 位 [a-zA-Z0-9] 随机字符（CSPRNG），约 286 bits 熵
```

- 密码与 `connect_url` 仅在创建/重置时返回一次，不落日志、不可再查
- 数据库只存 argon2id 哈希（64MB / t=3 / p=4，OWASP 推荐参数）
- 重置密码后旧凭据（密码、JWT、refresh_token、tunnel_token）立即全部失效

## 令牌体系（与实现一致）

| 令牌 | 格式 | 有效期 | 存储 |
|------|------|--------|------|
| admin access_token | JWT HS256 | 15 min | 内存 |
| admin refresh_token | JWT HS256 | 7 天 | jti 哈希落库，可吊销/轮换 |
| client access_token | JWT HS256 | 1 小时 | 内存 |
| client refresh_token | JWT HS256 | 30 天 | jti 哈希落库，可吊销/轮换 |
| client tunnel_token | `tun_` + 48 位 | 随登录/刷新轮换 | SHA-256 哈希落库 |
| relay psk | `psk_` + 48 位 | 不过期，手动轮换 | SHA-256 哈希落库，列表仅显示前缀 |
| 账号密码 | `sk-` + 48 位 | 不过期，重置轮换 | argon2id 哈希落库 |

JWT 密钥在节点首次启动时生成（64 位 hex 随机）并持久化到 `node_config.jwt_secret`，**绝不硬编码**。

## 接入信息二维码

Admin 生成的接入信息编码为 URL，客户端扫码直接导入：

```
agilenet://connect?
  server=cdn.example.com&
  port=443&
  account=acc_xxxxx&
  password=XxXxXxXx&
  tls=1
```

## 安全加固

### 频率限制

```
登录接口: 5 次/分钟/IP，失败 5 次锁定 15 分钟
API 接口: 100 次/分钟/token
隧道认证: 3 次/分钟/IP
```

### 审计日志

所有管理操作写入 `audit_log` 表：

```sql
INSERT INTO audit_log (admin_id, action, target, detail, ip, created_at)
VALUES (?, 'create_account', 'acc_xxx', '{"group":"dev"}', '1.2.3.4', datetime('now'));
```

### TLS 证书

- 生产推荐一：**ACME 自动证书**（Let's Encrypt，TLS-ALPN-01）——与 Relay 端口多路复用，
  ALPN 为 `acme-tls/1` 的连接出示挑战证书、其余出示正式证书，签发与续期全程免停机热替换；
  账户凭据持久化于 `node_config.acme.account`，证书落盘 `certs/acme-*.pem`
- 生产推荐二：手动放置证书（`listener.cert_path` / `key_path`），客户端使用**证书固定 (pinning)** 或私有 CA 校验
- 证书固定：节点启动日志输出证书 SHA-256 指纹，带外分发；客户端 `pinned_cert_path` 钉入后仅信任该证书，抗 MITM
- 开发：证书缺失时自动生成自签证书并**持久化**到 `./certs/`（重启不变，pinning 保持稳定）
- `insecure = true`（跳过校验）仅限开发调试，启动时打印醒目警告
- 信任策略优先级：pinning > 自定义 CA > insecure > webpki 系统根
