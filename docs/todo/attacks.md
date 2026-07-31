# AgileNet Security Audit — Attack Surface & Confirmed Vulnerabilities

> 审计时间: 2026-08-01
> 审计范围: `crates/core` + `crates/node` + `crates/client` 全部源码（含 dead code）
> 标准: 仅收录"一定被攻破 / 一定是漏洞"的确认项，拒绝理论风险灌水

---

## P0 — 必须立即修复

### ATK-001 SOCKS5 IPv6 ATYP 值错误 — IPv6 代理全面失效

| 字段 | 值 |
|------|-----|
| 文件 | `crates/core/src/proxy/inbound.rs:314` |
| 类型 | 协议实现错误 |
| 影响 | IPv6 ACL 规则完全失效；标准 SOCKS5 客户端 IPv6 请求被拒 |

RFC 1928 规定 IPv6 ATYP = `0x04`，代码使用 `0x06`。

- 任何标准 SOCKS5 客户端发送 IPv6 请求 → ATYP=0x04 → 落入 `unsupported SOCKS5 ATYP` 分支被拒绝
- 所有 IPv6 流量无法经 SOCKS5 代理 → 对应 ACL 规则形同虚设
- 仅自定义客户端（也用 0x06）可通过，形成隐性不兼容

**修复**: `0x06` → `0x04`

---

### ATK-002 自连接防护不完整 — 0.0.0.0 监听可被 DoS 崩溃

| 字段 | 值 |
|------|-----|
| 文件 | `crates/core/src/proxy/inbound.rs:187-189` |
| 类型 | 逻辑缺陷 |
| 影响 | 本地/内网用户可使代理进程崩溃 |

```rust
fn is_self_connect(ctx: &InboundCtx, addr: &SocketAddr) -> bool {
    *addr == ctx.listen_addr  // 精确比对 0.0.0.0:1080
}
```

监听 `0.0.0.0:1080` 时，`CONNECT 127.0.0.1:1080` 不会匹配 → 代理向自己建连 → 无限递归 → 连接数耗尽/栈溢出/进程崩溃。

**攻击**: 发送一个 `CONNECT 127.0.0.1:1080` 即可触发。

**修复**: 检查端口匹配 + IP 是否为本机任意地址（127.0.0.1、::1、所有本机网卡 IP），或当绑定 0.0.0.0 时匹配所有 loopback/local 地址。

---

## P1 — 应尽快修复

### ATK-003 Refresh Token 端点无速率限制

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/api/handlers/auth.rs` (refresh handler) |
| 类型 | 缺少防护 |
| 影响 | 被盗 refresh token 可发动 DoS；tunnel_token 写入风暴 |

`POST /api/v1/auth/login` 有 `login_limiter.check(ip)` 保护（5次/分钟/IP + 锁定），
`POST /api/v1/auth/refresh` **无任何速率限制**。

攻击者获得一个有效 refresh token 后可无限高速调用：
- 每次调用执行 DB 写入（revoke old + store new refresh token + 轮换 tunnel_token）
- 大量并发直接可拖垮 SQLite WAL
- 同时产生大量有效 access token

**修复**: 对 refresh 端点添加独立速率限制器（如 10次/分钟/IP）。

---

### ATK-004 WebSocket 事件端点通过 URL 查询参数传递 access_token

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/api/handlers/node.rs:391-416` + `crates/node/src/ui/mod.rs:444` |
| 类型 | 信息泄露 |
| 影响 | admin access_token 可被日志/历史/中间代理捕获 |

```
ws://host/api/v1/admin/node/events?token=<ACCESS_TOKEN>
```

Token 会出现在:
- Web 服务器 / 反向代理访问日志
- 浏览器历史记录
- CDN / WAF 日志
- Referer 头（如页面含外部资源）

15 分钟有效期内，攻击者从日志获取即可拥有完整管理员权限。

**修复**: 改用连接建立后首条 WebSocket 消息传递 token，或签发短期一次性 ticket。

---

### ATK-005 WebSocket 事件端点缺少 scope 权限检查

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/api/handlers/node.rs:396-402` |
| 类型 | 授权绕过 |
| 影响 | `scope: "ro"` 管理员可访问不该有权的实时事件流 |

手动验证只检查 `role == "admin"`，跳过了 `AdminAuth` 提取器的 scope 框架。
`scope: "ro"` 的只读管理员可实时监控全部客户端上下线 + 流量统计。

**修复**: 增加 scope 检查，保持与其他 admin 端点一致。

---

## P2 — 应当修复

### ATK-006 LoginRateLimiter DashMap 无上限增长 — 慢速内存泄漏

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/api/mod.rs:146-148` |
| 类型 | 资源耗尽 |
| 影响 | 长期运行节点可能 OOM |

`DashMap<IpAddr, LoginAttempts>` 只在 `record_success` 时 remove，失败条目永不过期。
攻击者用大量不同 IP 发登录请求 → 每个 IP 创建永久条目 → 内存缓慢增长。

**修复**: 添加定期清理任务（如每 5 分钟清理超过 30 分钟未活动的条目）。

---

### ATK-007 Connect URL 内存缓存包含明文密码

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/api/mod.rs:65` + `crates/node/src/api/handlers/accounts.rs:458` |
| 类型 | 敏感数据暴露 |
| 影响 | 进程内存 dump 可提取明文密码 |

创建/重置账号后明文密码嵌入 URL 缓存 10 分钟:
```
agilenet://connect?...&password={password}
```

Core dump、调试器附加、`/proc/pid/mem` 读取均可提取。

**修复**: 缩短缓存时间至 2-3 分钟；或改为加密存储 + 取用时解密。

---

### ATK-008 Dead Code — routes.rs 引用不存在的类型

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/api/handlers/routes.rs` |
| 类型 | 代码卫生 |
| 影响 | 误导开发者；若被错误启用可引入未经审计的接口 |

引用 `AuthClaims`、`state.db.list_routes()`、`state.router`、`RoutePatternType` 等不存在的类型。
未注册到 API router，不会编译进产物，但属于安全审计的噪声源。

**修复**: 删除或重写。

---

### ATK-009 客户端默认 HTTP 明文传输登录凭据

| 字段 | 值 |
|------|-----|
| 文件 | `crates/client/src/lib.rs:1357-1362` |
| 类型 | 信息泄露 |
| 影响 | 管理密码在网络上以明文传输，可被中间人嗅探 |

```rust
fn api_base_url(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.trim_end_matches('/').to_string()
    } else {
        format!("http://{}", addr.trim_end_matches('/')) // ← 默认 HTTP
    }
}
```

用户通过最常见的 `host:port` 格式连接节点时（如 `192.168.1.100:59090`），`POST /api/v1/auth/login` 中的 `username` + `password` 将以 **明文 HTTP** 传输。同一链路上的攻击者可直接嗅探到管理凭据。

connect URL (`agilenet://connect?...`) 解析后也走同样路径，密码同样明文传输。

**修复**: 默认使用 `https://`；若需 HTTP 降级应要求用户显式声明 `insecure` 或 `http://` 前缀。

---

### ATK-010 seed_admin_from_env 密码复杂度校验缺失

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/service/mod.rs:540-541` |
| 类型 | 弱认证 |
| 影响 | Docker/自动化部署可创建弱密码管理员 |

```rust
if password.len() < 10 {
    anyhow::bail!("AGILE_ADMIN_PASSWORD must be at least 10 characters");
}
// 无大小写/数字/特殊字符校验 ← 与 /api/v1/auth/init 不一致
```

`/api/v1/auth/init` 端点要求密码包含大小写字母和数字（10+ 字符），但 `AGILE_ADMIN_PASSWORD` 环境变量仅检查长度 ≥ 10。

Docker 部署场景中 `AGILE_ADMIN_PASSWORD=aaaaaaaaaa` 即可创建管理员 → 极易被字典攻击破解。

**修复**: 复用 `validate_password_complexity()` 逻辑，拒绝纯小写/纯数字等弱密码。

---

### ATK-011 客户端离线缓存含明文 tunnel_token + refresh_token（Windows 无权限保护）

| 字段 | 值 |
|------|-----|
| 文件 | `crates/client/src/lib.rs:329-342,381-389` |
| 类型 | 敏感数据暴露 |
| 影响 | Windows 上任意本地进程可读取隧道令牌和刷新令牌 |

`CachedNodeConfig` 结构体缓存于 `~/.agile-net/cache/*.json`：
```rust
pub struct CachedNodeConfig {
    pub tunnel_token: String,    // 明文隧道令牌
    pub refresh_token: String,   // 明文刷新令牌
    // ...
}
```

文件权限保护仅在 Unix 下通过 `#[cfg(unix)]` 设置 0600。**Windows 上该文件对所有本地用户可读**。

同样的问题也存在于：
- `CredentialStore`（`~/.agile-net/credentials.json`）— 含明文密码
- CLI session 文件（`~/.anet/session.json`）— 含 access/refresh token

攻击者获取这些文件中的 refresh_token 后可持续刷新获取新 access_token。

**修复**: Windows 上使用 DPAPI 加密或 ACL 限制；或对敏感字段加密存储。

---

### ATK-012 Dead Code — nodes.rs / system.rs 使用错误的鉴权提取器

| 字段 | 值 |
|------|-----|
| 文件 | `crates/node/src/api/handlers/nodes.rs` + `crates/node/src/api/handlers/system.rs` |
| 类型 | 代码卫生（潜在授权绕过） |
| 影响 | 若被错误启用将允许任意有效 JWT（含 client 角色）操作系统配置 |

这两个文件使用 `AuthClaims` 直接提取器而非 `AdminAuth`：
```rust
pub async fn list_nodes(_claims: AuthClaims, ...) -> impl IntoResponse { ... }
pub async fn set_config(_claims: AuthClaims, ...) -> impl IntoResponse { ... }
```

`AuthClaims` 仅验证 JWT 签名有效，**不检查 role 和 scope**。若这些端点被误接入路由：
- Client 角色 token 可操作节点列表和修改系统配置
- 无 scope 检查（`ro` 管理员可执行写操作）

当前两个文件未在 `handlers/mod.rs` 中导出，与 `routes.rs` 一同归为 dead code（ATK-008 升级合并）。

**修复**: 删除或重写为使用 `AdminAuth` 提取器。

---

### ATK-013 客户端 Web API LoginRateLimiter 同样存在无上限内存增长

| 字段 | 值 |
|------|-----|
| 文件 | `crates/client/src/api.rs:400-470` |
| 类型 | 资源耗尽 |
| 影响 | 长期运行的客户端守护进程可能 OOM |

与服务端 ATK-006 完全相同的模式：`DashMap<IpAddr, LoginAttempts>` 无过期淘汰。
`record_success` 会 remove，但登录失败的条目永远留存。

**修复**: 同 ATK-006，添加定期清理。

---

### ATK-014 client/api.rs init_password 密码复杂度校验不足

| 字段 | 值 |
|------|-----|
| 文件 | `crates/client/src/api.rs:370-376` |
| 类型 | 弱认证 |
| 影响 | 客户端 Web 管理可设置弱密码 |

```rust
if req.password.len() < 10 {
    return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "管理密码至少 10 位");
}
```

仅检查长度，无大小写/数字复杂度要求（与 ATK-010 同类问题）。

**修复**: 添加与服务端一致的密码复杂度校验。

---

## 安全设计亮点

| 设计 | 评价 |
|------|------|
| Argon2id (64MB/t=3/p=4) | OWASP 推荐参数 ✅ |
| constant_time_eq 凭证比对 | SOCKS5 auth / HTTP Basic / relay token ✅ |
| JWT secret 自动生成 256-bit | 持久化 DB，不硬编码 ✅ |
| Refresh token 轮换 + jti 吊销 | 每次 refresh 签发新 token ✅ |
| TLS 1.3 Only (rustls) | 不支持降级 ✅ |
| 帧大小限制 | 控制帧 64KB / 数据帧 256KB ✅ |
| Relay listener 多层认证保护 | 10s 超时 / 256 pending / 20 fail/min/IP / 随机延迟 ✅ |
| Scope fail-closed | 未知 scope 默认仅允许 GET ✅ |
| XSS 防护 | `esc()` 转义 + CSP + X-Frame-Options: DENY ✅ |
| 一次性票据 | SHA-256 哈希存储，兑换即失效 ✅ |
| API handler 输入校验 | 规则/组/账号全覆盖 + 批量导入上限 500 ✅ |
| 删除操作安全 | force 参数保护 + 关联引用计数预检 ✅ |
| 审计日志 | 全管理操作 + IP + 操作人 + 目标 ✅ |
| 凭据导出二次确认 | 客户端 Web API 必须 confirm=true ✅ |
| 离线缓存 Unix 权限 | credential/cache/session 均 0600 ✅ |
| 帧协议 DoS 防护 | 控制帧 64KB / 数据帧 256KB 上限 + per-channel 流控 ✅ |
| MuxSession 通道上限 | 单会话 1024 通道 + 1MiB 窗口流控 ✅ |
