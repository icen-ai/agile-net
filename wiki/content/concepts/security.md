# 安全模型

AgileNet 的安全设计假设：中继节点不可信、令牌会泄露、管理面必须可归因。

## 传输与认证

| 层 | 机制 |
| --- | --- |
| 传输加密 | 全程 TLS 1.3（`rustls` + `ring`）；relay 数据面与管理 API 均可独立启用 |
| 证书校验 | 客户端/connector 支持**证书固定（pinning）**：PEM 证书钉入或 SHA-256 指纹钉入（`fp`，随 connect_url 一键分发，抗 MITM）；也支持自定义 CA |
| 密码存储 | 管理员与客户端账号密码一律 **argon2id**（64MB / t=3 / p=4），严禁明文落库 |
| 令牌存储 | 客户端密码（`sk-`）、Relay Token（`psk_`）、隧道令牌（`tun_`）、管理引导票据（`adt_`）均由服务端生成 48 位强随机，**库中只存 SHA-256 哈希**，明文仅在创建时返回一次 |
| 比较方式 | 数据面 token 比较必须**常数时间**（`constant_time_eq`），防时序侧信道 |
| 会话 | JWT（HS256）：admin access 15min / refresh 7d；client access 1h / refresh 30d；refresh jti 哈希落库，支持吊销与轮换；JWT 密钥首启生成并持久化 |

## 抗爆破与限流

- 管理登录：按 IP 限流 5 次/分钟，连续失败 5 次锁定 15 分钟（可在 `[limits]` 配置）
- 数据面认证：按 IP 限流 20 次/分钟，失败随机延迟 150~400ms 惩罚
- 待认证连接数上限、总连接数上限（防 Slowloris 与资源耗尽）
- 控制帧 64KB / 数据帧 256KB 上限（防超大帧内存耗尽）

## 数据面 ACL

客户端隧道建立时，节点把该账号权限组的全部规则装载为 ACL——**只能打开规则覆盖的目标**，
规则外目标在隧道入口即被拒绝（docker 断言 T3）。能否管理某节点同样归结为一条规则：
「有没有到其 API 地址的通路」——收回授权即失去管理通路。

## 审计

敏感操作全部落 `audit_log` 表（operator / action / target / detail / 来源 IP，90 天留存自动清理），
严禁记录任何密码/Token 明文。管理面新增事件：

| action | 触发 |
| --- | --- |
| `account.issue_admin_link` | 签发管理版接入链接 |
| `relay_token.expose_control` | 暴露控制面开关变更 |
| `admin.session_via_relay` | 中继令牌换得管理会话 |
| `admin.console_access` | 经控制台通道访问某节点管理面 |
| `gui.role_toggle` | GUI 三路开关变更（JSONL 落 `~/.agile-net/gui-audit.jsonl`） |
| `web.exposure_change` | Web 面监听地址/启停变更 |

原则：每条管理操作必须能回答「谁、从哪条路径（本机/隧道第几级/经哪个中继）、对哪台设备、做了什么」；
令牌级会话与真人账号在 operator 字段明确区分（`relay:psk_前缀@下游` / `link:账号` vs 用户名）。

## 管理面纵深

- **管理引导票据一次性**（管理版链接场景）/ 限时限次（中继场景），原子计次防重放
- **scoped admin 三档**：`ro`（只读）/ `rules`（只读+规则写）/ `full`（全权），JWT scope 声明在
  AdminAuth 层强制，未知档位 fail-closed 按只读处理
- Web 远程面默认仅 127.0.0.1，暴露 LAN 为显式配置并告警；强制先设管理密码（argon2id）
- 凭据导出/接入链接经 Web 暴露需二次确认（`confirm=true`，否则 409）
- 前端统一 `esc()` 转义渲染杜绝存储型 XSS；CSP / X-Frame-Options / nosniff 安全头；
  Tauri CSP `script-src 'self'` 禁内联事件
