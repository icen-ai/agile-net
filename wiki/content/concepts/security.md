# 安全模型

AgileNet 的安全设计假设：中继节点不可信、令牌会泄露、管理面必须可归因。

## 传输与认证

| 层 | 机制 |
| --- | --- |
| 传输加密 | 全程 TLS 1.3（`rustls` + `ring`）；relay 数据面与管理 API 均可独立启用 |
| 证书校验 | 客户端/connector 支持**证书固定（pinning）**：SHA-256 指纹钉入（`fp`，随 anet:// 链接一键分发，抗 MITM）或 PEM 证书钉入；也支持自定义 CA |
| 密码存储 | 管理员密码一律 **argon2id**（64MB / t=3 / p=4），严禁明文落库 |
| 令牌存储 | Relay Token 与委托令牌（均 `psk_` + 48 位强随机，服务端生成）、管理引导票据——**库中只存 SHA-256 哈希**，明文仅在创建时返回一次 |
| 可逆例外 | 全库仅两处 AES-256-GCM 加密落库（`v1:nonce_b64:ct_b64`，机器密钥 `node_config.connector_token_key` 首用生成）：①扇出 connector 的连接凭据（对端签发、连接必须用明文）；②委托令牌 E2E 主密钥（签发端解包 E2E 信封必须可恢复）。创建后永不回显，审计不落明文/密文 |
| 比较方式 | 数据面 token 比较必须**常数时间**（`constant_time_eq`），防时序侧信道 |
| 会话 | JWT（HS256）：admin access 15min / refresh 7d；refresh jti 哈希落库，支持吊销与轮换；JWT 密钥首启生成并持久化 |

## 抗爆破与限流

- 管理登录：按 IP 限流 5 次/分钟，连续失败 5 次锁定 15 分钟（可在 `[limits]` 配置）
- 数据面认证：按 IP 限流 20 次/分钟，失败随机延迟 150~400ms 惩罚
- 待认证连接数上限、总连接数上限（防 Slowloris 与资源耗尽）
- 控制帧 64KB / 数据帧 256KB 上限（防超大帧内存耗尽）

## 数据面 ACL

消费者隧道建立时，节点把该委托令牌引用权限组的规则并集装载为 ACL——**只能打开规则
覆盖的目标**，规则外目标在隧道入口即被拒绝。能否管理某节点同样归结为一条规则：
「有没有到其 API 地址的通路」——收回授权即失去管理通路。

### 对端收敛（Peer ACL）

权限组同时是**节点间流量**的收敛点，身份挂组（逗号分隔组集，多组取并集）：

| 身份 | 挂载点 | 缺省 |
| --- | --- | --- |
| 消费者（委托令牌） | `delegated_token.groups` | 签发必选组 |
| 扇入对端 | `relay_token.group_id` | 不收敛（放行一切） |
| 扇出对端 | `connector.group_id` | 不收敛 |

对端隧道来的流量，目标命中该对端所在组的规则集合才放行，否则在入口拒绝并记审计
（`peer.acl_denied`：对端身份 + 目标 + 来源，按对端+目标每分钟去重）；组规则热更新、
吊销令牌、禁用 connector 均实时生效。

身份域分离（主权域原则）：隧道认证只携带对端节点身份，**永不**携带对端域内终端用户身份——
收敛与审计止于端点边界，问责沿组织链传递。

### 统一签发信任档

- **direct 入口**：消费者直连签发者本机 listener，TLS 已端到端，信任档锁明文；
- **relay 入口 + E2E 组**：全部 Open 端到端加密（HKDF(token) 密钥层次、严格序列校验
  重放即断），中继只见不透明路由词 `en_xxx`（entrust 零泄露路由，签发不要求上送组
  或路由宣告）；命中 `e2e_required` 组的明文 Open **fail-close**；
- **管理档**：引导票据经 E2E 配置通道下发，**绝不明文过中继**；
- **并发执法**：single 踢旧 / multi 并存 ≤ max_sessions（签发时快照，默认 8）；
- **生命周期**：可选过期/用量上限，过期用尽后注册停送、数据面硬拒（fail-closed）。

## 审计

敏感操作全部落 `audit_log` 表（operator / action / target / detail / 来源 IP，90 天留存自动清理），
严禁记录任何密码/Token 明文。管理面事件：

| action | 触发 |
| --- | --- |
| `delegation.issue` / `delegation.revoke` / `delegation.register` | 统一签发全生命周期（不记明文） |
| `relay_token.expose_control` | 暴露控制面开关变更 |
| `relay_token.set_group` | 扇入令牌收敛组变更（含创建挂组） |
| `connector.create/update/delete/enable/disable` | 扇出对端全生命周期（不落 token 明文/密文） |
| `peer.acl_denied` | 对端流量被收敛拒绝（对端身份 + 目标 + 来源，每分钟去重） |
| `admin.session_via_relay` | 中继令牌换得管理会话 |
| `admin.console_access` | 经控制台通道访问某节点管理面 |
| `gui.role_toggle` | GUI 三路开关变更（JSONL 落 `~/.anet/gui/gui-audit.jsonl`） |
| `web.exposure_change` | Web 面监听地址/启停变更 |

原则：每条管理操作必须能回答「谁、从哪条路径（本机/隧道第几级/经哪个中继）、对哪台设备、做了什么」；
令牌级会话与真人在 operator 字段明确区分（`relay:psk_前缀@下游` / `link:标签` vs 用户名）。

## 管理面纵深

- **管理引导票据一次性/限时限次**，原子计次防重放
- **scoped admin 三档**：`ro`（只读）/ `rules`（只读+规则写）/ `full`（全权），JWT scope 声明在
  AdminAuth 层强制，未知档位 fail-closed 按只读处理
- Web 远程面默认仅 127.0.0.1，暴露 LAN 为显式配置并告警；强制先设管理密码（argon2id）
- 凭据导出/接入链接经 Web 暴露需二次确认（`confirm=true`，否则 409）
- 前端统一 `esc()` 转义渲染杜绝存储型 XSS；CSP / X-Frame-Options / nosniff 安全头；
  Tauri CSP `script-src 'self'` 禁内联事件
