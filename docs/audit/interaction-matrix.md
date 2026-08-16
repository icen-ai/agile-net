# AgileNet 全组合交互矩阵（阶段 1 侦察与建模）

> 审计分支：`audit/full-attack-surface`。本文件是后续所有安全/性能审计工作的**基准表**，
> 随审计进度持续更新（「测试覆盖」列反映本轮盘点结果）。
> 生成方法：全量精读 `crates/core`（relay/proto/tunnel/proxy/device/link/util 共 ~7k 行核心路径）
> + `crates/node`（relay_auth/acme/qr/service/delegation 等）+ `crates/client`（client.rs 连接循环）
> + 三 crate 全部集成测试函数名盘点。

## 0. 对任务提示词的一处事实纠正

任务书将 `crates/core/src/relay/transit.rs` 描述为「明文/普通中转转发路径」。**经核实该描述不准确**：
`transit.rs` 实际是**中转流量记账模块（TransitMeter）**，按「来源×目的」对桥接字节做收盘记账，不承载任何转发逻辑。
真正的两条数据面路径是：

- **E2E 路径**：`relay/e2e.rs`（AES-256-GCM 信封 + HKDF 信道子密钥 + 严格序列号），
  中继只见密文；
- **明文（transparent/transit 档）路径**：`relay/listener.rs::route_open` + `relay/bridge.rs`，
  Open 载荷与 Data 帧对每一跳中继**明文可见**（仅有 TLS 逐跳加密）。

两条路径的执法点完全不同（见 §2），审计结论不可互相替代——任务书这一要求本身成立。

## 1. 组件清单（按协议栈位置）

| 层 | 模块 | 职责 | 信任的输入来源 |
|---|---|---|---|
| 传输 | `core::tunnel::tls` | TLS1.3 配置、自签拟态证书、指纹/证书钉值、(dev) insecure | 对端证书、本地 PEM |
| 传输 | `node::acme` | ACME TLS-ALPN-01 签发（ALPN 复用 relay 端口） | ACME CA |
| 帧 | `core::proto::frame` | 9 字节头帧编解码；控制帧 64KB / 数据帧 256KB 上限 | **不可信对端** |
| 消息 | `core::proto::message` | Auth/Open/Ctrl(E2E/CertPush/TokenRegister…) JSON 结构 | **不可信对端** |
| 身份 | `core::device` | ed25519 设备身份、`device_fp=sha256(pubkey)`、TLS exporter 挑战签名 | 本机私钥文件 |
| 复用 | `core::relay::mux` | 单 TLS 连接多路复用、v2 窗口流控、会话级令牌桶 | **不可信对端** |
| 扇入 | `core::relay::listener` | TLS+Auth 准入、设备证明、限流、委托注册表（会话域/本地持久/entrust/墓碑）、路由表、Open 执法 | **不可信对端**（token 持有者） |
| 扇出 | `core::relay::connector` | 上行维护（心跳/重连全抖动）、下行 Open 处理（委派钩子/多跳链/客户端隧道转售/本地拨出） | 上行（持 token 的对端） |
| E2E | `core::relay::e2e` | 信封封装/解封、信道子密钥、AEAD 流、防重放 | 持 e2e_key 的两端 |
| 记账 | `core::relay::transit` | 来源×目的字节台账（非转发路径） | 本地桥接收盘 |
| 诊断 | `core::relay::bandwidth` | 保留地址 `anet.bandwidth` echo/sink/source（ACL 前拦截） | 已认证对端 |
| 限速 | `core::relay::limit` | 会话级双方向合并令牌桶（时间债预约防惊群） | 本地配置 |
| ACL | `core::relay::acl` + `proxy::router` | 对端收敛 allowlist、入站决策 decide_inbound | 本地规则 |
| 代理 | `core::proxy::inbound/outbound` | SOCKS5/HTTP 认证入站、三臂出站 | **不可信本地应用** |
| 客户端 | `client::client` | 委托-only 引擎：容灾集切换、全量/分流路由、E2E 包装（`DelegatedOpener`） | 链接词（ek/en/entry） |
| 凭据 | `client::credential` + `core::link` | anet:// 链接解析/生成（唯一 scheme）、OS keyring | 链接/文件/二维码 |
| 签发 | `node::service::delegation` | issue_token、DelegationEngine（kid→key 缓存、组执法、e2e_required fail-close、生命周期门） | 本地管理员 |
| 扇出管理 | `node::service::connectors` | DB 唯一事实源、sync task 全量重注册/增量注册/ack 折叠、吊销帧 | 本地管理员 |
| 设备门 | `node::service::device_gate` + `approvals` | pending/certified/revoked 状态机（2s TTL 缓存） | 本地管理员 |
| 传递认证 | `node::service::cert_relay` | CertRecord 起源签名、信任名单采纳、盲转 | **不可信对端**（验证签名） |
| 管理面 | `node::api/*` + `db/*` + ui | Axum REST + SPA、AdminAuth、argon2id、审计 | **不可信网络** + 管理员 |
| 工具 | `node::qr` / `tool/*` | 二维码解码（rqrr）、网络诊断 | 不可信图片 |

## 2. 节点交互拓扑

```
消费者C ──(anet://connect + delegated_token + [en/ek])──▶ 入口Relay R ……(R 的扇入会话)…… 签发者I
                                                              │
   C 本地代理(57890 SOCKS5/HTTP) ──▶ DelegatedOpener(E2E包装) ─┘
                                                              │ 下游节点 D（I/R 经 advertise 上送路由）
管理端A ──(HTTPS 59090 AdminAuth/argon2id/JWT)──▶ 任意节点 API ◀─(ACME TLS-ALPN-01)─ CA

多跳链：C → R1 → R2 → … → Rn → I（每跳 = 一条独立 TLS+Auth 会话，Open 逐字透传 open_channel_full）
网格：N 台节点互为 潜在上行（connector）/潜在下行（listener advertise），路由表=各下行 advertise 并集
配对：二维码/链接/anet 文件（无独立配对协议——设备证明内嵌于每次 TLS 握手）
```

**四个正交维度**（任务书要求的建模）：

1. **角色**：消费者客户端（`AuthKind::Client`+delegated token）/ 扇出端点（`AuthKind::Node`+relay token，
   同时可能是签发者或纯中继或链中跳）/ 下游节点 / 管理端使用者 / ACME CA。
2. **连接方式**：direct 入口（消费者直连签发者 listener，本地持久注册表）/ relay 入口（会合点，
   注册随会话存活）/ 多跳 relay 链（`route_open`→`open_channel_full` 逐字透传，跳数无协议字段限制）/
   网格互为潜在中继（advertise 路由并集，客户端隧道规则可再转售 0.0.0.0/0）/ 本地环回代理 / ACME。
3. **加密模式**：E2E 档（中继盲转，kid=token_hash 前 12 hex 精确匹配 + hint 词汇表约束 + entrust en_ 词
   免路由披露）/ 明文档（transparent：中继可见目标与全部数据；组标在「下一跳=签发者」时保留）/
   混合链路：**协议不允许同一逻辑隧道的部分跳降级**——E2E 信封在过境跳不可拆（kid 未知→透传），
   明文 Open 命中 `e2e_required` 组在签发端 fail-close（`DelegationEngine::e2e_required_hit`），
   但「消费者选择发明文 Open」本身就是合法档位（transparent 令牌）。
4. **信任状态**：全链可信 / 单个恶意中继 / 多个共谋中继 / 恶意端点（消费者）/ 恶意签发者 /
   恶意下行节点（虚假 advertise）/ 管理面暴露面（API）。

**关键执法点速查**（安全审计的锚）：

| 执法 | 位置 | 说明 |
|---|---|---|
| TLS+首帧 Auth 10s 超时 | `listener.rs:39 AUTH_TIMEOUT` | 抗 Slowloris |
| 设备证明强制 | `listener.rs:1220` verify_device_proof（TLS exporter 挑战，防重放） | v4 起强制 |
| 认证失败限流+随机延迟 | `listener.rs:1075-1098`（20 次/分/IP）+150-400ms | |
| 常数时间比较 | `listener.rs:231 constant_time_eq` | |
| 入站 Open 洪泛上限 | `listener.rs:49 MAX_INBOUND_OPENS_PER_SESSION=256`（**仅 listener 侧**） | connector 侧缺失→见 M2 报告 |
| 委托令牌四注册表 | `delegated`（会话域）/`local_delegated`（持久）/`entrust`（en_→签发者）/墓碑 30min | |
| hint 路由回环校验 | `listener.rs:1719` 非 entrust hint 必须路由回签发者 | |
| 一哈希一签发者 / 一词一签发者 | `listener.rs:1671,1738` | |
| E2E kid/hint 一致性 | `listener.rs:2055`（中继侧）+ `DelegationEngine::e2e_unwrap`（签发侧） | |
| e2e_required fail-close | `DelegationEngine::e2e_required_hit`（`delegation.rs:538`） | 明文永不落地 |
| 组标生命周期 | `route_open`：下一跳≠签发者即清组标 | |
| 云元数据 IP 清洗 | `sanitize_pushed_groups`（169.254.169.254 覆盖网段拒绝） | |

## 3. 组合矩阵（基准表）

列说明——**跳数**：1=direct 入口；2-3=单会合点+扇出会话或一级下行；4-10=链式多跳；
>10=超长链（当前协议**无跳数上限**，见 multihop 报告 MH-1）。
**测试覆盖**：✅ 有集成测试直接构造该格；🟡 部分（相邻能力覆盖，非该格本体）；❌ 无。

### 3.1 数据面：消费者 × 入口 × 加密档 × 信任状态

| 格 | 组合 | 跳数 | 测试覆盖 | 结论摘要（详情见各报告） |
|---|---|---|---|---|
| D1 | 消费者→签发者 direct / E2E / 全可信 | 1 | ✅ `direct_issue_self_registers_and_consumes`、`e2e_client_to_internal_echo` | 信封+设备证明闭环 |
| D2 | 消费者→签发者 direct / 明文 / 全可信 | 1 | ✅ `local_registry_wins_and_persists`、`consumer_auth` | 中继=签发者自己，明文可接受 |
| D3 | 消费者→中继→签发者 / E2E / 中继恶意 | 2 | ✅ `p3_e2e_blind_relay_and_fail_close` | 中继不可解密（kid/密钥解耦）✓ |
| D4 | 消费者→中继→签发者 / 明文 / 中继恶意 | 2 | 🟡 `consumer_auth_reason` 等 | 中继可见明文——**设计取舍**，见 REPORT §决策项 |
| D5 | 消费者→中继→签发者 / E2E / 中继剥离信封降级 | 2 | ✅ fail-close 测试 | 降级为 DoS 不为明文 ✓ |
| D6 | 消费者多会话 single/multi 并发 | 2 | ✅ `single_tier_kicks_old_session`、`multi_tier_max_sessions_caps_auth` | listener 执法 ✓ |
| D7 | 消费者容灾集切换 / 墓碑窗 | 2 | ✅ `issuer_disconnect_tombstone_yields_retryable_reason`、`p2_full_chain_and_failover` | ✓ |
| D8 | 消费者→链式多跳（≥3 节点）/ E2E | 3-10 | 🟡→✅ `client_to_node_to_downstream_chain`（透明 3 跳）+ 审计新增 `open_hop_budget_kills_routing_loop`（2 节点互指环）+ `multihop_bench_test`（1-5 跳链实测） | MH 报告 §性能/环路 |
| D9 | 恶意消费者伪造 device_fp / kid / hint | 1-2 | ✅ `missing_or_forged_proof_is_rejected`、`engine_e2e_unwrap_three_roles` | fp 本地派生、kid 精确匹配 ✓ |
| D10 | 恶意消费者 Open 洪泛 | 2 | ✅ `open_flood_capped`（listener）| connector 侧不对称→发现 F2 |
| D11 | 恶意消费者透明 Open 打云元数据 | 2 | ✅ `sanitize_pushed_groups_caps` | ✓ |

### 3.2 数据面：节点×节点（扇出/扇入/网格）

| 格 | 组合 | 跳数 | 测试覆盖 | 结论摘要 |
|---|---|---|---|---|
| N1 | 扇出→上行认证（TLS 钉值/自签/insecure） | 1 | ✅ `cert_pinning_enforced`、`tls12_rejected` | 钉值>CA>insecure>系统CA ✓ |
| N2 | 上行→扇出反向 Open（PeerAcl 收敛） | 1 | ✅ `fanout_reverse_open_{allowed,denied,none}_by_acl` | 无组=不收敛（文档化） |
| N3 | 下行 advertise 路由 + 最长前缀 | 2 | ✅ `multi_node_routing_isolation`、`cidr_routing`、`longest_prefix_match` | ✓ |
| N4 | 策略组上送→采纳（联邦 P1） | 2 | ✅ `federation_push_pool_adopt_grant`、`pushed_groups_pool_and_disconnect_clear` | 命名空间隔离 ✓ |
| N5 | 传递认证 CertPush（M6）恶意起源 | 2+ | ✅ `m6_untrusted_origin_degrades_to_reference`、`m6_cert_propagation_and_revocation` | 起源签名+信任名单 ✓ |
| N6 | 恶意下行虚假 advertise（路由劫持/环路） | 2-10 | 🟡→✅ 环路：审计新增 `open_hop_budget_kills_routing_loop`（F3 已修）；劫持：见 MH-S3 决策项 | **MH-1→F3 已修** |
| N7 | 客户端隧道规则转售（0.0.0.0/0 再 advertise） | 2-3 | 🟡 `boot_fanout` 等 | 放大环路风险并入 F3（已修） |
| N8 | 上行 Open 洪泛打 connector | 1 | ❌→✅ 审计新增 `connector_open_flood_capped`（F2 已修） | **发现 F2（已修）** |
| N9 | 带宽诊断保留地址（ACL 前拦截） | 1 | ✅ `bandwidth_*_serves_before_acl` | 设计文档化；1GiB/请求上限 |

### 3.3 控制面 / 管理面

| 格 | 组合 | 测试覆盖 | 结论摘要 |
|---|---|---|---|
| M1 | 管理员登录（argon2id、限流、防枚举） | ✅ `login_oracle_prevented`、`login_bruteforce_lockout` | ✓ |
| M2 | JWT 伪造/刷新轮换 | ✅ `jwt_forgery_rejected`、`refresh_token_rotation_and_revocation` | ✓ |
| M3 | 管理票据（relay 握手/委托配置通道，TTL 1h/100 次） | ✅ `handshake_v2_control_offer_and_manageable_discovery`、`p3_delegated_admin_and_transit_management` | ✓ |
| M4 | API 注入/XSS/大包/未授权 | ✅ `sql_injection_safe`、`xss_payload_stored_safely`、`oversized_body_rejected`、`authorization_enforced` | ✓ |
| M5 | 审计无凭据泄露 | ✅ `audit_log_no_credential_leak` | ✓ |
| M6 | ACME 劫持/私钥权限 | 🟡 `challenge_cert_has_acme_identifier`（单元）；无劫持对抗测试 | 低风险（TLS-ALPN-01 域验证） |
| M7 | QR/链接导入（不可信链接/图片） | 🟡 `delegated_params`/`connect_params` 解析测试 | 解析纯函数、无执行语义 |
| M8 | 客户端 Web API（/api/v1/client/*） | ✅ `web_api_test` | ✓ |

### 3.4 依赖与供应链

| 项 | 状态 |
|---|---|
| `cargo audit` / `cargo deny` | 仓库未安装二者配置；以 `cargo tree` 人工核对关键加密/解析依赖版本（REPORT 附录） |

## 4. 审计交付物索引

- `docs/audit/interaction-matrix.md` — 本文件（基准表）
- `docs/audit/findings.md` — 阶段 2 逐格安全发现（STRIDE 归类、触发路径、复现、修复建议）
- `docs/audit/multihop-scale-report.md` — 阶段 2.5 多跳与规模化专项
- `docs/audit/REPORT.md` — 执行摘要与总交付
