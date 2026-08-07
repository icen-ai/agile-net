# AGENTS.md - AgileNet 开发与 Agent 协同规范

本文档为 AI Agent（Cindy、Claude Code、Kimi Code、Codex 等）在 **AgileNet** 项目中的开发规范、架构约定与行为准则。是唯一维护的 AI 指导文件（CLAUDE.md 仅为指向这里的引用）。

---

## 项目概览 (Project Overview)

**AgileNet** 是一个高安全、轻量级、Token 优化的 Rust 多节点网络穿透与代理链路由系统。

**产品方向（双产物，消灭 frps/frpc 式分裂）**：

- `anet-gui`：全功能图形客户端（Windows / macOS / Android），三路独立开关——客户端角色 / 服务端角色 / Web 远程面，一台有 UI 的机器勾一下即可成为内网转发机或机房留守管理端
- `anet-svc`：服务器二进制（`start` 默认 / `stop` / `restart` / `status` / `init` 首装向导 / `client` / `tui` 子命令），角色全靠配置：relay listener（扇入：接受扇入端点与消费者连入）、connector（扇出：入库一等资源，多目标扇出/容灾，可挂权限组做对端收敛；TOML `[[connectors]]` 仅启动导入）、client（`[client]` 段进程内嵌终端 / `client` 子命令独立进程）、proxy（本地代理）、api（统一 Web 管理面）
- `anet`：管理命令入口（与 anet-svc 同一实现、按 argv[0] 分人格）：`login` / `node` / `rule` / `group` / `token` / `connector` / `admin` / `audit` / `tui` / `doctor`

**统一签发（账号体系已整体删除）**：消费者接入无账号层——资源主直接签发委托令牌
（delegated_token），令牌即唯一身份。四维度：入口 `direct`（消费者直连签发者本机
listener，TLS 端到端锁明文，自注册进本地持久注册表）| `relay`（经扇出容灾集合会合点，
注册随会话存活）× 信任档（明文 / E2E / E2E+管理档）× 路由 `dedicated` 专线 | `split`
分流 × 并发 `single` 踢旧 | `multi` 并存 ≤ `max_sessions`（签发时读 node_config
`delegation_max_sessions` 快照，默认 8）。管理端扇入/扇出页统一为「监听 | 连接 | 签发」
三页签。anet-svc 单端口统一 Web：`/` 管理端 SPA、`/client` 客户端 SPA、
`/api/v1/client/*` 走 AdminAuth 共享登录（客户端 SPA 管理端列表本机第一）。

**当前仓库结构**：

- `crates/core`：核心网络协议（mux 帧/会话；**协议 v4 唯一行为**：`FrameType::Ctrl(0x04)` 会话控制面走 channel 0，`MuxSession::start` 收 `SessionEvents{open_tx,ctrl_tx}`；`PROTOCOL_VERSION=4` 仅为握手声明常量，无版本门槛、无降级分支）、**设备身份**（`device` 模块：ring ed25519 密钥对，`device_fp=sha256(pubkey)` 自证 ID；私钥存 `~/.anet/device.key` 0600（**不进 OS keyring**，整机一份双角色共用，`DeviceIdentity::machine()` 载入、`ephemeral()` 仅供测试）；握手设备证明强制——`AuthRequest{my_name,device_pubkey,device_sig}`，签 TLS exporter secret（RFC 5705 `session_challenge`，零额外 RTT、防重放），listener 验签失败按 `device_proof_invalid` 拒连并随机延迟；**reason_code 体系**：`FailReason`（AuthFail 结构化载荷）+ Ctrl `SessionNotice`（踢断/吊销前先发原因+一次性附言：kicked/revoked_by_admin/session_takeover/issuer_offline/server_shutdown/bad_credentials/device_revoked/device_replaced/pending_approval）+ `PendingNote`（pending 会话附言上行 ≤`MAX_PENDING_NOTES=3`）；会话元数据 `session_metas()`（session_id/device_fp/pubkey/token_hash/my_name/IP/接入时间，M3 会话表数据源）、踢断 API 全部带 reason+message 且 async）、TLS 握手（证书固定 pinning）、Relay 穿透（listener/connector；listener 会话级 Open 洪泛防护 `MAX_INBOUND_OPENS_PER_SESSION=256`，Semaphore 限流、超限回 OpenFail；**委托注册表** `DelegatedRegistry`——Ctrl 帧 token_register/revoke 会话级注册，组名∩上送组、hint 必须路由回签发者、一哈希一签发者，随会话清空吊销即断；同 node_id 第二会话踢旧留新、清理按 mux 指针 `remove_if`；同 B 委托会话以 `delegated:<token_hash>` 为键，透明档盖组标、E2E 信封验 kid/hint 后盲转，`open_channel_full` 多跳逐字透传；**entrust 注册表**——`en_` 前缀 hint 免路由校验直进 `en_→签发者` 不透明表（签发 E2E 委托不要求 push_groups/advertise，零规则泄露；透明档 ACL 为空 fail-closed），`route_open` 先查 entrust 再查路由表，签发者上限 `MAX_ENTRUST_PER_ISSUER=1024`；**direct 入口本地注册表** `local_delegated`——持久、随吊销即清；**并发执法在 listener**：single 档同令牌新会话踢旧留新、multi 档并存上限 max_sessions 超限拒开）、对端收敛（`relay::PeerAcl`，扇入/扇出数据面钩子 + `ProxyRouter::matches` 复用）、**E2E**（`relay::e2e`：HKDF 密钥层次 e2e_key=HKDF(token)→信道盐子密钥 chan_key，blob 随机 nonce 信封，ChannelCipher 严格序列校验重放即断 + seq 饱和检查（seal/open 返回 Result），E2eStream 流式 AEAD；kid=哈希前 12 hex、三处查找前缀唯一；connector `DelegationHooks` 三角色：终点解包/中间跳透传/伪造硬拒，命中 e2e_required 组的明文 Open fail-close；**按目标组身份**：DelegationConfig 带 `groups` 命明明细，客户端配置通道逐组编译匹配器、分流档 seal 命中组名未命中继承全集）、会话带宽限速（`relay::limit::TokenBucket`，relay_token.rate_limit_kbps→会话读写合并令牌桶，读写泵背压生效）、客户端隧道（`ClientTunnel`，`open_channel_raw` 自定义 Open payload）、代理入站（SOCKS5/HTTP + 认证）与路由器（`ProxyRouter`，热路径 `route_host(&str)` 零分配；**入站决策 `decide_inbound` 单一优先级来源**：用户 bypass > 更窄显式路由 > 内置预置 bypass（`add_preset_bypass` 直连预置层，只赢全量兜底 0.0.0.0/0、::/0、通配域名——专线委托 LAN 保持直连）> 默认出口，采纳组/分流词表的隧道路由永不被 LAN 预置遮蔽）、连接记录（`proxy::conlog`：入站全收录 `ConnLog`——SOCKS5/HTTP 两入口 Direct/Tunnel/Forward 三臂逐连接记录 + `decide_inbound_hit` 命中层（用户放行/显式路由/预置放行/默认兜底），默认关闭全路径短路零开销；ring 5000 + active 实时计数（`CountingIo` 包客户端流）+ kill 开关（oneshot 竞速入站任务）+ unflushed 批量快照接口）、共享工具（`util` 模块：`sha256_hex` / `base64_encode`+`base64_decode` / `LoginRateLimiter` 全仓唯一来源，node 侧 `db::sha256_hex` 为再导出）、统一链接底座（`link` 模块：`anet://` **唯一 scheme** connect/fanout 双角色解析+生成，server 可带 https:// 全形式承载 API 反代；**委托链接**：`d:<label>` 标记 + `entry/entryfp` 容灾集合平行列表 + `en` entrust 词（en_xxx 零泄露路由，`entrust_id_of(token_hash)` 唯一来源）+ `emode=split` 分流档（缺省专线全量路由；E2E 配置通道保留目标 `__anet_delegation_config__` 由签发端本地应答词表，消费端拉取换选择性路由、失败回退全量）+ `eadmin=1` 管理档（DB `admin_scope` ro/rules/full；票据经配置通道下发、限 E2E，`__anet_delegation_admin__` 桥接签发端控制台，full 档 blob 目标 `upstream:<节点名>` 穿透管理上游）+ **`myname` 词**（我的名称建议值，connect/fanout 双角色，M2-T5））、`ChannelOpener` 返回 `BoxedChannel`（`AsyncChannel` blanket，opener 可包 E2eStream 对消费方透明）、联邦策略上送（`AuthRequest.groups: Vec<PushedGroupMsg>`；listener `peer_offers()` 可授权池 + `sanitize_pushed_groups` 上限清洗；connector 上送槽位变更自动重连再推，Ctrl TokenAck 存 `delegation_acks` 新会话清零；**advertise 有效集 = 手工 ∪ 上送组规则**（上送即路由声明，`effective_advertise()` 握手时并集））。
- `crates/node`：服务端/节点库 + 二进制 **`anet-svc` / `anet`**（同一实现双入口：`start` 默认 / `stop` / `restart` / `status` / `init` / `node` / `rule` / `group` / `token` / `connector` / `admin` / `audit` / `client` / `tui` / `doctor`）：装配根 `service::NodeServer`（`stop` 经 `RelayListener::shutdown_all` 关闭已建会话；`[client]` 段经 `service::client_role` 进程内嵌客户端引擎）、扇出管理 `service::connectors::ConnectorManager`（DB 为唯一事实来源，热操作；每 connector 注册 sync task——新会话全量重注册/新令牌增量注册/ack 折叠状态表，`revoke_delegated` 向容灾集合在线上游发吊销帧，同 upstream 多连接强制 `node_id#connector` 后缀；M6 cert_relay 连接器新会话全量推 CertPush、认证变更增量推）、设备门控 `service::device_gate::DeviceGateCache`（2s TTL + 写即失效；`device_pending_policy` block=未认证拒开等审批（默认）/allow=放行插灰旗；direct 入口 listener 执法、relay 入口签发者 connector 执法、扇入节点不拦）、审批中心 `service::approvals`（device_certify/device_rebind/ref_cert_adopt/topo_approve 四类型可插拔）、传递认证 `service::cert_relay`（CertRecord 起源设备密钥签名、信任名单采纳/参考降级、吊销随签名传播、本地优先、血缘列盲转）、统一签发 `service::delegation`（issue_token 明文仅一次/e2e_key 加密落库；**entrust 词自动前置**：引用组含 e2e_required 时 hint_map 首位插入 `en_<token_hash 前12hex>`；direct 入口自注册本地注册表；`DelegationEngine` 数据面执法引擎：kid→key+组名集 与 组名→规则/e2e标记 双 ArcSwap 缓存热路径零 DB，空 blob.groups 继承令牌全集；M3-T2 `device_open_gate` 签发者侧设备门控 + M6 `pending_note` 附言落审批）、对端收敛注册表 `service::acl::PeerAclRegistry`（**组集语义**：relay_token/connector 的 `group_id` 存逗号分隔多组，ACL = 成员组规则并集，单 id 直接可用；`handle(group_id, db)` 首取即时编译、rebuild 热更新已发句柄）、SQLite（**基线 v1**：预发布迁移链已塌缩为单一基线直建最终形态——无 account/traffic_log 表，delegated_token 带 entry_mode/concurrency/max_sessions/visibility 列，connector 带 cert_relay/my_name 列，新增 device_registry（设备认证状态机+逻辑持有者 subject+血缘列）/approval/approval_message/device_session（M5 会话台账）/grant_receipt（M6 回执），node_config 预置 `delegation_max_sessions=8`；版本表机制保留，正式发布后只在 MIGRATIONS 末尾追加）、Axum REST API（**统一 Web**：`/` 管理端 SPA + `/client` 客户端 SPA + `/api/v1/client/*` 客户端管理接口挂 AdminAuth 共享登录；签发 `POST /api/v1/admin/delegation/tokens` 请求体 `{label, group_ids, regs:[{connector_id,is_primary}], mode, admin_scope, entry_mode, concurrency}`，响应/列表带 `entry_mode/concurrency/max_sessions`；status 无 accounts 段；groups 无 accounts/account_count；WS 事件 `consumer.online/offline`（data.session_key，升级后首条消息认证）；M3 管理面：`GET /admin/sessions` 活会话清单 + kick/kick_token、`/admin/devices` 列表/详情/certify/revoke/rebind/policy + traffic/activity/sessions 画像三件套、`/admin/approvals` + decide 三动作、`/federation/cert`（传递认证开关+信任名单）+ `/federation/receipts`（拓扑回执）；WS 增 auth.rejected（吊销告警）/approval.new（admin_events 总线）；无 `/api/v1/admin/node/stats`）、Web 管理后台（`ui`，扇入/扇出页 ag-tabs「监听 | 连接 | 签发」三页签）、TUI（API 优先 + DB 只读兜底）、CLI（`cli/` 目录按域 10 文件，无 account）、服务管理（`svc` 模块 PID 文件）、首装向导（`init` 模块）、内存日志缓冲、二维码图片解码（`qr` 模块 rqrr，API `POST /api/v1/admin/tool/qr-decode`）、自我诊断（`tool::doctor/` 目录按域 10 文件：7 节检查 + 自动修复，CLI `anet doctor` 与 GUI `run_doctor` 共用，`run_streaming` 支持逐节流式回调）。
- `crates/client`：客户端核心引擎（**委托-only** 库；M4 感知面：`NotificationCenter` 本地持久收件箱（~/.anet/notifications.json，200 封顶，broadcast 订阅）+ `NodeStatus::PendingApproval`（设备待认证，数据面门控）/ `Blocked`（终态 reason+附言，不重连）+ `send_pending_note` 附言上行 + `with_persistent_notifications()` 生产启用）：`lib.rs` 只做模块声明与再导出（pub API 路径不变），实现按域拆分——`client`（多节点连接：`AgileNetClient::connect()` 唯一入口，纯数据面密钥无 API 往返，主入口同步首连 fail fast + 监督循环容灾切换（断开按 entry 序换入、逐入口指纹钉值、指数回退 full jitter、流量跨隧道累计），规则合并与暂停 `paused_rules`，本地代理；`DelegatedOpener` 在 en 存在时全 Open E2E 包装；委托节点注册全量路由 0.0.0.0/0+通配域名；`delegated_console_ticket`/`delegated_upstream_ticket` 管理档票据；`NodeState.label` 为显示名）、`credential`（凭据存储：桌面平台 OS keyring 优先存令牌，0600 文件回退；`Credential{addr,label,token,name?,insecure,pinned_fingerprint?,entries,entry_fps,en?,emode?,eadmin}`）、`config_cache`（分流词表离线缓存）、`connect_url`（接入链接解析/生成）、`custom_rules`（自定义规则）、`hosts`（系统 hosts 管理）+ 管理面 Web API（`api` 模块，挂到 anet-svc `/api/v1/client/*`）+ 客户端角色守护（`daemon` 模块：TOML `nodes = ["anet://..."]` 链接式）。
- `apps/desktop`：**anet-gui**（Tauri 2 桌面/Android，独立 workspace，前端无 Node 构建链）：Rust 侧 `cmd/`（命令按域 12 模块）+ `kernel/`（mihomo sidecar 7 模块，manager.rs 以 `KernelState` 聚合结构统一管理内核状态槽位）+ 装配根 lib.rs（<300 行，AppState/run/generate_handler）；前端 `ui/app-*.js` 按域 7 文件（core/views/subscription/hero/logs/settings/agent）+ 启动序列 app.js（普通 script 串联共享全局，index.html 依依赖序引入）+ i18n 双语（`agi18n.js` 运行时 + `aglang.js` 基础字典 + `lang/` 域分片，见 §7）：三路独立开关（客户端/服务端/Web 远程面）+ 扇出管理（「监听 | 连接 | 签发」三页签：监听面板可复制本机证书指纹、可设对外地址 public_host 热生效；connector 入库 CRUD + 权限组收敛 + 证书指纹钉值；统一签发四维度对话框）+ 控制台窗口 + 订阅代理（mihomo sidecar 内核托管，GUI 独享）+ 系统代理托管（冲突巡检提醒 + 「锁定系统代理」硬核模式）+ 日志视图（连接记录/实时日志/命中追踪/事件中心四页签：**连接记录 = anet 入站层全收录**（直连/隧道/订阅含放行，逐连接命中层与累计上下行，默认关闭、智能落盘；订阅臂出口细分——conlog_hosts 附 `sub_exits` 内核链标注，DIRECT→订阅放行 / REJECT→订阅拦截 / 节点名→订阅·节点，悬停见全链），右键强制打断/一键加规则；实时日志与命中追踪为 mihomo external-controller WS 采集；命中/事件 50 条/页分页）+ 首页中控台（大总开关 proxy_power + 实时速率双序列曲线 + dstat 摘要 + 新手检查单）+ 节点页批量测速（流式 .lat 延迟分级/按延迟排序/推荐徽标）+ 托盘弹窗（tray.html：实时网速/代理组速切/连接摘要）+ 桌面悬浮球（float.html：拖拽/单双击/右键菜单/气泡通知）+ 拖拽导入本地 Clash YAML 订阅 + 统一盲插导入（标题栏 link 按钮 `openUniversalImport`，扇出链接在服务端角色未启动时给一键启动；visibility=disclose/approve 链接确认步前插拓扑可见性条款卡）+ **通知中心**（node.md M4：标题栏 bell 未读角标 + 侧栏「通知」页，本机持久收件箱 ~/.anet/notifications.json，`ag-notify` Tauri 广播 + 悬浮球气泡；节点卡 Blocked 红徽章渲染 reason 映射 + 管理员附言 + 重新导入引导，PendingApproval 琥珀徽章 + 附言上行 ≤3）+ 设置内自我诊断（流式逐节动画）+ 设置页本机身份卡（设备指纹/OpenSSH 公钥可复制 + 我的名称编辑写凭据 myname + 端点认证状态回显）+ 性能模式（reduce_effects 关模糊动画，低配/国产 Linux）+ 窄屏底部导航 .bnav（≤720px，桌面/管理端隐藏）+ 设置同步（sync.rs：WebDAV/S3/文件三通道版本化加密存档，4 位 PIN AES-256-GCM 或明文，恢复自动备份+重启）+ **网络助手**（标题栏 sparkles 右侧抽屉：内置白帽 agent——BYOK OpenAI 兼容端点预设、Key 存 OS keyring、工具注册表白名单（doctor/网络探针/连接记录/系统代理状态等只读 + conlog_kill 确认闸门 fail-closed）、会话归后端（关抽屉不中断）、钉线路由（国内直连+API 域名自动放行 / 海外钉本地代理）+ 断线同历史重试、场景技能可插拔（内置 4 playbook + 用户自定义 agent-skills.json））。
- `.docker`：四级节点链编排测试（`docker-compose.test.yaml`）与常驻演示（`docker-compose.chain.yaml`）。
- `docs/architecture/`：架构（overview/security/relay-protocol/config-file/ui-design/proxy-routing）；`docs/api/`：REST 逐域文档（overview/auth/rules/groups/connectors/delegation/node）；`docs/database/schema.md`：基线 v1 schema；`docs/crate/`：crate 分层说明；`docs/todo/`：纯规划（island 移动端系统岛 / agent 网络助手后续 / embedded-ports 内嵌端口动态化 / login-lockout 限流加固）。

---

## Agent 核心行为准则 (Core Rules)

1. **禁用子 Agent**：严禁直接或间接调用子 Agent 工具（如 `Agent` / `spawn_agent`），所有任务须在当前 Session 中独立高效完成。
2. **任务结束总结**：每次 Turn 或任务结束时，必须使用**中文**进行清晰、结构化的总结汇报。
3. **Token 优化**：在 Bash 执行 CLI 命令时，必须优先使用 `rtk` 前缀（如 `rtk cargo test`、`rtk git status`）。
4. **测试驱动与提交**：新增功能或修复 Bug 后，必须运行 `cargo test --workspace` 确保全部通过，通过后立即提交 Git。
5. **Windows 构建注意**：编译/测试前确认没有正在运行的本项目 exe（`anet-svc.exe` / `anet-gui.exe` 等），否则链接期文件锁失败（os error 5）；演示进程在跑时可用 `CARGO_TARGET_DIR=target/ci` 换目录跑测试。
6. **桌面端状态同步约定**：角色/模式状态（`get_role_settings`）的跨窗一致性走 **`ag-roles` 广播**（Rust 变更点经 `cmd/roles.rs::emit_settings` 发出，主窗监听刷 `_rolesCache`+`Hero.renderMode`+TUN 翻转即刷 `refreshTun()`）+ 10s 轮询 `refreshRolesCache()` 签名守卫兜底——悬浮球/托盘与主窗是独立 JS 上下文，事件是唯一即时通道；**节点状态/管理能力变更**走 **`ag-nodes`**（client 引擎 `state_touch` Notify 全部变更点打点——连接/重连/Blocked/管理档到达/暂停——桌面 `nodes_watch` 转发，主窗监听即刷 `refreshNodes()`）；**代理开关**走 **`ag-proxy`**（全部变更路径汇聚 `report_client_proxy` 一并发出，主窗刷 `Hero.pollPower`+`refreshProxy`，托盘/悬浮球改动即时回显主窗）；**订阅内核生命周期**走 **`ag-kernel`**（KernelManager `state_touch`：启动就绪/停止/崩溃重启/放弃——`kernel_watch` 转发，主窗刷 `refreshSubStatus()`）；10s AgPulse/主循环轮询一律降为兜底；`server_status` 轮询走 `serverStatusFresh()` 在途去重（1.5s TTL），用户操作路径直连；确认弹窗一律 DOM 模态（`askConfirm`/`askPassword`），**严禁 `window.confirm`/`window.alert`**（嵌入式 WebView 返回值不可靠，且样式不一致）。
7. **无兼容包袱（pre-launch）**：产品未面世，严禁编写任何向后兼容/迁移代码——serde 兼容旧字段、旧协议版本分支、旧链接 scheme、DB 迁移链追加、旧端回退、deprecated 命令/参数 shim，一律直接改为最新形态并删除旧路径。此规则在产品正式上架后由用户本人移除。

---

## 架构与编码约定 (Architecture & Coding Idioms)

1. **Rustls 加密提供者**：
   - `rustls = "0.23"` + `ring` feature；所有初始化 TLS 配置处须显式安装过程级 Provider：
     ```rust
     let _ = rustls::crypto::ring::default_provider().install_default();
     ```
2. **数据库与 API**：
   - 数据库交互统一封装在 `crates/node/src/db/`（pool/migrations/admin/rules/relay_tokens/connectors/delegation/devices/logs/paginate 按域文件 + mod/models，`paginate.rs` 为分页查询公共 helper，`sha256_hex` 自 `core::util` 再导出保持 `db::sha256_hex` 路径；`r2d2_sqlite` 连接池：file 池 8 / memory 池 1，WAL），**基线 v1** 见 `migrations.rs`（单一基线直建最终形态；版本表机制保留，正式发布后升级只在 MIGRATIONS 末尾追加，严禁改基线）。
   - 表：`admin`, `rule`, `group`（**命名主权**：name 纯语义不再带 `@node` 后缀；唯一性 = 两个部分唯一索引 `idx_group_name_local`(name WHERE adopted_node='') + `idx_group_name_adopted`(name, adopted_node)；本机组与采纳组可同名，来源走徽章；查重一律 `get_local_group_by_name`，采纳走 `create_adopted_group` 插入即带血缘）, `group_rule`, `relay_token`（含 `rate_limit_kbps` 带宽配额列与 `expires_at`/`max_uses`/`used_count` 生命周期列）, `connector`（含 `pinned_fingerprint` 指纹钉值列、`push_groups` 策略上送组列、`cert_relay` 传递认证开关列 M6、`my_name` 上送对端自声明名列 M3-T6）, `delegated_token`（统一签发：`groups` JSON 组 ID 数组 / `hint_map` entrust 词 / `e2e_key_enc` / `mode` / `admin_scope` / `entry_mode` / `concurrency` / `max_sessions` / `visibility` 拓扑可见性档 M6 / 生命周期三列）+ `delegated_token_reg`（relay 入口容灾集合）, `device_registry`（设备注册表：`device_fp` 唯一 / `pubkey` / `subject` 逻辑持有者（换绑 `rebind_device` 迁移持有者+累计流量并吊销旧机、加绑=多设备同 subject）/ `my_name` 自声明名 / `state` pending→certified→revoked 终态 / 累计流量双列；`touch_device` 由 service 会话事件钩子驱动）, `approval`+`approval_message`（审批中心：类型可插拔、附言 appeal ≤3 / notice 单发）, `device_session`（M5 设备会话流量台账：断开 flush 一行，时序/历史/热力三吃）, `grant_receipt`（M6 拓扑可见性回执）, `node_config`（含 `public_host` / `public_api_url` 公网身份与反代端点、`delegation_max_sessions` 签发并发上限快照源）, `admin_ticket`, `audit_log`, `node_traffic_log`, `refresh_token`。relay_token/connector 的 `group_id` 均为逗号分隔组集（无外键，多组并集收敛）；API 组列响应统一结构化 `groups: [{id,name,adopted_node}]`（`group_refs_of` 解析）。
   - **令牌生命周期**：relay_token 与 delegated_token 可选过期/用量上限，NULL=永不过期/不限；写入一律 `db::normalize_expiry` 规范化 UTC Z 秒级（收 RFC3339/datetime-local），判活 `db::expiry_active`（解析失败 fail-closed）/`db::uses_exhausted`。执法点：扇入认证 `check_relay_token`（过期/用尽按未知令牌拒、命中即累 used_count）、委托令牌注册同步死令牌跳过（状态 expired/exhausted）+ `DelegationEngine` KeyEntry `alive()` 门（e2e_unwrap 硬拒/配置通道关闭，用量内存计数、refresh_keys 时刷回 DB 保重启连续）。API/控制台：签发可选过期+用量、列表 lifecycle 徽标（active/expiring<72h/expired/exhausted）。
   - API 路由在 `crates/node/src/api/`（axum，可配内置 HTTPS）；管理接口强制 `AdminAuth`；响应统一 `{code, data}` / `{code, message}` 信封，错误码遵循 `docs/api/overview.md`。handler 内严禁直接跑阻塞活：DB 调用一律经 `ApiState::db_call`（spawn_blocking offload），auth.rs 的 argon2id 校验/哈希与 jwt issue/refresh/revoke 同样 offload。
3. **安全硬化**：
   - 管理密码统一 argon2id（64MB/t=3/p=4），严禁明文存储。
   - Relay Token 与委托令牌由服务端生成（`psk_` + 48 位），明文仅创建时返回一次，库中只存 SHA-256 哈希。
   - 可逆存储例外（全库仅两处，同机制）：①扇出 token——connector 的连接凭据由对端签发、连接时必须使用明文，只能可逆存储；②委托令牌 e2e_key——签发端解包 E2E 信封必须可恢复 HKDF(token) 主密钥。均为 AES-256-GCM 加密落库，格式 `v1:nonce_b64:ct_b64`；机器密钥 `node_config.connector_token_key` 首用生成并持久化（与 `jwt_secret` 同机制）。token 创建后永不回显（PUT 留空 = 保留原值），审计严禁记录明文与密文。
   - 扇出 TLS 校验优先级：`pinned_fingerprint`（SHA-256 钉值，对外分发首选）> `pinned_cert_path` > `ca_cert_path` > insecure（仅限调试）> 系统 CA。relay 证书为自签拟态证书，系统 CA 恒失败——生产扇出必须钉指纹而非勾 insecure。
   - JWT 密钥首启生成并持久化于 `node_config.jwt_secret`；refresh token jti 哈希落库，支持吊销轮换。
   - 数据面 token 比较必须常数时间（`constant_time_eq`）；认证失败按 IP 限流（20 次/分钟）并随机延迟惩罚。
   - 登录限流统一 `core::util::LoginRateLimiter`（默认 5 次/分钟/IP、连续失败 5 次锁 15 分钟，服务端管理 API 与客户端 Web 远程面共用同一实现）；管理员初始化引导另有 `bootstrap_limiter` 票据限流（10 次/分钟/IP）。
   - 管理引导票据（relay/expose_control 握手与委托配置通道下发）：TTL 1 小时、max_uses 100（`relay_auth::RELAY_TICKET_*`；按握手/配置拉取即铸即用）。**控制台开启路径**（GUI `console_url` / Web 远程面 `open_console`）先重拉配置通道换新票据再取（长会话防 TTL 过期）；**本机内嵌面板免登录**走同一票据机制——GUI 进程为信任锚点、按次铸票，严禁「loopback 即信任」（本地任意网页都能扫回环端口，盲信等于裸奔）。
   - 密码强度策略两端统一：`api::handlers::auth::validate_password_strength`（≥10 位 + 大小写 + 数字）为唯一实现，桌面端 `set_web_password` 直接复用。
   - 客户端凭据（crates/client）：桌面平台令牌存 OS keyring（Windows 凭据管理器 / macOS 钥匙串），文件只留元数据；keyring 不可用回退 0600 文件。**设备身份私钥例外**（node.md M2）：统一存 `~/.anet/device.key` 0600 文件（不污染用户 OS keyring），整机一份、客户端/服务端角色共用。
   - 敏感操作须 `record_audit_log`（含 detail 与来源 IP），严禁记录任何密码/Token 明文。
4. **抗指纹拟态原则（relay 数据面）**：TLS 层必须像普通 HTTPS——ALPN 恒 `h2,http/1.1`；自签证书带仿真 O/C 字段且到期日随机；首帧非法的连接按 nginx 行为回 400（严禁发 AuthFail 自报家门）；TCP 设 `set_nodelay(true)`；心跳指数分布、重连 full jitter；数据分片长度随机扰动。新增传输层行为必须先过一遍「这像不像浏览器」。
5. **端口规范**：
   - 默认端口一律 5 万段，规避 Clash 系常用端口：API `59090`、Relay listener `54430`、客户端代理 `57890`。
   - 与 Clash/FlClash 共存的组合配置见 `apps/README.md`。
5. **链接与凭证载体规范**：
   - 一切可分享的技术字段必须能打包进一条链接（链接恒为三件套：入口地址 + 凭证 + 入口证书指纹）；生成与解析一律 `anet://`（**唯一 scheme**）；Rust 底座 `core::link`，前端唯一实现共享 `aglink.js`，严禁第三处解析器。
   - 签发弹窗统一「分享卡片」：端点选择（对外声明 public_host > 内网直连枚举 > 回环兜底）+ 完整链接/仅密钥 tab + 下载 .anet；API 反代端点走 `node_config.public_api_url`（scheme+端口覆盖），relay 数据面必须 L4 透传（严禁 L7 终结 TLS）。
   - `.anet` 文件：magic `ANET1` JSON 信封（role/issuer/created_at/note/payload），PIN 加密与 sync.rs 同构（格式级兼容）；导入三入口（文件选择/双击文件关联/拖拽入窗）必先展示信封元信息再确认应用；桌面经 tauri-plugin-dialog/deep-link/single-instance 落地。
   - 策略上送：扇出 connector `push_groups` → `AuthRequest.groups` → 上游可授权池（`federation/offered`，折叠本地采纳状态）→ 一键采纳（`federation/adopt` 幂等，组名 `组名@节点ID` 命名空间隔离；**采纳组 = 只读活镜像**——血缘列 adopted_node/adopted_name，`service::adoption::sync_adopted` 逐 watcher tick 漂移写跟随源规则/E2E 标记、源离线保留快照，组更新/绑规则写入口拒绝，`federation/adopted/{id}/copy` 复制为可编辑本地组）；上送内容清洗上限见 `relay::listener::MAX_PUSHED_*`。
5. **前端约定（Web 后台 + 桌面/Android 共用前端，均无 Node 构建链）**：
   - 图标统一内置 Lucide 内联 SVG（双端唯一图标表 `apps/desktop/ui/icons.js`：`AgIcon()` + `data-ic` 占位水合 + `AgIconHydrate(root)` 复跑），只收录用到的图标；**严禁文字表情充当图标，文档中同样不得出现文字表情**。
   - 视觉 token 对齐 Cindy 桌面端（浅色默认），见 `docs/architecture/ui-design.md`。
   - **严禁内联事件属性（onclick 等）**，一律 app.js 显式绑定或事件委托：桌面端 Tauri CSP 为 `script-src 'self'` 天然禁止；管理端（crates/node/ui）内联事件同样已清零，两端一致执行。
   - 轮询渲染必须做变更检测（签名对比），不变更不重写 DOM，避免频闪；页面隐藏时轮询必须暂停（主窗 `startMainLoops`/`stopMainLoops` 随 visibilitychange 停启，日志页 1s 轮询带内核运行/页签可见守卫）。列表/状态类视图的自动刷新一律挂 **`AgPulse`**（agutil.js：更新时间戳 + 间隔下拉持久化，**严禁手动刷新按钮**，间隔选项即防滥用速率下限）；动态表格渲染一律 **`AgTbl.sync`**（agtbl.js）行级 reconcile，严禁整表 innerHTML 重建。
   - 灵动岛：显式尺寸形变 + 弹簧缓动，形变全程内容不得溢出岛体（`docs/architecture/ui-design.md` §3）。
6. **前端共享与组件沉淀（两端一致性唯一来源）**：
   - **共享 token**：`apps/desktop/ui/tokens.css` 是设计 token 的唯一权威文件（颜色/语义色/边框/文字梯度，深浅两套）。桌面端 `<link>` 引入；管理端经 `include_str!` 内嵌服务（`crates/node/src/ui/mod.rs` 引用相对路径）。**严禁在任一端的 style.css 里另起同名 token 或硬编码色值**，新增 token 一律进 tokens.css 并在 `docs/architecture/ui-design.md` 登记。
   - **管理端 SPA 文件布局**：`crates/node/ui/`（`index.html` / `app.js` / `style.css`），`mod.rs` 只做路由与内嵌（`include_str!`），**严禁再把界面代码写进 Rust 字符串**。客户端 SPA 同机制（crates/client/ui）。
   - **共享组件层**：`apps/desktop/ui/components.css` 是两端共用组件样式唯一来源（桌面 `<link>`、管理端 `/ui/components.css` 同机制内嵌），当前收录 ag-select 自定义下拉（两端各自 app.js 的 `agSelectEnhance(root)` / `agSelectRefresh(sel)` 驱动）、ag-tabs 横向页签条（`agTabsBind(bar, onSwitch)`）、ahelp 行内帮助（`.ahelp` 纯 CSS hover 说明卡，共享 `ahelp(text)` helper 在 agutil.js，解释性小字一律收进 ahelp 而非常驻 hint）、**来源/认证徽章**（命名主权 M1：`.src-verify` 联邦蓝来源徽章 / `.grp-chip` 组胶囊 / `.nodebadge` 节点标识 + `.nb-auth` 认证标 / `.local` 本机标）；端特有覆盖留各自 style.css。共享 JS 组件同机制沉淀在 `apps/desktop/ui/`（桌面 `<script src>`、管理端 `/ui/*.js` 内嵌服务）：`agchart.js`（图表：sparkline 省略版 / line 完整版，签名不变不重绘、rAF 插值过渡，两端调用 `AgChart.sparkline(el, series, opts)` / `AgChart.line(el, cfg)`）、`icons.js`（双端唯一图标表，`AgIcon()` / `data-ic` 水合 / `AgIconHydrate`；`badge-check` 为唯一节点认证标）、`agutil.js`（`$` / `esc` / `ahelp` / **徽章 helpers**：`srcBadge(node,title?)` 来源徽章 / `nodeBadge(node,auth,strong?)` 认证标（auth=pin|tls，insecure 不显示）/ `grpChip({name,adopted,e2e})` 组胶囊 / `localTag()` / `connAuthTier(c)` TLS 档位派生 / **`AgPulse` 自动刷新状态件**（更新时间戳 + 间隔下拉，无手动刷新按钮，间隔选项即速率下限；页面级 `setActive` 启停，`document.hidden` 跳拍），仅收录两端语义完全一致的工具，依赖 icons.js 先加载）、`agtbl.js`（**表格框架**：`AgTbl.sync` 行级 reconcile（节点跨轮询存活、变化行原地 patch，杜绝整表 innerHTML 重建闪屏；`_agAfter` 钉住详情行随行迁移）、`AgTbl.attach` 表头隐式增强（列宽拖拽持久化 / 点击排序 asc→desc→关 / 漏斗筛选弹层文本或枚举多选，全部近零常驻视觉；语言切换自动重挂；挂接即加 `.agtbl` opt-in 类，样式选择器只认该类——桌面 `.tbl` 与管理端原生 table 通吃）、`sortState`/`filterGet`/`filters` 读取器；双端接入：桌面 `<script src>`、管理端 `/ui/agtbl.js` 内嵌，服务端分页表排序走 `db::paginate::order_clause` 白名单）、`aglink.js`（anet:// 统一链接解析器/生成器，connect/fanout 双角色含 `myname` 词；全部表单的粘贴导入/分享卡片/深链路由唯一实现，与 Rust `core::link` 行为对齐）、`aganet.js`（.anet 凭据文件构建/解析/加解密，WebCrypto PBKDF2-100k + AES-256-GCM，与 sync.rs 格式级兼容）、`agimport.js`（统一盲插导入向导 `AgImport.open(cfg)`：anet:// 链接/.anet 文件/二维码图片三载体一弹窗，解析预览 + 角色适用性门 + 扇出细节步，两端首页各接一个 cfg 落地，i18n 键 `import.*` 在 aglang.js 基础层）。
   - **组件沉淀流程**：新组件先在本端页面内实现并验证；第二次需要（或明确两端共用）时，先**泛化**（class 命名语义化、尺寸/状态走修饰类、色值只吃 token）再沉淀到共享层（tokens.css / 共享组件样式 / icons.js），随后各端改为引用共享实现。禁止把页面级一次性样式直接拷给另一端。
   - **表单控件选型定式（两端一致）**：单选维度（签发四维度这类 2-4 项互斥）一律 **agtabs 分段控件**（管理端 `segHtml/segVal/segSet/SEG_EVT`、桌面端静态 group-tabs + 各自 change 联动），**严禁原生 radio 直出**；行内单选（主入口选择、换绑选择）保留原生 radio（共享层已主题化 `accent-color: var(--accent)`）；多选列表保留 `.chk` 原生 checkbox；开/关状态一律 `.switch` 滑块。
   - 端文案：AgileNet 对端一律称「端点」；连接方向用「扇出」（本端点主动连出）/「扇入」（对端连入本端点）；「节点」仅指订阅代理节点。
7. **国际化（i18n，zh-CN + en-US 双语）**：
   - **运行时唯一来源**：`apps/desktop/ui/agi18n.js`（桌面 `<script src>`、管理端 `/ui/agi18n.js` include_str! 内嵌、wiki `assets/agi18n.js` 复制件）。API：`AgI18n.register/t(key, {name}占位)/hydrate/setLang/onChange/lang`；静态标记 `data-i18n`（文本）/`data-i18n-ph`（placeholder）/`data-i18n-title`（title）；持久化 localStorage `ag-lang`。
   - **字典**：`apps/desktop/ui/aglang.js` 是双端共享基础层（`common.*` 动作/状态 + `term.*` 术语 + `lang.*`）；各端/各域分片在 `apps/desktop/ui/lang/*.js`（desktop-html/views/sub/core/trayfloat + admin，管理端经 `/ui/lang/admin.js` 服务），均单个 `AgI18n.register` 调用合并。**新增文案先查 common.*/term.* 复用，严禁同义重复造键**；同键跨分片必须同值。
   - **文案规范**：中文官方口吻、极简、同级对称（同组菜单/按钮/表头字数对齐，如侧栏全 2 字）；英文信达雅、术语优先、菜单 Title Case、消息 sentence case。术语表见 aglang.js 头部（端点 Endpoint / 扇出 Fan-out / 扇入 Fan-in / 节点 Node / 权限组 Group …）。
   - **动态渲染**：JS 文案一律 `AgI18n.t()`，远端用户数据仍走 `esc()`；切语言后须重渲染（轮询签名检测会挡词条变更，视图要清签名或注册 `onChange` 主动重渲；自定义下拉需 `agSelectRefresh`）。
   - **文档站（wiki/）双语**：镀铬用 agi18n 运行时 + `assets/wikilang.js` 小字典；正文英文镜像 `content/en/<相同相对路径>.md`，缺失回退中文；`nav.json` 标题内联 `{zh, en}`。
   - **代码注释一律英文**（开发者读者：简短、术语化）；后端/CLI 的用户可见中文字符串字面量（错误消息、clap help、doctor 报告）暂保留中文，后续独立批次决策。

---

## 常用开发命令 (Common Commands)

所有命令均要求前缀 `rtk`：

```bash
# 编译与类型检查
rtk cargo check --workspace
rtk cargo build --workspace

# 单元与集成测试（演示进程占用 exe 时用 CARGO_TARGET_DIR=target/ci）
rtk cargo test --workspace

# 代码规范检查
rtk cargo clippy --workspace

# 启动 anet-svc（裸跑等同 start，API 59090 端口）
rtk cargo run -p agile-net-node

# 首装初始化向导（配置/管理员/系统服务/启动，交互式）
rtk cargo run -p agile-net-node --bin anet -- init

# 服务管理（PID 文件 ~/.anet/svc/anet-svc.pid）
rtk cargo run -p agile-net-node --bin anet -- start target/tmp/test-node.toml -d
rtk cargo run -p agile-net-node --bin anet -- status
rtk cargo run -p agile-net-node --bin anet -- stop

# 管理 CLI（anet 入口；资源管理需先 login）
rtk cargo run -p agile-net-node --bin anet -- --help
rtk cargo run -p agile-net-node --bin anet -- login
rtk cargo run -p agile-net-node --bin anet -- rule list

# TUI 控制台（默认走 API 需 login；--offline 直连数据库只读兜底）
rtk cargo run -p agile-net-node --bin anet -- tui --offline

# 客户端角色（anet-svc client，TOML 为 nodes = ["anet://..."] 链接式）
rtk cargo run -p agile-net-node -- client agile-net-client.toml

# 内置网络诊断工具集（anet tool，本机操作、无需 login；实现 crates/node/src/tool/）
rtk cargo run -p agile-net-node --bin anet -- tool --help

# 自我诊断报告（7 节检查 + 自动修复；--json 机器可读；有错误项退出码 1）
rtk cargo run -p agile-net-node --bin anet -- doctor

# Docker 四级链断言测试 / 常驻演示
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up --abort-on-container-exit --exit-code-from tester
docker compose -f .docker/docker-compose.chain.yaml up -d

# 发布（全自动）：打 tag 推送即全平台构建并挂载 GitHub Release，无需本地构建
git tag vX.Y.Z && git push origin vX.Y.Z   # 产物矩阵与签名现状见 docs/release.md

# Tauri 桌面/Android（独立 workspace）
cargo check --manifest-path apps/desktop/Cargo.toml
```

`anet tool` 依赖：`netstat2` / `default-net` / `surge-ping`（均纯 Rust、无 C 依赖、musl 静态兼容，
一律 `default-features = false` 起步；用户文档见 wiki「网络工具 anet tool」）。

## 已知地雷 (Landmines)

1. **Tauri CSP nonce 与 style 属性互斥**：Tauri 资产协议会给 `style-src` 注入 `nonce-*`，按 CSP3 规范 nonce 存在时 `'unsafe-inline'` 对 **style 属性**失效——全部 `style="display:none"` 弹窗同时弹出（黑屏风暴）。tauri.conf.json 已设 `dangerousDisableAssetCspModification: true`（关闭 Tauri 的 CSP 改写，按配置原样下发）。**严禁改回**；JS 侧 `el.style.x = ...` 属性赋值不受 CSP 影响可正常用。
2. **悬浮球是原生分层窗**（apps/desktop/src/floatball.rs：WS_EX_LAYERED + GDI+ 画圆）：严禁改回 WebView 球（WebView2 透明合成/默认白底/DWM 隐形边框在部分机器整类失效）；菜单/气泡仍是 webview 小窗，定位源 floatball::rect 静态槽。
3. **wintun 不可依赖网络下载**：download.wireguard.com 受限网络不可达，官方 0.14.1 dll 已内嵌（apps/desktop/wintun/wintun.dll，钉值校验）；SHA-256 钉值全仓唯一来源为 node 侧常量 `WINTUN_DLL_SHA256`（`crates/node/src/tool/doctor/tun.rs`，经 `tool::doctor` re-export，桌面端 `kernel/wintun.rs` 引用它校验），升级须同步三处：dll 文件本体 / node 侧 `WINTUN_DLL_SHA256` / desktop 侧 `WINTUN_VERSION`（kernel/wintun.rs）。
4. **系统代理看门狗进程**：接管系统代理时（engage/reclaim）会 spawn 一个无头 `anet-gui.exe --sysproxy-watchdog <pid>`（sysproxy.rs `ensure_watchdog`），它只等待主进程死亡并在快照仍在时还原系统代理——任务管理器里出现第二个无窗口 anet-gui.exe 是设计行为，不是泄漏；主进程正常退出会先 disengage 删快照，看门狗随后空转退出。**严禁**给该参数模式挂 GUI 初始化（main.rs 须在 `run()` 前拦截）；退出/卸载路径的系统代理还原一律用 `sysproxy::managed()` 谓词（system_proxy ‖ sysproxy_lock ‖ tun_mode）判定。
5. **代理"停止"必须真断连**：入站连接由 `ProxyInbound::start_on_with_shutdown` 的 JoinSet 跟踪，停止即 abort 全部隧道并等排水完成（client 引擎 `stop_proxy` 有 3s 上限）——游离连接会让 Windows 下端口重绑 EADDRINUSE（开关组合"无法开启"的根因），严禁改回 detached spawn。
6. **reqwest 默认开启 system-proxy**（0.12 默认 feature 含 `system-proxy` → hyper-util `client-proxy-system` 读 Windows 注册表系统代理）：接管系统代理后，GUI 进程内**一切未设 `no_proxy()` 的 reqwest 客户端都会被导入本机 anet 入站**（127.0.0.1:57890），loopback 控制面调用随之进隧道全灭（mihomo 控制面 59292 被劫持导致节点页退化为只读缓存的根因）。凡 loopback/语义要求"真直连"的客户端必须 `.no_proxy()`（现有：kernel/api.rs 控制面、cmd/net.rs direct 探针、cmd/delegation.rs、llm.rs 两路由）；订阅拉取/内核下载/sync 等公网客户端保留系统代理（受限网络需要）。配套地，消费端**严禁**把管理上游 api 端点注册为隐式路由（曾有的 `add_manageable_routes` 已删除）——签发端未配 public_host 时 api_host=127.0.0.1，/32 路由会把消费端整机 loopback 劫进隧道；控制台一律走 loopback 转发器（`ensure_console_forwarder` + E2E 桥接目标）。
