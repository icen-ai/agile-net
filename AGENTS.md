# AGENTS.md - AgileNet 开发与 Agent 协同规范

本文档为 AI Agent（Cindy、Claude Code、Kimi Code、Codex 等）在 **AgileNet** 项目中的开发规范、架构约定与行为准则。是唯一维护的 AI 指导文件（CLAUDE.md 仅为指向这里的引用）。

---

## 项目概览 (Project Overview)

**AgileNet** 是一个高安全、轻量级、Token 优化的 Rust 多节点网络穿透与代理链路由系统。

**产品方向（双产物，消灭 frps/frpc 式分裂）**：

- `anet-gui`：全功能图形客户端（Windows / macOS / Android），三路独立开关——客户端角色 / 服务端角色 / Web 远程面，一台有 UI 的机器勾一下即可成为内网转发机或机房留守管理端
- `anet-svc`：服务器二进制（`start` 默认 / `stop` / `restart` / `status` / `init` 首装向导 / `client` / `tui` 子命令），角色全靠配置：relay listener（扇入：接受扇入端点连入）、connector（扇出：入库一等资源，多目标扇出/容灾，可挂权限组做对端收敛；TOML `[[connectors]]` 仅启动导入）、client（终端下游）、proxy（本地代理）、api（Web 管理面）
- `anet`：管理命令入口（与 anet-svc 同一实现、按 argv[0] 分人格）：`login` / `node` / `rule` / `group` / `account` / `token` / `connector` / `admin` / `audit` / `tui`

统一与分布式管理面的完整设计（带内管理、relay 暴露控制面开关、管理可达自动发现、分期 P1→P3）见 **`docs/plan/merge-gui-svc.md`**，实施以其为准。

**当前仓库结构**（双产物统一已完成，见上述计划）：

- `crates/core`：核心网络协议（mux 帧/会话）、TLS 握手（证书固定 pinning）、Relay 穿透（listener/connector；listener 会话级 Open 洪泛防护 `MAX_INBOUND_OPENS_PER_SESSION=256`，Semaphore 限流、超限回 OpenFail）、对端收敛（`relay::PeerAcl`，扇入/扇出数据面钩子 + `ProxyRouter::matches` 复用）、会话带宽限速（`relay::limit::TokenBucket`，relay_token.rate_limit_kbps→会话读写合并令牌桶，读写泵背压生效）、客户端隧道（`ClientTunnel`）、代理入站（SOCKS5/HTTP + 认证）与路由器（`ProxyRouter`，热路径 `route_host(&str)` 零分配）、共享工具（`util` 模块：`sha256_hex` / `base64_encode` / `LoginRateLimiter` 全仓唯一来源，node 侧 `db::sha256_hex` 为再导出）。
- `crates/node`：服务端/节点库 + 二进制 **`anet-svc` / `anet`**（同一实现双入口：`start` 默认 / `stop` / `restart` / `status` / `init` / `node` / `rule` / `group` / `account` / `token` / `connector` / `admin` / `audit` / `client` / `tui` / `doctor`）：装配根 `service::NodeServer`、扇出管理 `service::connectors::ConnectorManager`（DB 为唯一事实来源，热操作）、对端收敛注册表 `service::acl::PeerAclRegistry`、SQLite（版本化迁移）、Axum REST API、Web 管理后台（`ui`）、TUI（API 优先 + DB 只读兜底）、CLI（`cli/` 目录按域 11 文件）、服务管理（`svc` 模块 PID 文件）、首装向导（`init` 模块）、内存日志缓冲、自我诊断（`tool::doctor/` 目录按域 10 文件：7 节检查 + 自动修复，CLI `anet doctor` 与 GUI `run_doctor` 共用，`run_streaming` 支持逐节流式回调）。
- `crates/client`：客户端核心引擎（库）：`lib.rs` 只做模块声明与再导出（pub API 路径不变），实现按域拆分——`client`（多节点连接：登录/配置/隧道/长轮询/心跳，规则合并与暂停 `paused_rules`，本地代理）、`credential`（凭据存储：桌面平台 OS keyring 优先存密码，0600 文件回退，旧明文自动迁移）、`config_cache`（节点配置离线缓存）、`connect_url`（接入链接解析/生成）、`custom_rules`（自定义规则）、`hosts`（系统 hosts 管理）+ 管理面 Web API（`api` 模块）、客户端角色守护（`daemon` 模块）。
- `apps/desktop`：**anet-gui**（Tauri 2 桌面/Android，独立 workspace，前端无 Node 构建链）：Rust 侧 `cmd/`（命令按域 11 模块）+ `kernel/`（mihomo sidecar 7 模块，manager.rs 以 `KernelState` 聚合结构统一管理内核状态槽位）+ 装配根 lib.rs（<300 行，AppState/run/generate_handler）；前端 `ui/app-*.js` 按域 6 文件（core/views/subscription/hero/logs/settings）+ 启动序列 app.js（普通 script 串联共享全局，index.html 依依赖序引入）+ i18n 双语（`agi18n.js` 运行时 + `aglang.js` 基础字典 + `lang/` 域分片，见 §7）：三路独立开关（客户端/服务端/Web 远程面）+ 扇出管理（connector 入库 CRUD + 权限组收敛 + 证书指纹钉值，独立菜单；监听面板可复制本机证书指纹、可设对外地址 public_host 热生效）+ 控制台窗口 + 订阅代理（mihomo sidecar 内核托管，GUI 独享）+ 系统代理托管（冲突巡检提醒 + 「锁定系统代理」硬核模式）+ 日志视图（实时连接/实时日志/命中追踪/事件中心四页签，mihomo external-controller WS 采集，右键强制打断/一键加规则，连接详情展开含链路迷你拓扑）+ 首页中控台（大总开关 proxy_power + 实时速率双序列曲线 + dstat 摘要 + 新手检查单）+ 节点页批量测速（流式 .lat 延迟分级/按延迟排序/推荐徽标）+ 托盘弹窗（tray.html：实时网速/代理组速切/连接摘要）+ 桌面悬浮球（float.html：拖拽/单双击/右键菜单/气泡通知）+ 拖拽导入本地 Clash YAML 订阅 + 设置内自我诊断（流式逐节动画）+ 性能模式（reduce_effects 关模糊动画，低配/国产 Linux）+ 窄屏底部导航 .bnav（≤720px，桌面/管理端隐藏）+ 设置同步（sync.rs：WebDAV/S3/文件三通道版本化加密存档，4 位 PIN AES-256-GCM 或明文，恢复自动备份+重启）。
- `.docker`：四级节点链编排测试（`docker-compose.test.yaml`）与常驻演示（`docker-compose.chain.yaml`）。
- `docs/plan/merge-gui-svc.md`：双产物统一实施计划；`docs/plan/subscription.md`：GUI 独享订阅代理（mihomo sidecar）实施计划；`docs/plan/tun.md`：TUN 模式（anet 在前、FlClash 在后，Windows 桌面）实施计划；`docs/todo/peer-acl.md`：对端收敛（Peer ACL，已实施）设计与实施记录；`docs/todo/island.md`：移动端系统岛规划；`docs/todo/gui-observability.md`：GUI 可观测性（日志三连/托盘/悬浮球）与 anet doctor 自我诊断实施记录。

---

## Agent 核心行为准则 (Core Rules)

1. **禁用子 Agent**：严禁直接或间接调用子 Agent 工具（如 `Agent` / `spawn_agent`），所有任务须在当前 Session 中独立高效完成。
2. **任务结束总结**：每次 Turn 或任务结束时，必须使用**中文**进行清晰、结构化的总结汇报。
3. **Token 优化**：在 Bash 执行 CLI 命令时，必须优先使用 `rtk` 前缀（如 `rtk cargo test`、`rtk git status`）。
4. **测试驱动与提交**：新增功能或修复 Bug 后，必须运行 `cargo test --workspace` 确保全部通过，通过后立即提交 Git。
5. **Windows 构建注意**：编译/测试前确认没有正在运行的本项目 exe（`anet-svc.exe` / `anet-gui.exe` 等），否则链接期文件锁失败（os error 5）；演示进程在跑时可用 `CARGO_TARGET_DIR=target/ci` 换目录跑测试。

---

## 架构与编码约定 (Architecture & Coding Idioms)

1. **Rustls 加密提供者**：
   - `rustls = "0.23"` + `ring` feature；所有初始化 TLS 配置处须显式安装过程级 Provider：
     ```rust
     let _ = rustls::crypto::ring::default_provider().install_default();
     ```
2. **数据库与 API**：
   - 数据库交互统一封装在 `crates/node/src/db/`（pool/migrations/admin/rules/accounts/connectors/logs/paginate 按域 8 文件 + mod/models，`paginate.rs` 为分页查询公共 helper，`sha256_hex` 自 `core::util` 再导出保持 `db::sha256_hex` 路径；`r2d2_sqlite` 连接池：file 池 8 / memory 池 1，WAL），版本化迁移见 `migrations.rs` 的 `MIGRATIONS`。
   - 表：`admin`, `rule`, `group`, `group_rule`, `account`, `relay_token`（含 `rate_limit_kbps` 带宽配额列 v7+）, `connector`, `node_config`, `audit_log`, `traffic_log`, `node_traffic_log`, `refresh_token`。
   - API 路由在 `crates/node/src/api/`（axum，可配内置 HTTPS）；管理接口强制 `AdminAuth`、客户端接口强制 `ClientAuth`；响应统一 `{code, data}` / `{code, message}` 信封，错误码遵循 `docs/api/overview.md`。handler 内严禁直接跑阻塞活：DB 调用一律经 `ApiState::db_call`（spawn_blocking offload），auth.rs 的 argon2id 校验/哈希与 jwt issue/refresh/revoke 同样 offload。
3. **安全硬化**：
   - 密码统一 argon2id（64MB/t=3/p=4），严禁明文存储。
   - 账号密码/Relay Token 由服务端生成（`sk-`/`psk_`/`tun_` + 48 位），明文仅创建时返回一次，库中只存 argon2id 或 SHA-256 哈希。
   - 扇出 token 可逆存储（全库唯一例外）：connector 的连接凭据由对端签发、连接时必须使用明文，只能可逆存储——AES-256-GCM 加密落库，格式 `v1:nonce_b64:ct_b64`；机器密钥 `node_config.connector_token_key` 首用生成并持久化（与 `jwt_secret` 同机制）。token 创建后永不回显（PUT 留空 = 保留原值），审计严禁记录明文与密文。
   - 扇出 TLS 校验优先级：`pinned_fingerprint`（SHA-256 钉值，DB v8+，对外分发首选）> `pinned_cert_path` > `ca_cert_path` > insecure（仅限调试）> 系统 CA。relay 证书为自签拟态证书，系统 CA 恒失败——生产扇出必须钉指纹而非勾 insecure。
   - JWT 密钥首启生成并持久化于 `node_config.jwt_secret`；refresh token jti 哈希落库，支持吊销轮换。
   - 数据面 token 比较必须常数时间（`constant_time_eq`）；认证失败按 IP 限流（20 次/分钟）并随机延迟惩罚。
   - 登录限流统一 `core::util::LoginRateLimiter`（默认 5 次/分钟/IP、连续失败 5 次锁 15 分钟，服务端管理 API 与客户端 Web 远程面共用同一实现）；管理员初始化引导另有 `bootstrap_limiter` 票据限流（10 次/分钟/IP）。
   - 密码强度策略两端统一：`api::handlers::auth::validate_password_strength`（≥10 位 + 大小写 + 数字）为唯一实现，桌面端 `set_web_password` 直接复用。
   - 客户端凭据（crates/client）：桌面平台密码存 OS keyring（Windows 凭据管理器 / macOS 钥匙串），文件只留元数据；keyring 不可用回退 0600 文件，旧明文自动迁移。
   - 敏感操作须 `record_audit_log`（含 detail 与来源 IP），严禁记录任何密码/Token 明文；管理面新增事件见 `docs/plan/merge-gui-svc.md` §9。
4. **抗指纹拟态原则（relay 数据面）**：TLS 层必须像普通 HTTPS——ALPN 恒 `h2,http/1.1`；自签证书带仿真 O/C 字段且到期日随机；首帧非法的连接按 nginx 行为回 400（严禁发 AuthFail 自报家门）；TCP 设 `set_nodelay(true)`；心跳指数分布、重连 full jitter；数据分片长度随机扰动。新增传输层行为必须先过一遍「这像不像浏览器」。
5. **端口规范**：
   - 默认端口一律 5 万段，规避 Clash 系常用端口：API `59090`、Relay listener `54430`、客户端代理 `57890`。
   - 与 Clash/FlClash 共存的组合配置见 `apps/README.md`。
5. **前端约定（Web 后台 + 桌面/Android 共用前端，均无 Node 构建链）**：
   - 图标统一内置 Lucide 内联 SVG（双端唯一图标表 `apps/desktop/ui/icons.js`：`AgIcon()` + `data-ic` 占位水合 + `AgIconHydrate(root)` 复跑），只收录用到的图标；**严禁文字表情充当图标，文档中同样不得出现文字表情**。
   - 视觉 token 对齐 Cindy 桌面端（浅色默认），见 `docs/architecture/ui-design.md`。
   - **严禁内联事件属性（onclick 等）**，一律 app.js 显式绑定或事件委托：桌面端 Tauri CSP 为 `script-src 'self'` 天然禁止；管理端（crates/node/ui）内联事件同样已清零，两端一致执行。
   - 轮询渲染必须做变更检测（签名对比），不变更不重写 DOM，避免频闪；页面隐藏时轮询必须暂停（主窗 `startMainLoops`/`stopMainLoops` 随 visibilitychange 停启，日志页 1s 轮询带内核运行/页签可见守卫）。
   - 灵动岛：显式尺寸形变 + 弹簧缓动，形变全程内容不得溢出岛体（`docs/architecture/ui-design.md` §3）。
6. **前端共享与组件沉淀（两端一致性唯一来源）**：
   - **共享 token**：`apps/desktop/ui/tokens.css` 是设计 token 的唯一权威文件（颜色/语义色/边框/文字梯度，深浅两套）。桌面端 `<link>` 引入；管理端经 `include_str!` 内嵌服务（`crates/node/src/ui/mod.rs` 引用相对路径）。**严禁在任一端的 style.css 里另起同名 token 或硬编码色值**，新增 token 一律进 tokens.css 并在 `docs/architecture/ui-design.md` 登记。
   - **管理端 SPA 文件布局**：`crates/node/ui/`（`index.html` / `app.js` / `style.css`），`mod.rs` 只做路由与内嵌（`include_str!`），**严禁再把界面代码写进 Rust 字符串**。
   - **共享组件层**：`apps/desktop/ui/components.css` 是两端共用组件样式唯一来源（桌面 `<link>`、管理端 `/ui/components.css` 同机制内嵌），当前收录 ag-select 自定义下拉（两端各自 app.js 的 `agSelectEnhance(root)` / `agSelectRefresh(sel)` 驱动）、ag-tabs 横向页签条（`agTabsBind(bar, onSwitch)`）、ahelp 行内帮助（`.ahelp` 纯 CSS hover 说明卡，共享 `ahelp(text)` helper 在 agutil.js，解释性小字一律收进 ahelp 而非常驻 hint）；端特有覆盖留各自 style.css。共享 JS 组件同机制沉淀在 `apps/desktop/ui/`（桌面 `<script src>`、管理端 `/ui/*.js` 内嵌服务）：`agchart.js`（图表：sparkline 省略版 / line 完整版，签名不变不重绘、rAF 插值过渡，两端调用 `AgChart.sparkline(el, series, opts)` / `AgChart.line(el, cfg)`）、`icons.js`（双端唯一图标表，`AgIcon()` / `data-ic` 水合 / `AgIconHydrate`）、`agutil.js`（`$` / `esc` / `ahelp`，仅收录两端语义完全一致的工具，依赖 icons.js 先加载）。
   - **组件沉淀流程**：新组件先在本端页面内实现并验证；第二次需要（或明确两端共用）时，先**泛化**（class 命名语义化、尺寸/状态走修饰类、色值只吃 token）再沉淀到共享层（tokens.css / 共享组件样式 / icons.js），随后各端改为引用共享实现。禁止把页面级一次性样式直接拷给另一端。
   - 端文案：AgileNet 对端一律称「端点」；连接方向用「扇出」（本端点主动连出，原上游）/「扇入」（对端连入本端点，原下游）；「节点」仅指订阅代理节点。
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

# 服务管理（PID 文件 ~/.agile-net/anet-svc.pid）
rtk cargo run -p agile-net-node --bin anet -- start target/tmp/test-node.toml -d
rtk cargo run -p agile-net-node --bin anet -- status
rtk cargo run -p agile-net-node --bin anet -- stop

# 管理 CLI（anet 入口；资源管理需先 login）
rtk cargo run -p agile-net-node --bin anet -- --help
rtk cargo run -p agile-net-node --bin anet -- login
rtk cargo run -p agile-net-node --bin anet -- rule list

# TUI 控制台（默认走 API 需 login；--offline 直连数据库只读兜底）
rtk cargo run -p agile-net-node --bin anet -- tui --offline

# 客户端角色（anet-svc client，原 agile-net-client daemon）
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

`anet tool` 新增依赖：`netstat2` / `default-net` / `surge-ping`（均纯 Rust、无 C 依赖、musl 静态兼容，
一律 `default-features = false` 起步；设计见 `docs/todo/cli-tool.md`，用户文档见 wiki「网络工具 anet tool」）。

## 已知地雷 (Landmines)

1. **Tauri CSP nonce 与 style 属性互斥**：Tauri 资产协议会给 `style-src` 注入 `nonce-*`，按 CSP3 规范 nonce 存在时 `'unsafe-inline'` 对 **style 属性**失效——全部 `style="display:none"` 弹窗同时弹出（黑屏风暴）。tauri.conf.json 已设 `dangerousDisableAssetCspModification: true`（关闭 Tauri 的 CSP 改写，按配置原样下发）。**严禁改回**；JS 侧 `el.style.x = ...` 属性赋值不受 CSP 影响可正常用。
2. **悬浮球是原生分层窗**（apps/desktop/src/floatball.rs：WS_EX_LAYERED + GDI+ 画圆）：严禁改回 WebView 球（WebView2 透明合成/默认白底/DWM 隐形边框在部分机器整类失效）；菜单/气泡仍是 webview 小窗，定位源 floatball::rect 静态槽。
3. **wintun 不可依赖网络下载**：download.wireguard.com 受限网络不可达，官方 0.14.1 dll 已内嵌（apps/desktop/wintun/wintun.dll，钉值校验）；SHA-256 钉值全仓唯一来源为 node 侧常量 `WINTUN_DLL_SHA256`（`crates/node/src/tool/doctor/tun.rs`，经 `tool::doctor` re-export，桌面端 `kernel/wintun.rs` 引用它校验），升级须同步三处：dll 文件本体 / node 侧 `WINTUN_DLL_SHA256` / desktop 侧 `WINTUN_VERSION`（kernel/wintun.rs）。
