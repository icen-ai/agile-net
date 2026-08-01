# AGENTS.md - AgileNet 开发与 Agent 协同规范

本文档为 AI Agent（Cindy、Claude Code、Kimi Code、Codex 等）在 **AgileNet** 项目中的开发规范、架构约定与行为准则。是唯一维护的 AI 指导文件（CLAUDE.md 仅为指向这里的引用）。

---

## 项目概览 (Project Overview)

**AgileNet** 是一个高安全、轻量级、Token 优化的 Rust 多节点网络穿透与代理链路由系统。

**产品方向（双产物，消灭 frps/frpc 式分裂）**：

- `anet-gui`：全功能图形客户端（Windows / macOS / Android），三路独立开关——客户端角色 / 服务端角色 / Web 远程面，一台有 UI 的机器勾一下即可成为内网转发机或机房留守管理端
- `anet-svc`：服务器二进制（`start` 默认 / `stop` / `restart` / `status` / `init` 首装向导 / `client` / `tui` 子命令），角色全靠配置：relay listener（扇入：接受扇入端点连入）、connector（扇出：`[[connectors]]` 多目标扇出/容灾）、client（终端下游）、proxy（本地代理）、api（Web 管理面）
- `anet`：管理命令入口（与 anet-svc 同一实现、按 argv[0] 分人格）：`login` / `node` / `rule` / `group` / `account` / `token` / `admin` / `audit` / `tui`

统一与分布式管理面的完整设计（带内管理、relay 暴露控制面开关、管理可达自动发现、分期 P1→P3）见 **`docs/plan/merge-gui-svc.md`**，实施以其为准。

**当前仓库结构**（双产物统一已完成，见上述计划）：

- `crates/core`：核心网络协议（mux 帧/会话）、TLS 握手（证书固定 pinning）、Relay 穿透（listener/connector）、客户端隧道（`ClientTunnel`）、代理入站（SOCKS5/HTTP + 认证）与路由器（`ProxyRouter`）。
- `crates/node`：服务端/节点库 + 二进制 **`anet-svc` / `anet`**（同一实现双入口：`start` 默认 / `stop` / `restart` / `status` / `init` / `node` / `rule` / `group` / `account` / `token` / `admin` / `audit` / `client` / `tui`）：装配根 `service::NodeServer`、SQLite（版本化迁移）、Axum REST API、Web 管理后台（`ui`）、TUI（API 优先 + DB 只读兜底）、CLI（`cli` 模块）、服务管理（`svc` 模块 PID 文件）、首装向导（`init` 模块）、内存日志缓冲。
- `crates/client`：客户端核心引擎（库）：多节点连接（登录/配置/隧道/长轮询/心跳）、规则合并与暂停（`paused_rules`）、本地代理、hosts 管理、凭据存储、管理面 Web API（`api` 模块）、客户端角色守护（`daemon` 模块）。
- `apps/desktop`：**anet-gui**（Tauri 2 桌面/Android，独立 workspace，前端无 Node 构建链）：三路独立开关（客户端/服务端/Web 远程面）+ 扇出管理（`[[connectors]]` 多目标，独立菜单）+ 控制台窗口 + 订阅代理（mihomo sidecar 内核托管，GUI 独享）+ 系统代理托管（冲突巡检提醒）。
- `.docker`：四级节点链编排测试（`docker-compose.test.yaml`）与常驻演示（`docker-compose.chain.yaml`）。
- `docs/plan/merge-gui-svc.md`：双产物统一实施计划；`docs/plan/subscription.md`：GUI 独享订阅代理（mihomo sidecar）实施计划；`docs/plan/tun.md`：TUN 模式（anet 在前、FlClash 在后，Windows 桌面）实施计划；`docs/todo/island.md`：移动端系统岛规划。

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
   - 数据库交互统一封装在 `crates/node/src/db/`（`r2d2_sqlite` 连接池：file 池 8 / memory 池 1，WAL），版本化迁移见 `MIGRATIONS`。
   - 表：`admin`, `rule`, `group`, `group_rule`, `account`, `relay_token`, `node_config`, `audit_log`, `traffic_log`, `refresh_token`。
   - API 路由在 `crates/node/src/api/`（axum，可配内置 HTTPS）；管理接口强制 `AdminAuth`、客户端接口强制 `ClientAuth`；响应统一 `{code, data}` / `{code, message}` 信封，错误码遵循 `docs/api/overview.md`。
3. **安全硬化**：
   - 密码统一 argon2id（64MB/t=3/p=4），严禁明文存储。
   - 账号密码/Relay Token 由服务端生成（`sk-`/`psk_`/`tun_` + 48 位），明文仅创建时返回一次，库中只存 argon2id 或 SHA-256 哈希。
   - JWT 密钥首启生成并持久化于 `node_config.jwt_secret`；refresh token jti 哈希落库，支持吊销轮换。
   - 数据面 token 比较必须常数时间（`constant_time_eq`）；认证失败按 IP 限流（20 次/分钟）并随机延迟惩罚。
   - 敏感操作须 `record_audit_log`（含 detail 与来源 IP），严禁记录任何密码/Token 明文；管理面新增事件见 `docs/plan/merge-gui-svc.md` §9。
4. **端口规范**：
   - 默认端口一律 5 万段，规避 Clash 系常用端口：API `59090`、Relay listener `54430`、客户端代理 `57890`。
   - 与 Clash/FlClash 共存的组合配置见 `apps/README.md`。
5. **前端约定（Web 后台 + 桌面/Android 共用前端，均无 Node 构建链）**：
   - 图标统一内置 Lucide 内联 SVG（Web 端 `ic()` / 桌面端 `AgIcon()` + `data-ic` 占位水合），只收录用到的图标；**严禁文字表情充当图标，文档中同样不得出现文字表情**。
   - 视觉 token 对齐 Cindy 桌面端（浅色默认），见 `docs/architecture/ui-design.md`。
   - 桌面端 Tauri CSP 为 `script-src 'self'`：**严禁内联事件属性（onclick 等）**，一律 app.js 显式绑定或事件委托。
   - 轮询渲染必须做变更检测（签名对比），不变更不重写 DOM，避免频闪。
   - 灵动岛：显式尺寸形变 + 弹簧缓动，形变全程内容不得溢出岛体（`docs/architecture/ui-design.md` §3）。
6. **前端共享与组件沉淀（两端一致性唯一来源）**：
   - **共享 token**：`apps/desktop/ui/tokens.css` 是设计 token 的唯一权威文件（颜色/语义色/边框/文字梯度，深浅两套）。桌面端 `<link>` 引入；管理端经 `include_str!` 内嵌服务（`crates/node/src/ui/mod.rs` 引用相对路径）。**严禁在任一端的 style.css 里另起同名 token 或硬编码色值**，新增 token 一律进 tokens.css 并在 `docs/architecture/ui-design.md` 登记。
   - **管理端 SPA 文件布局**：`crates/node/ui/`（`index.html` / `app.js` / `style.css`），`mod.rs` 只做路由与内嵌（`include_str!`），**严禁再把界面代码写进 Rust 字符串**。
   - **组件沉淀流程**：新组件先在本端页面内实现并验证；第二次需要（或明确两端共用）时，先**泛化**（class 命名语义化、尺寸/状态走修饰类、色值只吃 token）再沉淀到共享层（tokens.css / 共享组件样式 / icons.js），随后各端改为引用共享实现。禁止把页面级一次性样式直接拷给另一端。
   - 端文案：AgileNet 对端一律称「端点」；连接方向用「扇出」（本端点主动连出，原上游）/「扇入」（对端连入本端点，原下游）；「节点」仅指订阅代理节点。

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

# Docker 四级链断言测试 / 常驻演示
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up --abort-on-container-exit --exit-code-from tester
docker compose -f .docker/docker-compose.chain.yaml up -d

# 发布（全自动）：打 tag 推送即全平台构建并挂载 GitHub Release，无需本地构建
git tag vX.Y.Z && git push origin vX.Y.Z   # 产物矩阵与签名现状见 docs/release.md

# Tauri 桌面/Android（独立 workspace）
cargo check --manifest-path apps/desktop/Cargo.toml
```
