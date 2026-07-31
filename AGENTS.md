# AGENTS.md - AgileNet 开发与 Agent 协同规范

本文档为 AI Agent（包括 Cindy、Claude Code、Codex 等）在 **AgileNet** 项目中的开发规范、架构约定与行为准则。

---

## 📌 项目概览 (Project Overview)

**AgileNet** 是一个高安全、轻量级、Token 优化的 Rust 多节点网络穿透与代理链路由系统。

- **工作区路径**：`C:\Users\thatc\.workspace\icen\agile-net`
- **语言与版本**：Rust (Edition 2024 / Cargo Workspace)
- **主要组件**：
  - `crates/core`：核心网络协议（mux 帧/会话）、TLS 握手（证书固定 pinning）、Relay 穿透（listener/connector）、客户端隧道 (`ClientTunnel`)、代理入站（SOCKS5/HTTP + 认证）与路由器 (`ProxyRouter`)。
  - `crates/node`：服务端/节点代理服务 (`agile-net-node`)，包含 SQLite 数据库（版本化迁移）、Axum REST API（docs/api 规格）、Web 管理后台 (`ui`)、TUI 终端与内存日志缓冲 (`logs`)。
  - `crates/cli`：命令行工具 `anet` (基于 Clap Derive)，支持 `login`, `logout`, `status`, `rule`, `group`, `account`, `token`, `audit`, `tui` 等子命令，会话持久化于 `~/.anet/session.json`。
  - `crates/client`：客户端核心引擎 (`agile-net-client`)，管理多节点连接（登录/配置/隧道/长轮询/心跳）、路由规则合并、本地 SOCKS5/HTTP 代理、hosts 管理及凭据存储 (`CredentialStore`)。
  - `apps/desktop`：Tauri 2 桌面（Windows）与 Android 客户端（独立 workspace，前端无 Node 构建链）。
  - `.docker`：深度链路部署测试（四级节点链 compose + 断言脚本）。

---

## ⚙️ Agent 核心行为准则 (Core Rules)

1. **禁用子 Agent**：严禁直接或间接调用子 Agent 工具（如 `Agent` / `spawn_agent`），所有任务须在当前 Session 中独立高效完成。
2. **任务结束总结**：每次 Turn 或任务结束时，必须使用**中文**进行清晰、结构化的总结汇报。
3. **Token 优化**：在 Bash 执行 CLI 命令时，必须优先使用 `rtk` 前缀（如 `rtk cargo test`, `rtk git status`, `rtk cargo check`）以最大化 Token 节约。
4. **测试驱动与提交**：新增功能或修复 Bug 后，必须运行 `cargo test --workspace` 确保所有单元测试与集成测试通过，测试通过后立即提交 Git。

---

## 🏛️ 架构与编码约定 (Architecture & Coding Idioms)

1. **Rustls 加密提供者**：
   - 使用 `rustls = "0.23"` 且启用了 `ring` feature。
   - 所有初始化 TLS 配置（如 `TlsConfigBuilder`）处均须显式安装过程级 Provider：
     ```rust
     let _ = rustls::crypto::ring::default_provider().install_default();
     ```
2. **数据库与 API**：
   - 数据库交互统一封装在 `crates/node/src/db/`（`r2d2_sqlite` 连接池：file 池 8 / memory 池 1，WAL 模式），版本化迁移见 `MIGRATIONS`。
   - 包含的表：`admin`, `rule`, `group`, `group_rule`, `account`, `relay_token`, `node_config`, `audit_log`, `traffic_log`, `refresh_token`。
   - API 路由定义在 `crates/node/src/api/`（基于 `axum`，可配内置 HTTPS），管理接口强制 `AdminAuth` 提取器（admin 角色）、客户端接口强制 `ClientAuth`；响应统一 `{code, data}` / `{code, message}` 信封，错误码遵循 `docs/api/overview.md`。
3. **安全硬化**：
   - 用户与客户端账号密码统一采用 `argon2id`（64MB/t=3/p=4）加密哈希，严禁明文存储。
   - 账号密码/Relay Token 由服务端生成（`sk-`/`psk_`/`tun_` + 48 位），明文仅创建时返回一次，数据库只存 argon2id 或 SHA-256 哈希。
   - JWT 密钥首次启动生成并持久化于 `node_config.jwt_secret`；refresh token jti 哈希落库，支持吊销与轮换。
   - 数据面 token 比较必须常数时间（`constant_time_eq`）；认证失败按 IP 限流（20 次/分钟）并随机延迟惩罚。
   - 敏感操作（登录/增删改/启停/重置/吊销）须调用 `record_audit_log` 记录系统审计日志（含 detail 与来源 IP），严禁记录任何密码/Token 明文。
4. **前端 SPA 与嵌入式 UI**：
   - `crates/node/src/ui/mod.rs` 嵌入单页 Web Dashboard。
   - 原生 JavaScript 交互使用 `async function fnFetch(...)` 确保包含 Bearer Token 并在 401 时跳转登录。

---

## 🧪 常用开发命令 (Common Commands)

所有命令均要求前缀 `rtk`：

```bash
# 编译与类型检查
rtk cargo check --workspace
rtk cargo build --workspace

# 单元与集成测试
rtk cargo test --workspace

# 代码规范检查
rtk cargo clippy --workspace

# 启动 Node 服务 (默认 9090 端口)
rtk cargo run -p agile-net-node

# 使用 CLI 工具 anet
rtk cargo run -p anet -- --help

# Docker 深度链路部署测试（四级节点链）
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up --abort-on-container-exit --exit-code-from tester

# Tauri 桌面/Android 客户端（独立 workspace）
cargo check --manifest-path apps/desktop/Cargo.toml
```
