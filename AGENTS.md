# AGENTS.md - AgileNet 开发与 Agent 协同规范

本文档为 AI Agent（包括 Cindy、Claude Code、Codex 等）在 **AgileNet** 项目中的开发规范、架构约定与行为准则。

---

## 📌 项目概览 (Project Overview)

**AgileNet** 是一个高安全、轻量级、Token 优化的 Rust 多节点网络穿透与代理链路由系统。

- **工作区路径**：`C:\Users\thatc\.workspace\icen\agile-net`
- **语言与版本**：Rust (Edition 2024 / Cargo Workspace)
- **主要组件**：
  - `crates/core`：核心网络协议、TLS 握手、代理路由器 (`ProxyRouter`)、匹配规则 (`MatchRule`)。
  - `crates/node`：服务端/节点代理服务 (`agile-net-node`)，包含 SQLite 数据库、Axum REST API、Web 管理后台 (`ui`) 与 TUI 终端。
  - `crates/cli`：命令行工具 `anet` (基于 Clap Derive)，支持 `status`, `login`, `node`, `route`, `tui` 等子命令。
  - `crates/client`：客户端核心引擎 (`agile-net-client`)，管理多节点连接、路由规则合并、本地 SOCKS5/HTTP 代理服务及凭据存储 (`CredentialStore`)。

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
   - 数据库交互统一封装在 `crates/node/src/db/`（基于 `rusqlite`）。
   - 包含的表：`nodes`, `routes`, `system_configs`, `groups`, `accounts`, `audit_logs`。
   - API 路由定义在 `crates/node/src/api/`（基于 `axum`），接口保护统一使用 JWT `AuthClaims` 提取器。
3. **安全硬化**：
   - 用户与客户端账号密码统一采用 `argon2id` 加密哈希，严禁明文存储。
   - 敏感操作（如节点/路由/账号添加与删除）须调用 `record_audit_log` 记录系统审计日志。
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
```
