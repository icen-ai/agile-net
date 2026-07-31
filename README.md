# AgileNet

高安全、轻量级的 Rust 多节点网络穿透与代理链路由系统。**上下游同体**——没有 frps/frpc
式的分裂，最终只有两个产物：

| 产物 | 形态 | 典型场景 |
| --- | --- | --- |
| **anet-gui** | 全功能图形客户端（Windows / macOS / Android） | 办公终端、内网转发机、机房留守管理端 |
| **anet-svc** | 服务器二进制（`serve` / `tui` / `cli` 子命令） | 服务器中继、内网网关 |

> 双产物统一已按 `docs/plan/merge-gui-svc.md` 完成（P1→P3）：
> `agile-net-node` → `anet-svc`、`agilenet-desktop` → `anet-gui`，
> `anet`（CLI）与 `agile-net-client`（daemon）收编为 `anet-svc cli` 与 `anet-svc client`。

## 能力一览

- **多层级链式穿透**：客户端经任意级 relay 链直达最深嵌套网段
  （四级链断言见 `.docker/docker-compose.test.yaml`），链路断开自动重连自愈
- **聚合中继**：任一节点可同时是上游与下游；一台机器既是终端也是转发机
- **全功能 GUI**：Cindy 风格设计、灵动岛状态通知（网络降级可展开明细）、
  凭据管理（删除/导出接入链接）、路由逐条启停自由组合、列表折叠搜索
- **带内管理**：管理面流量走数据面隧道，控制台只是内网里的一个站点；
  relay 令牌可勾选「暴露控制面」（ro/rules/full 三档），管理可达性沿链路自动发现；
  管理版接入链接一键授予「管理此节点」
- **Clash/FlClash 共存**：5 万段默认端口（API 59090 / Relay 54430 / 代理 57890），
  可作为 Clash 的 socks5 节点按内网 CIDR 分流（见 `apps/README.md`）
- **安全硬化**：argon2id 密码哈希、令牌只存哈希、证书固定 pinning、常数时间比较、
  登录限流锁定、全量审计日志、JWT 吊销轮换

## 快速开始

```bash
# 服务器 anet-svc（默认 API 端口 59090）
cargo run -p agile-net-node            # = anet-svc serve
cargo run -p agile-net-node -- tui     # 本地 TUI 控制台
cargo run -p agile-net-node -- cli --help   # 命令行管理工具（原 anet）
cargo run -p agile-net-node -- client client.toml  # 客户端角色（原 agile-net-client）
# 打开 http://127.0.0.1:59090 完成管理员初始化，创建权限组/规则/账号，
# 将生成的 agilenet://connect?... 接入链接发给终端

# 终端 anet-gui（apps/desktop）
cd apps/desktop && cargo tauri dev   # 或 cargo tauri build 产出安装包
# 粘贴接入链接一键接入，本地代理默认 127.0.0.1:57890；
# 「设置 → 角色与远程面」可开启服务端角色（内嵌节点）与 Web 远程面

# Docker 四级链演示（宿主机直连最深层网络）
docker compose -f .docker/docker-compose.chain.yaml up -d   # 详见 .docker/README.md
```

## 文档

| 文档 | 内容 |
| --- | --- |
| `docs/plan/merge-gui-svc.md` | 双产物统一与分布式管理面实施计划（当前主线） |
| `docs/architecture/` | 架构总览 / 配置说明 / 代理路由 / UI 设计规范 |
| `docs/api/` | REST API 规格与错误码 |
| `docs/database/` | 数据库 schema 与迁移 |
| `docs/todo/island.md` | 移动端系统级状态岛规划 |
| `.docker/README.md` | 链路测试与常驻演示编排 |
| `AGENTS.md` | AI Agent 开发协同规范 |

## 开发

Rust Edition 2024 Cargo Workspace（`crates/*`）+ Tauri 2 独立 workspace（`apps/desktop`）。

```bash
cargo test --workspace          # 单元 + 集成测试
cargo clippy --workspace        # 规范检查
```
