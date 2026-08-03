# AgileNet

高安全、轻量级的 Rust 多端点网络穿透与代理链路由系统。**扇入扇出同体**——没有 frps/frpc
式的分裂，最终只有两个产物：

> **节点即主权，权利平等**：只发布规则、选择接受者，不过问对端域内的使用明细——
> 收敛与审计止于端点边界，问责沿组织链传递。

| 产物 | 形态 | 典型场景 |
| --- | --- | --- |
| **anet-gui** | 全功能图形客户端（Windows / macOS / Android） | 办公终端、内网转发机、机房留守管理端 |
| **anet-svc / anet** | 服务器二进制 + 管理命令（同一实现双入口） | 服务器中继、内网网关、运维管理 |

> 命令面统一为 `anet`：`init`（首装向导）/ `start` / `stop` / `restart` / `status` /
> `login` / `node` / `rule` / `group` / `account` / `token` / `connector` / `admin` / `audit` / `tui`。
> `anet-svc` 仅作服务器进程名（裸跑等同 `anet start`）；`anet-svc serve` 与 `anet-svc cli` 已废弃（保留隐藏兼容）。

## 能力一览

- **多层级链式穿透**：客户端经任意级 relay 链直达最深嵌套网段
  （四级链断言见 `.docker/docker-compose.test.yaml`），链路断开自动重连自愈
- **多目标扇出**：中继节点经 `[[connectors]]` 数组扇出到多个目标端点（扇出/容灾）；
  任一节点可同时扇入与扇出，一台机器既是终端也是转发机
- **全功能 GUI**：Cindy 风格设计、灵动岛状态通知（网络降级可展开明细）、
  凭据管理（删除/导出接入链接）、路由逐条启停自由组合、扇出连接管理（独立页签）、
  管理端内嵌主窗（指纹入口按名排序）
- **带内管理**：管理面流量走数据面隧道，控制台只是内网里的一个站点；
  relay 令牌可勾选「暴露控制面」（ro/rules/full 三档），管理可达性沿链路自动发现；
  管理版接入链接一键授予「管理此端点」
- **Clash/FlClash 共存**：5 万段默认端口（API 59090 / Relay 54430 / 代理 57890），
  可作为 Clash 的 socks5 节点按内网 CIDR 分流（见 `apps/README.md`）
- **安全硬化**：argon2id 密码哈希、令牌只存哈希、证书固定 pinning、常数时间比较、
  登录限流锁定、全量审计日志、JWT 吊销轮换、客户端凭据 OS keyring 存储

## 快速开始

```bash
# 首装（交互向导：配置/管理员/系统服务/启动）
cargo run -p agile-net-node --bin anet -- init

# 服务器（默认 API 端口 59090；裸 anet-svc 等同 start）
cargo run -p agile-net-node --bin anet -- start [-d]
cargo run -p agile-net-node --bin anet -- status / stop / restart

# 管理（需先 login；全部落审计）
cargo run -p agile-net-node --bin anet -- login
cargo run -p agile-net-node --bin anet -- rule list
cargo run -p agile-net-node --bin anet -- tui            # TUI（--offline 数据库只读兜底）
# 打开 http://127.0.0.1:59090 完成管理员初始化，创建权限组/规则/账号，
# 将生成的 agilenet://connect?... 接入链接发给终端

# 终端 anet-gui（apps/desktop）
cd apps/desktop && cargo tauri dev   # 或 cargo tauri build 产出安装包
# 粘贴接入链接一键接入，本地代理默认 127.0.0.1:57890；
# 首页开关：扇入（客户端角色）/ 远程（Web 远程面）；扇出页管理服务端角色与扇出连接

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
