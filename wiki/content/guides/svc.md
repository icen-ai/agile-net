# anet-svc 服务器

anet-svc 是服务器二进制（同一内核无 GUI），角色全靠配置。管理命令统一走 `anet` 入口
（同一实现，按 argv[0] 分人格：`anet` = 管理命令，`anet-svc` = 服务器进程）。

## 子命令

| 命令 | 说明 |
| --- | --- |
| `anet-svc start [config.toml] [-d]` | 启动节点（默认前台；`-d` 后台守护；裸 `anet-svc` 等同 start） |
| `anet-svc stop` | 停止运行中的节点（PID 文件 `~/.agile-net/anet-svc.pid`） |
| `anet-svc restart [config.toml]` | 重启 |
| `anet-svc status` | 运行状态（进程/配置/API 可达性，无需登录） |
| `anet-svc init` | 首装初始化向导（配置/管理员/系统服务/启动，见「命令行 anet」） |
| `anet-svc client [config.toml]` | 客户端角色：连上游 + 本地代理（原 agile-net-client） |
| `anet-svc tui [--offline]` | TUI 控制台（默认走 API；`--offline` 直连数据库只读兜底） |
| `anet-svc --version` | 版本信息 |

兼容：`anet-svc serve` 等同 `start`（已废弃，保留可用）。

## start 角色装配

`start` 读取 `agile-net.toml`（缺省路径；配置缺失时用默认值）。各配置段即角色：

| 配置段 | 角色 | 默认 |
| --- | --- | --- |
| `[api]` | Web 管理面（REST + 控制台 SPA） | `0.0.0.0:59090` |
| `[listener]` | 上游角色：接受下游 relay 连入 | 关 |
| `[connector]` | 下游角色：接入上游 relay | 关 |
| `[proxy]` | 节点本地代理（SOCKS5/HTTP） | 关 |
| `[acme]` | 自动证书（Let's Encrypt TLS-ALPN-01） | 关 |
| `[limits]` | 连接与登录限流参数 | 内置默认 |

完整字段见「参考 → 配置文件」。

### 环境变量（容器/自动化友好）

| 变量 | 说明 |
| --- | --- |
| `AGILE_ADMIN_USERNAME` / `AGILE_ADMIN_PASSWORD` | 首次启动预置管理员（密码 ≥10 位） |
| `AGILE_RELAY_TOKENS` | 逗号分隔预置 Relay Token；支持 `psk_xxx\|expose:rules` 暴露控制面语法 |
| `AGILE_PUBLIC_HOST` | connect_url 与隧道端点对外地址 |
| `DATABASE_PATH` | SQLite 路径覆盖 |
| `API_LISTEN` / `API_TLS_CERT` / `API_TLS_KEY` | API 监听与 HTTPS 证书覆盖 |
| `AGILE_LOG_DIR` | 按天滚动文件日志目录 |

## Web 管理后台（内嵌 SPA）

`http://<节点>:59090`：概览（状态卡/24h 流量趋势/WebSocket 实时事件）、客户端账号
（创建即得 `sk-` 密码 + 接入链接 + 二维码，管理版勾选）、权限组、路由规则（批量导入）、
Relay 令牌（暴露控制面勾选与档位）、审计日志（动作过滤）、端点设置。

## TUI

```bash
anet tui               # 默认走 API（需 anet login），写操作与管理端一致且落审计
anet tui --offline     # 数据库直连只读兜底（节点未启动/损坏时也能本地查看）
```

API 不可达或会话失效时自动降级只读并在状态栏明示；只读模式下启停/生成/删除均被拒绝。

## client 角色

`anet-svc client client.toml`：与 anet-gui 同一客户端引擎（多端点、规则合并、长轮询热更新、
离线缓存降级、hosts 管理）。配置示例见「快速上手」。

## 部署建议

- 生产 API 启用 HTTPS（`[api] tls_cert_path/tls_key_path`）或前置反代
- relay listener 证书自动生成自签并持久化；客户端经 connect_url 指纹固定，无需 insecure
- systemd 常驻：`anet init` 自动识别发行版注册（Ubuntu / Rocky / 麒麟 / 统信 UOS 等）；
  docker 编排见「Docker 链路与演示」
