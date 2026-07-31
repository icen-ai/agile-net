# anet-svc 服务器

anet-svc 是服务器二进制（同一内核无 GUI），角色全靠配置与子命令。

## 子命令

| 命令 | 说明 |
| --- | --- |
| `anet-svc serve [config.toml]` | 默认：节点全角色（relay listener / connector / client 隧道 / proxy / api） |
| `anet-svc tui` | 本地 TUI 控制台（直连数据库，无 API 依赖） |
| `anet-svc client [config.toml]` | 客户端角色：连上游 + 本地代理（原 agile-net-client） |
| `anet-svc cli <args...>` | 命令行管理工具（原 anet，见「命令行 anet-svc cli」） |
| `anet-svc --version` | 版本信息 |

## serve 角色装配

`serve` 读取 `agile-net.toml`（缺省路径；配置缺失时用默认值）。各配置段即角色：

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
Relay 令牌（暴露控制面勾选与档位）、审计日志（动作过滤）、节点设置。

## TUI

```bash
anet-svc tui   # 直连 DATABASE_PATH 或 ./agile-net.db
```

适合无外露面时的本机管理：账号/组/规则/令牌同 Web 后台能力。

## client 角色

`anet-svc client client.toml`：与 anet-gui 同一客户端引擎（多节点、规则合并、长轮询热更新、
离线缓存降级、hosts 管理）。配置示例见「快速上手」。

## 部署建议

- 生产 API 启用 HTTPS（`[api] tls_cert_path/tls_key_path`）或前置反代
- relay listener 证书自动生成自签并持久化；客户端经 connect_url 指纹固定，无需 insecure
- systemd 常驻见「安装」；docker 编排见「Docker 链路与演示」
