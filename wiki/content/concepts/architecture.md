# 架构与双产物

## 定位

私有化部署的内网访问管理平台：自建公网中继 + 内网跳板，通过 TLS 1.3 加密隧道安全穿透内网，
客户端按 CIDR/HOST 规则精确路由流量。

## 核心原则

1. **节点无固定角色**——同一程序既可扇入（接受对端连入）也可扇出（主动连出），角色全由配置决定
2. **双产物收敛**——`anet-gui`（图形）与 `anet-svc`（服务器）共享同一内核；`anet` CLI 与客户端 daemon 已收编为 `anet-svc` 的子命令
3. **令牌即身份**——数据面无账号层：节点间扇入与消费者接入统一为 relay PSK / 委托令牌，每个节点独立管理自己的令牌、权限组、规则
4. **全程 TLS 1.3**——节点间、消费者到节点全部走 TLS，流量特征等同 HTTPS
5. **精确路由**——客户端只代理命中规则的流量（IP-CIDR / HOST），其余走 DIRECT

## 产物与角色

| 产物 | 子命令 / 开关 | 角色 |
| --- | --- | --- |
| anet-svc | `start`（默认） | relay listener（扇入）/ connector（扇出）/ client（`[client]` 段进程内嵌终端）/ proxy（本地代理）/ api（统一 Web：管理端 SPA + 客户端 SPA） |
| anet-svc | `tui` | 本地 TUI 控制台（API 优先 + 数据库只读兜底） |
| anet-svc | `client` | 客户端角色（消费委托链接 + 本地代理） |
| anet | 管理命令 | 与 anet-svc 同一实现双入口：login / node / rule / group / token / connector / admin / audit / doctor |
| anet-gui | 开关A 客户端角色 | 连上游、本地代理、路由组合 |
| anet-gui | 开关B 服务端角色 | 内嵌完整 anet-svc 节点（同一 `NodeServer` 装配根） |
| anet-gui | 开关C Web 远程面 | 管理 UI 经 HTTP 暴露（默认仅 127.0.0.1，强制管理密码） |

组合示例：办公机只开 A；转发机只开 B；机房留守机 A+B+C 全开（替代向日葵远程桌面）。

## 全局数据流

```
用户机（anet-gui / anet-svc client）
│  本地 SOCKS5/HTTP 127.0.0.1:57890
│  路由表：ip-cidr 10.12.0.0/16 → Node-B
│          host  git.internal   → Node-B
│          *                    → DIRECT
▼
公网机 Node-A（anet-svc start：relay listener :54430）
│  TLS 1.3 + 令牌认证（relay PSK / 委托令牌）
│  按下游通告路由转发到 Node-B
▼
内网机 Node-B（anet-svc start：connector → Node-A）
│  命中本机通告网段 → 本机直连目标
▼
内网目标 10.12.x.x / git.internal
```

## 多层级链式穿透

节点可以无限级串联：每个节点的 connector 向上游通告自己（及其下游）的可服务网段，
上游按最长前缀匹配选择下一跳。Docker 断言环境即四级链：

```
tester ──public──► node-root ──public──► node-mid ──mid──► node-leaf ──leaf──► node-deep ──deep──► target
```

断言矩阵（T1-T7）：四级链 SOCKS5 / HTTP CONNECT 穿透、ACL 拒绝、多节点接入、
规则热更新、断链自愈、管理面穿透。见「Docker 链路与演示」。

## 仓库结构

```
crates/core     核心协议：mux 帧/会话（协议 v4）、TLS pinning、relay listener/connector、
                委托注册表与 E2E、ClientTunnel、SOCKS5/HTTP 入站、ProxyRouter、anet:// 链接底座
crates/node     anet-svc：NodeServer 装配根、SQLite 基线 v1、Axum API、统一 Web
                （管理端/客户端 SPA）、TUI、cli 模块（anet 管理命令）
crates/client   客户端引擎库（委托-only）：connect 唯一入口、监督循环容灾、规则合并、
                本地代理、hosts 管理、管理面 Web API、daemon 模块（anet-svc client）
apps/desktop    anet-gui：Tauri 2 桌面/Android，三路开关 + 控制台窗口
.docker         四级链断言测试与常驻演示编排
wiki            本文档站（Cloudflare Pages 部署）
```
