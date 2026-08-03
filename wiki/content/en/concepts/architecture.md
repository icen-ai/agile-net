# Architecture & the Two Artifacts

## Positioning

A self-hosted intranet access management platform: your own public relay plus intranet jump hosts,
securely tunneling into private networks over TLS 1.3 encrypted tunnels, with clients routing
traffic precisely by CIDR/HOST rules.

## Core Principles

1. **Nodes have no fixed role** — the same program can act as an upstream (accepting fan-in from downstreams) or as a downstream (fanning out to an upstream); the role is decided entirely by configuration
2. **Convergence into two artifacts** — `anet-gui` (graphical) and `anet-svc` (server) share the same core; the `anet` CLI and the `agile-net-client` daemon have been absorbed as `anet-svc` subcommands
3. **Distributed accounts** — each node manages its own accounts, groups, and rules independently; nodes never share databases
4. **TLS 1.3 everywhere** — node-to-node and client-to-node traffic all runs over TLS, indistinguishable from HTTPS
5. **Precise routing** — clients only proxy traffic matching the rules (IP-CIDR / HOST); everything else goes DIRECT

## Artifacts and Roles

| Artifact | Subcommand / Switch | Role |
| --- | --- | --- |
| anet-svc | `serve` (default) | relay listener (as upstream) / connector (as downstream relay) / client (terminal downstream) / proxy (local proxy) / api (Web management plane) |
| anet-svc | `tui` | Local TUI console (direct database access) |
| anet-svc | `client` | Client role (fan out upstream + local proxy, formerly agile-net-client) |
| anet-svc | `cli` | Command-line management tool (formerly anet) |
| anet-gui | Switch A: client role | Fan out upstream, local proxy, route composition |
| anet-gui | Switch B: server role | Embeds a full anet-svc node (the same `NodeServer` assembly root) |
| anet-gui | Switch C: Web remote panel | Management UI exposed over HTTP (127.0.0.1 only by default, management password enforced) |

Example combinations: an office workstation runs A only; a forwarder runs B only; a lights-out server-room machine runs A+B+C (replacing Sunlogin-style remote desktops).

## Global Data Flow

```
用户机（anet-gui / anet-svc client）
│  本地 SOCKS5/HTTP 127.0.0.1:57890
│  路由表：ip-cidr 10.12.0.0/16 → Node-B
│          host  git.internal   → Node-B
│          *                    → DIRECT
▼
公网机 Node-A（anet-svc serve：relay listener :54430）
│  TLS 1.3 + token 认证
│  按下游通告路由转发到 Node-B
▼
内网机 Node-B（anet-svc serve：connector → Node-A）
│  命中本机通告网段 → 本机直连目标
▼
内网目标 10.12.x.x / git.internal
```

## Multi-Level Chained Tunneling

Nodes can be chained without depth limits: each node's connector advertises the segments it
(and its downstreams) can serve to its upstream, and the upstream picks the next hop by
longest-prefix match. The Docker assertion environment is exactly a four-level chain:

```
tester ──public──► node-root ──public──► node-mid ──mid──► node-leaf ──leaf──► node-deep ──deep──► target
```

The assertion matrix (T1-T7): four-level chain SOCKS5 / HTTP CONNECT traversal, ACL rejection,
multi-node access, long-polling hot updates, link-loss self-healing, and management-plane
traversal. See "Docker Chains & Demos".

## Repository Layout

```
crates/core     核心协议：mux 帧/会话、TLS pinning、relay listener/connector、
                ClientTunnel、SOCKS5/HTTP 入站、ProxyRouter
crates/node     anet-svc：NodeServer 装配根、SQLite 迁移、Axum API、Web 后台、
                TUI、cli 模块（原 anet）
crates/client   客户端引擎库：多节点连接、规则合并、本地代理、hosts 管理、
                管理面 Web API、daemon 模块（anet-svc client）
apps/desktop    anet-gui：Tauri 2 桌面/Android，三路开关 + 控制台窗口
.docker         四级链断言测试与常驻演示编排
wiki            本文档站（Cloudflare Pages 部署）
```
