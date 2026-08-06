# Architecture & the Two Artifacts

## Positioning

A self-hosted intranet access management platform: your own public relay plus intranet jump hosts,
securely tunneling into private networks over TLS 1.3 encrypted tunnels, with clients routing
traffic precisely by CIDR/HOST rules.

## Core Principles

1. **Nodes have no fixed role** — the same program can fan in (accepting peer connections) or fan out (dialing peers); the role is decided entirely by configuration
2. **Convergence into two artifacts** — `anet-gui` (graphical) and `anet-svc` (server) share the same core; the `anet` CLI and the client daemon have been absorbed as `anet-svc` subcommands
3. **The token is the identity** — no account layer on the data plane: fan-in between nodes and consumer access are unified as relay PSK / delegated tokens; each node manages its own tokens, groups, and rules independently
4. **TLS 1.3 everywhere** — node-to-node and consumer-to-node traffic all runs over TLS, indistinguishable from HTTPS
5. **Precise routing** — clients only proxy traffic matching the rules (IP-CIDR / HOST); everything else goes DIRECT

## Artifacts and Roles

| Artifact | Subcommand / Switch | Role |
| --- | --- | --- |
| anet-svc | `start` (default) | relay listener (fan-in) / connector (fan-out) / client (in-process embedded via the `[client]` section) / proxy (local proxy) / api (unified Web: admin SPA + client SPA) |
| anet-svc | `tui` | Local TUI console (API-first + read-only database fallback) |
| anet-svc | `client` | Client role (consume delegated links + local proxy) |
| anet | management commands | Same implementation as anet-svc, two entry points: login / node / rule / group / token / connector / admin / audit / doctor |
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
公网机 Node-A（anet-svc start：relay listener :54430）
│  TLS 1.3 + 令牌认证（relay PSK / 委托令牌）
│  按下游通告路由转发到 Node-B
▼
内网机 Node-B（anet-svc start：connector → Node-A）
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
multi-node access, rule hot updates, link-loss self-healing, and management-plane
traversal. See "Docker Chains & Demos".

## Repository Layout

```
crates/core     core protocol: mux frames/sessions (protocol v4), TLS pinning,
                relay listener/connector, delegation registries & E2E, ClientTunnel,
                SOCKS5/HTTP inbound, ProxyRouter, the anet:// link foundation
crates/node     anet-svc: NodeServer assembly root, SQLite baseline v1, Axum API,
                unified Web (admin/client SPAs), TUI, the cli module (anet commands)
crates/client   client engine library (delegation-only): connect() as the single entry,
                supervisor-loop failover, rule merging, local proxy, hosts management,
                management Web API, the daemon module (anet-svc client)
apps/desktop    anet-gui: Tauri 2 desktop/Android, three switches + console window
.docker         four-level chain assertion tests and the standing demo
wiki            this documentation site (deployed on Cloudflare Pages)
```
