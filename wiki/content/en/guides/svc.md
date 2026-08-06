# anet-svc Server

anet-svc is the server binary (same core, no GUI); roles come entirely from configuration.
Management commands go through the unified `anet` entry point (same implementation, personas
switched by argv[0]: `anet` = management commands, `anet-svc` = server process).

## Subcommands

| Command | Description |
| --- | --- |
| `anet-svc start [config.toml] [-d]` | Start the node (foreground by default; `-d` daemonizes; a bare `anet-svc` is equivalent to start) |
| `anet-svc stop` | Stop the running node (PID file `~/.anet/svc/anet-svc.pid`) |
| `anet-svc restart [config.toml]` | Restart |
| `anet-svc status` | Runtime status (process / config / API reachability; no login required) |
| `anet-svc init` | First-install setup wizard (config / admin / system service / launch; see "The anet CLI") |
| `anet-svc client [config.toml]` | Client role: consume delegated links + local proxy |
| `anet-svc tui [--offline]` | TUI console (API by default; `--offline` falls back to read-only direct database access) |
| `anet-svc --version` | Version information |

## start Role Assembly

`start` reads `agile-net.toml` (default path; defaults are used for missing configuration). Each configuration section maps to a role:

| Section | Role | Default |
| --- | --- | --- |
| `[api]` | Unified Web (`/` admin SPA, `/client` client SPA, REST) | `0.0.0.0:59090` |
| `[listener]` | Fan-in role: accepts peer relay and consumer connections | Off |
| `[[connectors]]` | Fan-out role: connects to peer relays (imported at startup only; at runtime the database is authoritative — hot-manage via the admin "Fan-out" page / `anet connector`) | Off |
| `[client]` | In-process embedded client role (link-style `nodes` of anet:// links) | Off |
| `[proxy]` | Node-local proxy (SOCKS5/HTTP) | Off |
| `[acme]` | Automatic certificates (Let's Encrypt TLS-ALPN-01) | Off |
| `[limits]` | Connection and login rate-limit parameters | Built-in defaults |

For the full field list, see "Reference → Configuration File".

### Environment Variables (container/automation friendly)

| Variable | Description |
| --- | --- |
| `AGILE_ADMIN_USERNAME` / `AGILE_ADMIN_PASSWORD` | Pre-provision an admin on first start (password ≥ 10 characters) |
| `AGILE_RELAY_TOKENS` | Comma-separated pre-provisioned relay tokens; the `psk_xxx\|expose:rules` syntax exposes the control plane |
| `AGILE_PUBLIC_HOST` | External address for share links and tunnel endpoints |
| `DATABASE_PATH` | SQLite path override |
| `API_LISTEN` / `API_TLS_CERT` / `API_TLS_KEY` | API listen address and HTTPS certificate overrides |
| `AGILE_LOG_DIR` | Directory for daily-rotated file logs |

## Web Admin Console (embedded SPA)

`http://<node>:59090`: Overview (status cards / 24h traffic trend / WebSocket live events), the
fan-in / fan-out pages (three tabs "Watch | Connect | Issue": listener endpoint / token and
connector management / the unified-issuance four-dimension dialog — token plaintext and the
`anet://` link are shown only once at issuance), groups (E2E badges; details include fan-in
tokens / fan-out peers), routing rules (batch import), audit log (action filter), endpoint
settings. The client SPA lives at `/client` (same AdminAuth login as the admin SPA; the local
machine lists first).

## TUI

```bash
anet tui               # 默认走 API（需 anet login），写操作与管理端一致且落审计
anet tui --offline     # 数据库直连只读兜底（节点未启动/损坏时也能本地查看）
```

When the API is unreachable or the session expires, the TUI automatically degrades to read-only and
says so in the status bar; enable/disable, generate, and delete operations are rejected in read-only mode.

## client Role

`anet-svc client client.toml`: the same client engine as anet-gui (delegation-only: link-style
anet:// `nodes`, supervisor-loop failover, offline split-vocabulary cache, hosts management).
For a configuration example, see "Getting Started".

## Deployment Recommendations

- Enable HTTPS for the production API (`[api] tls_cert_path/tls_key_path`) or put a reverse proxy in front
- The relay listener certificate is auto-generated, self-signed, and persisted; clients pin it via the link `fp` fingerprint — no insecure mode needed
- systemd persistence: `anet init` detects the distribution and registers the service automatically
  (Ubuntu / Rocky / Kylin / UnionTech UOS, etc.); for Docker orchestration, see "Docker Chains and Demo"
