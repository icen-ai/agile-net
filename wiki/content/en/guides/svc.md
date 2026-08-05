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
| `anet-svc client [config.toml]` | Client role: connect to upstreams + local proxy (formerly agile-net-client) |
| `anet-svc tui [--offline]` | TUI console (API by default; `--offline` falls back to read-only direct database access) |
| `anet-svc --version` | Version information |

Compatibility: `anet-svc serve` is equivalent to `start` (deprecated but still available).

## start Role Assembly

`start` reads `agile-net.toml` (default path; defaults are used for missing configuration). Each configuration section maps to a role:

| Section | Role | Default |
| --- | --- | --- |
| `[api]` | Web management plane (REST + console SPA) | `0.0.0.0:59090` |
| `[listener]` | Upstream role: accepts downstream relay connections | Off |
| `[[connectors]]` | Fan-out role: connects to peer relays (imported at startup only; at runtime the database is authoritative — hot-manage via the admin "Fan-out" page / `anet connector`) | Off |
| `[proxy]` | Node-local proxy (SOCKS5/HTTP) | Off |
| `[acme]` | Automatic certificates (Let's Encrypt TLS-ALPN-01) | Off |
| `[limits]` | Connection and login rate-limit parameters | Built-in defaults |

For the full field list, see "Reference → Configuration File".

### Environment Variables (container/automation friendly)

| Variable | Description |
| --- | --- |
| `AGILE_ADMIN_USERNAME` / `AGILE_ADMIN_PASSWORD` | Pre-provision an admin on first start (password ≥ 10 characters) |
| `AGILE_RELAY_TOKENS` | Comma-separated pre-provisioned relay tokens; the `psk_xxx\|expose:rules` syntax exposes the control plane |
| `AGILE_PUBLIC_HOST` | External address for connect_url and tunnel endpoints |
| `DATABASE_PATH` | SQLite path override |
| `API_LISTEN` / `API_TLS_CERT` / `API_TLS_KEY` | API listen address and HTTPS certificate overrides |
| `AGILE_LOG_DIR` | Directory for daily-rotated file logs |

## Web Admin Console (embedded SPA)

`http://<node>:59090`: Overview (status cards / 24h traffic trend / WebSocket live events), client
accounts (creation yields an `sk-` password + connect link + QR code, with an admin-variant checkbox),
groups (details include member accounts / fan-in tokens / fan-out peers), routing rules (batch import),
relay tokens (restriction group, control-plane exposure checkbox and tiers), fan-out (connector CRUD +
live status badges + enable/disable; tokens are stored encrypted and never shown again), audit log
(action filter), endpoint settings.

## TUI

```bash
anet tui               # 默认走 API（需 anet login），写操作与管理端一致且落审计
anet tui --offline     # 数据库直连只读兜底（节点未启动/损坏时也能本地查看）
```

When the API is unreachable or the session expires, the TUI automatically degrades to read-only and
says so in the status bar; enable/disable, generate, and delete operations are rejected in read-only mode.

## client Role

`anet-svc client client.toml`: the same client engine as anet-gui (multi-endpoint, rule merging,
long-poll hot updates, offline-cache fallback, hosts management). For a configuration example, see "Getting Started".

## Deployment Recommendations

- Enable HTTPS for the production API (`[api] tls_cert_path/tls_key_path`) or put a reverse proxy in front
- The relay listener certificate is auto-generated, self-signed, and persisted; clients pin it via the connect_url fingerprint — no insecure mode needed
- systemd persistence: `anet init` detects the distribution and registers the service automatically
  (Ubuntu / Rocky / Kylin / UnionTech UOS, etc.); for Docker orchestration, see "Docker Chains and Demo"
