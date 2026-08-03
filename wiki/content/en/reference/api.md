# REST API

Node management-plane and client interfaces. Base path `/api/v1`, JSON content, JWT Bearer authentication.

## Conventions

| Item | Value |
| --- | --- |
| Authentication | `Authorization: Bearer <jwt>` (except the public `/api/v1/auth/*` endpoints) |
| Roles | `admin` (management plane) / `client` (client); AdminAuth enforces the three scope tiers (ro/rules/full) |
| Time | ISO 8601 (`2026-07-31T12:00:00Z`) |
| ID | UUIDv4 |
| Pagination | `page` (≥1), `page_size` (1~100); responses include `items/total/page/page_size` |

Unified response envelope:

```json
// 成功
{ "code": 0, "data": { } }
// 失败
{ "code": 40001, "message": "username already exists" }
```

For error-code ranges, see "Reference → Error Codes".

## Auth (Public)

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/v1/auth/init` | Initialize the first administrator (only available when no admin exists) |
| POST | `/api/v1/auth/login` | Log in (admin or client account; rate-limited + lockout) |
| POST | `/api/v1/auth/refresh` | Refresh the token (rotates refresh + tunnel_token) |
| POST | `/api/v1/auth/logout` | Log out (revokes refresh) |
| GET | `/api/v1/auth/me` | Current identity (including scope) |
| PUT | `/api/v1/auth/password` | Change the administrator password |
| POST | `/api/v1/auth/admin-bootstrap` | Exchange a management bootstrap ticket for a scoped management session |

## Client API (client role)

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/v1/client/config` | Pull routing config; `?wait=true&version=N` long-polls (returns 304 on timeout). The response includes `admin_console` and `manageable` (management-grade accounts) |
| POST | `/api/v1/client/heartbeat` | Heartbeat report (online status + traffic deltas; a `force_disconnect` response means go offline immediately) |
| POST | `/api/v1/client/console-ticket` | Request a management bootstrap ticket (`admin_console` accounts; `{"upstream":"node name"}` fetches an upstream ticket) |

## Management: Rules / Groups / Accounts

| Method | Path | Description |
| --- | --- | --- |
| GET/POST | `/api/v1/admin/rules` | List (type/search/pagination) / create |
| PUT/DELETE | `/api/v1/admin/rules/{id}` | Update / delete |
| POST | `/api/v1/admin/rules/batch` | Batch import (JSON/NDJSON) |
| GET/POST | `/api/v1/admin/groups` | List / create |
| GET/PUT/DELETE | `/api/v1/admin/groups/{id}` | Detail / update / delete (`force` required when in use) |
| GET | `/api/v1/admin/groups/{id}/detail` | Group detail: the three identity kinds under it — accounts + fan-in tokens + fan-out endpoints |
| PUT | `/api/v1/admin/groups/{id}/rules` | Bind rules for the whole group |
| GET/POST | `/api/v1/admin/accounts` | List / create (`admin_console` grants management permission) |
| PUT/DELETE | `/api/v1/admin/accounts/{id}` | Update (including enable/disable and granting/revoking management permission) / delete |
| POST | `/api/v1/admin/accounts/{id}/reset-password` | Reset password (new password + connect_url returned only once) |
| GET | `/api/v1/admin/accounts/{id}/qrcode` | Connect-URL QR code (SVG; available for 10 minutes after creation/reset) |

## Management: Node / Tokens / Audit

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/v1/admin/node/status` | Node status (roles/connections/account stats/manageable upstreams) |
| GET | `/api/v1/admin/node/stats` | Traffic stats (`period`, `group_by`) |
| GET | `/api/v1/admin/node/logs` | In-memory log buffer |
| GET | `/api/v1/admin/node/metrics` | System resource metrics |
| PUT | `/api/v1/admin/node/settings` | Node settings (name/public address) |
| POST | `/api/v1/admin/node/kick` | Kick a downstream node or a client session |
| GET | `/api/v1/admin/node/events` | WebSocket real-time event stream |
| GET/POST | `/api/v1/admin/node/relay-tokens` | List / create tokens (`group_id` scoping group, `expose_control`+`control_scope`) |
| PUT/DELETE | `/api/v1/admin/node/relay-tokens/{id}` | Update (expose switch/tier; `group_id` is tri-state: absent = unchanged, `null` = unscoped, string = attach to group) / revoke (kicks sessions) |
| GET/POST | `/api/v1/admin/admins` | List / create administrators |
| DELETE | `/api/v1/admin/admins/{id}` | Delete an administrator |
| GET | `/api/v1/admin/audit-logs` | Audit logs (action filter/pagination) |

## Management: Fan-out (connectors)

Fan-out endpoints are first-class, database-backed resources: TOML `[[connectors]]` is imported at startup only (name defaults to upstream_addr, group = unscoped);
the database is the source of truth at runtime, and all operations below take effect immediately. Attaching a `group_id` applies peer scoping (absent = unscoped).

| Method | Path | Description |
| --- | --- | --- |
| GET/POST | `/api/v1/admin/connectors` | List (with live status and owning group) / create (`advertise` is a string array) |
| PUT/DELETE | `/api/v1/admin/connectors/{id}` | Update (**full-replacement** semantics; leaving token empty = keep the current value) / delete |
| POST | `/api/v1/admin/connectors/{id}/enable` | Enable (assemble and connect) |
| POST | `/api/v1/admin/connectors/{id}/disable` | Disable (disconnect; the record is kept) |

A fan-out token is a connection credential issued by the endpoint: it is stored encrypted with AES-256-GCM (the only reversible exception in the entire database) and is never displayed again after creation.

## Rate Limits and Constraints

- Login is rate-limited per IP (default 5/minute; 15-minute lockout after 5 consecutive failures; tunable under `[limits]`)
- Password/token plaintext is returned only once, in the creation response; QR codes are cached for 10 minutes
- The WebSocket `/api/v1/admin/node/events` requires an admin JWT

## Client Web Remote Plane API (anet-gui switch C)

When `anet-gui` enables the "Web Remote Plane", a local HTTP service (default `127.0.0.1:59291`) exposes a REST API identical to the specification above.

- **Administrator initialization and login**: `/api/v1/auth/init` / `/api/v1/auth/login`
- **Node and network control**: `GET/POST /api/v1/nodes` (list nodes and initiate connections)
- **Sensitive-export constraint**: exporting credentials and connect URLs is a sensitive operation; requests must carry `confirm=true` (e.g. `GET /api/v1/credentials/export?confirm=true`), otherwise a `40001` error is returned asking for secondary confirmation, and the attempt is recorded in the client audit log.
