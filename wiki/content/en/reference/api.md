# REST API

Node management-plane interfaces. Base path `/api/v1`, JSON content, JWT Bearer authentication.
anet-svc serves a unified Web on a single port: `/` admin SPA, `/client` client SPA, and
`/api/v1/client/*` client-SPA management interfaces (sharing the same AdminAuth login).

## Conventions

| Item | Value |
| --- | --- |
| Authentication | `Authorization: Bearer <jwt>` (except the public `/api/v1/auth/*` endpoints) |
| Roles | The management plane has a single `admin` identity; AdminAuth enforces the three scope tiers (ro/rules/full) |
| Time | ISO 8601 (`2026-07-31T12:00:00Z`) |
| ID | UUIDv4 |
| Pagination | `page` (≥1), `page_size` (1~100); responses include `items/total/page/page_size` |

Unified response envelope:

```json
// Success
{ "code": 0, "data": { } }
// Failure
{ "code": 40001, "message": "name already exists" }
```

For error-code ranges, see "Reference → Error Codes".

## Auth (Public)

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/v1/auth/init` | Initialize the first administrator (only available when no admin exists) |
| POST | `/api/v1/auth/login` | Log in (administrator; rate-limited + lockout) |
| POST | `/api/v1/auth/refresh` | Refresh the token (rotates refresh) |
| POST | `/api/v1/auth/logout` | Log out (revokes refresh) |
| GET | `/api/v1/auth/me` | Current identity (including scope) |
| PUT | `/api/v1/auth/password` | Change the administrator password |
| POST | `/api/v1/auth/admin-bootstrap` | Exchange a management bootstrap ticket for a scoped management session |

## Management: Rules / Groups

| Method | Path | Description |
| --- | --- | --- |
| GET/POST | `/api/v1/admin/rules` | List (type/search/pagination) / create |
| PUT/DELETE | `/api/v1/admin/rules/{id}` | Update / delete |
| POST | `/api/v1/admin/rules/batch` | Batch import (JSON/NDJSON) |
| GET/POST | `/api/v1/admin/groups` | List / create (`e2e_required` marks an E2E-enforced group) |
| GET/PUT/DELETE | `/api/v1/admin/groups/{id}` | Detail / update / delete |
| GET | `/api/v1/admin/groups/{id}/detail` | Group identity overview: fan-in tokens + fan-out endpoints |
| PUT | `/api/v1/admin/groups/{id}/rules` | Bind rules for the whole group |

## Management: Unified Issuance (delegation)

The resource owner issues consumer access credentials directly (the token is the identity —
no account layer). Four dimensions: entry `entry_mode` (direct = dial the issuer's own
listener / relay = via the fan-out disaster set rendezvous) × trust tier (plaintext / E2E /
E2E+management `admin_scope`) × routing `mode` (dedicated / split) × concurrency
(`single` kicks the old session / `multi` up to max_sessions, snapshotted from the
node_config `delegation_max_sessions` value at issuance, default 8).

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/v1/admin/delegation/tokens` | List issued tokens (group names resolved, per-upstream registration state, entry_mode/concurrency/max_sessions, lifecycle badge) |
| POST | `/api/v1/admin/delegation/tokens` | Issue (the plaintext and the `anet://connect` share link are returned only once) |
| DELETE | `/api/v1/admin/delegation/tokens/{id}` | Revoke (revocation frames go to every online upstream; active sessions are kicked) |

## Management: Node / Tokens / Audit

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/v1/admin/node/status` | Node status (roles/connections/manageable upstreams/24h traffic series) |
| GET | `/api/v1/admin/node/logs` | In-memory log buffer |
| GET | `/api/v1/admin/node/metrics` | System resource metrics |
| PUT | `/api/v1/admin/node/settings` | Node settings (name/public address) |
| POST | `/api/v1/admin/node/kick` | Kick a downstream node session |
| GET | `/api/v1/admin/node/events` | WebSocket real-time event stream (`consumer.online/offline` etc.; first-message auth after upgrade) |
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

A fan-out token is a connection credential issued by the endpoint: it is stored encrypted with AES-256-GCM (one of the two reversible exceptions in the entire database) and is never displayed again after creation.

## Rate Limits and Constraints

- Login is rate-limited per IP (default 5/minute; 15-minute lockout after 5 consecutive failures; tunable under `[limits]`)
- Password/token plaintext is returned only once, in the creation response; QR codes are cached for 10 minutes
- The WebSocket `/api/v1/admin/node/events` requires an admin JWT

## Client Web Remote Plane API (anet-gui switch C)

When `anet-gui` enables the "Web Remote Plane", a local HTTP service (default `127.0.0.1:59291`) exposes the client management REST API.

- **Administrator initialization and login**: `/api/v1/auth/init` / `/api/v1/auth/login`
- **Node and network control**: `GET/POST /api/v1/nodes` (list nodes and initiate connections)
- **Sensitive-export constraint**: exporting credentials and connect URLs is a sensitive operation; requests must carry `confirm=true` (e.g. `GET /api/v1/credentials/export?confirm=true`), otherwise a `40001` error is returned asking for secondary confirmation, and the attempt is recorded in the client audit log.
