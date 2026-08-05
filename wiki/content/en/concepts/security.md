# Security Model

AgileNet's security design assumes: relays are untrusted, tokens will leak, and the management
plane must be attributable.

## Transport & Authentication

| Layer | Mechanism |
| --- | --- |
| Transport encryption | TLS 1.3 throughout (`rustls` + `ring`); the relay data plane and the management API can each enable it independently |
| Certificate verification | Clients/connectors support **certificate pinning**: pin a PEM certificate or a SHA-256 fingerprint (`fp`, distributed one-click via connect_url, MITM-resistant); custom CAs are also supported |
| Password storage | Administrator and client account passwords are always hashed with **argon2id** (64MB / t=3 / p=4); plaintext never touches the database |
| Token storage | Client passwords (`sk-`), Relay Tokens (`psk_`), tunnel tokens (`tun_`), and management bootstrap tickets (`adt_`) are all server-generated 48-character strong random secrets; **only SHA-256 hashes are stored**, and the plaintext is returned exactly once at creation time |
| Fan-out token | A connector's connection credential is issued by the peer and must be presented in plaintext when connecting: **the only reversible-storage exception in the entire database** — encrypted at rest with AES-256-GCM (`v1:nonce_b64:ct_b64`), with the machine key `node_config.connector_token_key` generated on first use; never displayed again after creation, and neither plaintext nor ciphertext is written to the audit log |
| Comparison | Data-plane token comparison must be **constant-time** (`constant_time_eq`) to defeat timing side channels |
| Sessions | JWT (HS256): admin access 15min / refresh 7d; client access 1h / refresh 30d; refresh jti hashes are stored for revocation and rotation; the JWT secret is generated on first start and persisted |

## Brute-Force Resistance & Rate Limiting

- Management login: per-IP limit of 5 attempts/minute; 5 consecutive failures lock the IP for 15 minutes (configurable in `[limits]`)
- Data-plane authentication: per-IP limit of 20 attempts/minute, with a random 150–400ms delay penalty on failure
- Caps on pending-auth connections and total connections (against Slowloris and resource exhaustion)
- 64KB control-frame / 256KB data-frame caps (against oversized-frame memory exhaustion)

## Data-Plane ACL

When a client tunnel is established, the node loads every rule of that account's group as the
ACL — **only destinations covered by the rules can be opened**; anything outside the rules is
rejected at the tunnel entrance (docker assertion T3). Whether a node can be managed reduces to
a rule as well: "is there a path to its API address" — revoke the grant and the management path
disappears.

### Peer ACL

Groups are also the single point of restriction for **node-to-node traffic**; all three identity
kinds attach to a group:

| Identity | Attachment | Default |
| --- | --- | --- |
| Account (direct users of this node) | `account.group_id` | Group chosen at creation |
| Fan-in peer | `relay_token.group_id` | Unrestricted (allow everything) |
| Fan-out peer | `connector.group_id` | Unrestricted |

Traffic arriving over a peer tunnel is allowed only if its destination matches the rule set of
that peer's group; otherwise it is rejected at the entrance and audited
(`peer.acl_denied`: peer identity + destination + source, deduplicated per peer+destination per
minute). Group rule hot updates, token revocation, and connector disabling all take effect in
real time.

Identity domains are separated (the sovereignty principle): tunnel authentication carries only
the peer node's identity, **never** the identity of end users inside the peer's domain —
restriction and auditing stop at the endpoint boundary, and accountability travels along the
organizational chain. See `docs/todo/peer-acl.md` for the design and implementation record.

## Auditing

All sensitive operations are written to the `audit_log` table (operator / action / target /
detail / source IP, retained 90 days with automatic cleanup). Recording any password or token
plaintext is strictly forbidden. Management-plane events include:

| action | Trigger |
| --- | --- |
| `account.issue_admin_link` | Management-capable access link issued |
| `relay_token.expose_control` | Control-plane exposure toggle changed |
| `relay_token.set_group` | Fan-in token restriction group changed (including group assignment at creation) |
| `connector.create/update/delete/enable/disable` | Full fan-out peer lifecycle (no token plaintext/ciphertext recorded) |
| `peer.acl_denied` | Peer traffic rejected by restriction (peer identity + destination + source, deduplicated per minute) |
| `admin.session_via_relay` | Management session obtained via a relay token |
| `admin.console_access` | Management plane of a node accessed through the console channel |
| `gui.role_toggle` | GUI three-way switch changed (JSONL written to `~/.anet/gui/gui-audit.jsonl`) |
| `web.exposure_change` | Web panel listen address or start/stop changed |

The principle: every management operation must be able to answer "who, via which path (local /
which tunnel level / through which relay), on which device, did what"; token-level sessions and
real human accounts are clearly distinguished in the operator field
(`relay:psk_prefix@downstream` / `link:account` vs. usernames).

## Management-Plane Defense in Depth

- **Management bootstrap tickets are single-use** (management-link scenario) / time- and
  count-limited (relay scenario), with atomic counting against replay
- **Three scoped-admin tiers**: `ro` (read-only) / `rules` (read + rule write) / `full` (full
  control); the JWT scope claim is enforced at the AdminAuth layer, and unknown tiers fail
  closed as read-only
- The Web remote panel binds 127.0.0.1 by default; exposing it on the LAN is an explicit
  configuration and triggers a warning; setting a management password first is enforced (argon2id)
- Credential export / access links over the Web require a second confirmation (`confirm=true`,
  otherwise 409)
- The frontend escapes all rendering through a unified `esc()` to kill stored XSS; CSP /
  X-Frame-Options / nosniff security headers; Tauri CSP `script-src 'self'` forbids inline events
