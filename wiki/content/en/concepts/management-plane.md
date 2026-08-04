# In-Band Management

**Management traffic rides the data-plane tunnel as ordinary intranet HTTP** — the console is just a web site on the intranet.
No central console, no fleet-wide session store: whether a node can be managed = whether a route to its API address exists.

## Console Channel

The GUI ships with a built-in loopback forwarder (local loopback port → client tunnel → target node API).
The console window or any browser opens `127.0.0.1:58xxx` and loads the remote node's management SPA — no browser proxy required.

```
控制台窗口 ──http──► 127.0.0.1:58xxx（loopback 转发器）
                     │  经本机已建立的客户端隧道（TLS 1.3）
                     ▼
                 目标节点 API（管理 SPA + REST）
```

- End to end: management HTTP travels inside the tunnel's TLS; relay nodes only see ciphertext forwarding
- Unified ACL: revoking a rule or permission removes the management path
- Audit attribution to a person or a token: every operation lands on a real identity

## Management-Grade Connect URL (Manage This Node)

When the console creates a client account, checking "Also grant management permission" generates
the `anet://connect?...&admin=1` variant (the generation page shows a strong warning, and issuance is audited as `account.issue_admin_link`).

After the client connects:

1. The config response carries `admin_console: true` → the GUI node card shows "Manage This Node" and a "Manageable" badge
2. On click, the GUI obtains a **one-time management bootstrap ticket** via `POST /api/v1/client/console-ticket` (valid 10 minutes; only its hash is stored)
3. The console window opens, and the SPA exchanges `#boot=<ticket>` for a management session via `POST /api/v1/auth/admin-bootstrap`
4. The exchange is audited immediately as `admin.console_access` (operator=`link:account`); revoking the permission drops the tunnel and voids the ticket

## Exposing the Control Plane (Management over Relay Chains)

A Relay Token can check "Allow this downstream relay to manage this node" (off by default), with three tiers: ro/rules/full.
During the handshake (a backward-compatible AuthOk extension), the control endpoint and a management bootstrap ticket are delivered to that downstream:

```
上游 E ──握手下发 control──► 下游 D ──config.manageable──► 管理版客户端 C
   │                                                    │
   └──────── C 经隧道直达 E API，票据换取 scoped 管理会话 ◄┘
```

- The downstream node records its "manageable upstreams" and passes them down with its own management plane → **the GUI device list auto-discovers manageable nodes (local machine / connected nodes / upstream chain)**
- The ticket's security boundary equals the relay token itself: a psk holder is already a high-trust credential on the data plane, so with the expose switch on, the relay session can be exchanged directly for a management session (zero provisioning)
- Exchanges are audited as `admin.session_via_relay` (operator=`relay:psk_prefix@downstream`); revoking the token and kicking the session reclaims the whole chain

## Scoped Admin: Three Tiers

| Tier | Capability |
| --- | --- |
| `ro` | Read-only (GET status/rules/accounts/audit) |
| `rules` | Read-only + create/modify/delete routing rules |
| `full` | Full power (equivalent to an administrator) |

The scope is issued with the management-session JWT and enforced at the AdminAuth layer; unknown tiers fail closed and are treated as read-only.

## Route Re-Advertisement

When the GUI enables both the client and server roles, the embedded node's connectors **resell the client tunnels' rules downstream**:
the advertised set = static config + client rule values; when a downstream Open matches one of these rules, it is forwarded through the corresponding client tunnel (via=client tunnel).
Rule-set changes trigger an automatic reconnect and re-advertisement (no new frame types; older upstreams remain fully compatible).

## Rejected Design Archive (the D-Proxy Route)

"C → D console → D backend proxy forwarding → EFG": D would have to store admin sessions for the entire fleet (a single-point credential store),
EFG's audit would see D instead of the actual operator, and a separate delegation permission model would be required. It is kept as a candidate for phase two,
"limited delegated management" (forwarding carries the real operator identity header), but is not the baseline path.
