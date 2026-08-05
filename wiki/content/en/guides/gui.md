# anet-gui Graphical Client

anet-gui is the full-featured graphical client (Windows / macOS / Android). Three independent
switches let one machine act as an office terminal, an intranet forwarder, and an unattended
server-room management endpoint at the same time.

## UI Tour

- **Connections**: one-click import of connect links (or clipboard detection), local proxy switch (SOCKS5/HTTP auto-detect, 127.0.0.1 only), manual node entry, saved-node management (connect / disconnect / export / delete)
- **Nodes**: real-time status cards for connected nodes; "Manageable" badge and "Manage This Node" entry; automatic discovery of manageable upstreams
- **Routing**: merged view of the rules pushed by all nodes; per-rule pause/resume (effective immediately, remembered locally); sticky header for long tables + collapsible search
- **Settings**: roles and remote access, launch on boot, auto proxy / auto reconnect, language and theme

The Dynamic Island (centered in the title bar) shows proxy status and network-degradation details
in real time; events such as successful connections and errors pop up as spring-loaded notifications.

## Three Independent Switches (Settings → Roles & Remote Access)

### Switch A: Client Role (on by default)

Connect to upstreams, local proxy, rule routing — the full set of client capabilities. Turning it
off disconnects all nodes and stops the proxy (pure forwarder scenario). All changes are recorded
as `gui.role_toggle` audit entries (`~/.anet/gui/gui-audit.jsonl`).

### Switch B: Server Role (off by default)

Embeds a complete anet-svc node (the same `NodeServer` assembly root): relay listener,
accounts / rules / tokens / audit, SQLite.

- **First enable requires setting an admin password** (stored as argon2id), after which the embedded node starts automatically
- Default ports avoid local standalone nodes and the Docker demo chain (59290): API `127.0.0.1:59293`, Relay `0.0.0.0:54431`
- Data directory `~/.anet/gui/embedded-node/`
- "Open Console" manages the embedded node in a separate window (reusing the node management SPA)
- The "Fan-out" menu manages the embedded node's connectors (database-backed CRUD + enable/disable + group
  restriction dropdown, unrestricted by default); once connected to an upstream, the rules of the local
  client tunnel are resold to downstreams (route re-advertisement)

### Switch C: Web Remote Access (off by default)

Exposes the local management UI over HTTP — the browser experience is identical to sitting in front of the machine:

- **Setting an admin password is mandatory first** (argon2id hash stored in `~/.anet/gui/web-auth.json`)
- Defaults to `127.0.0.1:59291` only; switching to a LAN address is an explicit action and recorded as a `web.exposure_change` audit entry
- Authentication matches server-side strength: login rate limiting (5 attempts/minute, 15-minute lockout after consecutive failures), 12-hour JWT, login/export auditing
- Credential export requires a second confirmation on the Web side

## Console Channels (Manage This Node / Manageable Upstreams)

Management entries on node cards (see "In-Band Management Plane" for details):

| Entry | Prerequisite | Path |
| --- | --- | --- |
| Manage This Node | The account is granted admin privileges (admin connect link) | Local → client tunnel → node API |
| Manageable Upstream | The upstream relay token exposes the control plane | Local → client tunnel → relay → upstream API |

Both open the full management SPA in a separate window with ticket-bootstrap login — no manual password entry.

## Credentials and Privacy

- Credentials are stored in `~/.anet/credentials.json` (Unix 0600); exported connect links contain plaintext passwords — share with care
- Offline node-config cache `~/.anet/cache/`: when offline, the last known rules keep the network running; it upgrades seamlessly once connectivity returns
- Closing the main window minimizes to the system tray; the tray menu can show the window, start/stop the proxy, and quit

## Mobile (Android)

- `app-*-debug.apk` is the mobile sideload package.
- The system-level status island and background-resident service architecture for mobile (Android foreground-service notification / iOS Live Activities) is still being planned; see "Development → Roadmap" for details.
