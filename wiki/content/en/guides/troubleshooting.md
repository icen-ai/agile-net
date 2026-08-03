# Troubleshooting and Diagnosis

This guide collects common failure scenarios, diagnostic methods, and resolution steps encountered
when deploying and running AgileNet.

For local-environment issues (port occupancy, system proxy residue, TUN, subscription kernel, etc.),
run [Self-Diagnosis](#/guides/doctor) first for a one-click inspection — most items can be auto-fixed
on the spot. This page focuses on cross-machine scenarios: links, certificates, accounts.

## Common Diagnostic Methods and Log Paths

### Locating Logs

1. **anet-svc node logs**:
   - Defaults to standard output (`stdout`).
   - With `[log] dir = "logs"` set in the config file or via environment variable (`AGILE_LOG_DIR=logs`), daily log files are generated.
2. **anet-gui audit logs**:
   - Role-switch and exposure-change audits are written to `~/.agile-net/gui-audit.jsonl` (`%USERPROFILE%\.agile-net\gui-audit.jsonl` on Windows).
3. **Node database audit**:
   - The SQLite `audit_log` table records all management operations and login events, viewable via the Web console, `anet-svc cli audit list`, or `anet-svc tui`.

---

## Common Issues

### 1. Certificate Pinning Mismatch

**Symptom**: the client / downstream node cannot connect to the upstream, reporting `certificate fingerprint mismatch` or `TLS handshake failed`.

**Cause**:
- The upstream node regenerated its self-signed certificate, but the `fp` (certificate fingerprint) saved on the client was not updated.

**Diagnosis and resolution**:
- **Check the current fingerprint**: log in to the upstream node's Web console and get the latest fingerprint from the overview page, or run:
  ```bash
  openssl x509 -in certs/relay-cert.pem -noout -fingerprint -sha256
  ```
- **Update the client configuration**:
  - `anet-gui`: re-import the latest `agilenet://connect?...` connect link.
  - `anet-svc client`: edit the `pinned_fingerprint` field of the corresponding node in `client.toml`.

---

### 2. DNS Resolution and System Hosts Maintenance Failures

**Symptom**: a `host` rule with `resolve: true` is configured, but the browser cannot reach the target domain.

**Cause**:
- Maintaining the system hosts file requires elevated privileges (administrator on Windows, `sudo` / `root` on Linux/macOS).

**Diagnosis and resolution**:
- Confirm that `anet-gui` or `anet-svc client` runs with administrator privileges.
- If root/administrator privileges are unavailable, turn off the `manage_hosts` option and access through the SOCKS5/HTTP auto-detect proxy only (`127.0.0.1:57890`).

---

### 3. Port Conflicts and Occupancy

**Symptom**: the node fails to start with `Address already in use (os error 98 / 10048)`.

**Default ports at a glance**:
- Admin API / Web console: `59090`
- Relay listener: `54430`
- Client local proxy: `57890`
- GUI embedded-node API / Relay: `59293` / `54431`

**Diagnosis and resolution**:
- Find the occupying process:
  ```bash
  # Linux / macOS
  lsof -i :59090
  # Windows
  netstat -ano | findstr 59090
  ```
- Change the conflicting port in `agile-net.toml` / `client.toml` to a free one (staying in the 50000 range is recommended to avoid Clash and other software).

---

### 4. Account / Login Lockout (HTTP 429)

**Symptom**: the Web console or CLI reports `42900 Too Many Requests` and login fails.

**Cause**:
- The anti-brute-force mechanism was triggered (by default, more than 5 failures within 1 minute locks the account/IP for 15 minutes).

**Resolution**:
- Wait for the 15-minute lockout countdown to expire.
- Or, in urgent operations, connect directly to the database via the TUI (`anet-svc tui`) to make changes.
