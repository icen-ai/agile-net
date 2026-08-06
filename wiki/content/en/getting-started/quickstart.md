# Quick Start

Get a minimal working path up in five minutes: **start a node → issue a token → connect a client → local proxy**.

## 1. Start a Node (anet-svc)

```bash
anet-svc start
# anet-svc v0.1.0 starting
# Web Dashboard & API Server started (http://0.0.0.0:59090)
```

It starts even without a config file (API only by default). For production, use a config file:

```toml
# agile-net.toml
name = "my-node"
db_path = "agile-net.db"
public_host = "relay.example.com"   # public address shown in share links and tunnel endpoints

[api]
addr = "0.0.0.0:59090"
# tls_cert_path = "certs/api-cert.pem"   # HTTPS recommended in production
# tls_key_path = "certs/api-key.pem"

[listener]
addr = "0.0.0.0:54430"
cert_path = "certs/relay-cert.pem"
key_path = "certs/relay-key.pem"
sni_hostname = "cdn.cloudflare.com"
```

> On first start, you can preseed the administrator via environment variables: `AGILE_ADMIN_USERNAME=admin AGILE_ADMIN_PASSWORD='strong password (≥10 chars)'`;
> or complete the initialization in the Web dashboard afterwards (next step).

## 2. Initialize the Administrator and Issue a Token

Open `http://<node>:59090` and finish the one-time administrator initialization. Then, in the Web dashboard:

1. **Groups**: create a group (e.g. `office`)
2. **Routing rules**: add intranet segments, e.g. `ip-cidr 10.12.0.0/16`, `host git.internal`
3. Go back to the group and bind the rules to it
4. **Fan-in page → "Issue" tab**: unified issuance — pick the group, entry "Direct to this
   endpoint" (direct), routing "Dedicated", concurrency "Single", and issue a delegated
   token (a 48-character `psk_` secret shown only once)

Once issued, you get an access link:

```
anet://connect?server=relay.example.com&port=54430&account=d:alice-laptop&password=psk_...&fp=<cert fingerprint>
```

> The certificate fingerprint (`fp`) lets the client pin the certificate in one click — no insecure mode needed.
> Four dimensions: entry (direct to this endpoint / via fan-out rendezvous) × trust
> (plaintext / E2E / E2E+management) × routing (dedicated / split) × concurrency
> (single kicks old / multi up to max_sessions); see "Federation & Delegation".

## 3. Connect a Client (anet-gui)

Install and open anet-gui, paste the access link into the input on the Home page, and click **Connect**. Once connected:

- The "Nodes" page shows node cards with live status
- The "Routes" page shows the merged routing table, where each rule can be paused/resumed individually (effective immediately and remembered locally)
- Click **Start Proxy** and a local `127.0.0.1:57890` listener serves an auto-detecting SOCKS5/HTTP proxy

Point your system or application proxy at `127.0.0.1:57890`; traffic matching the rules enters the tunnel, everything else goes direct.

## 4. Terminals without a GUI (anet-svc client)

For terminal roles on servers or in containers, use the `client` subcommand; the node list is link-style `nodes`:

```toml
# client.toml
proxy_port = 57890
manage_hosts = true

nodes = [
  "anet://connect?server=relay.example.com&port=54430&account=d:alice-laptop&password=psk_...&fp=<cert fingerprint>",
]
```

```bash
anet-svc client client.toml
# local proxy listening on 127.0.0.1:57890 (SOCKS5/HTTP)
```

## 5. Verify

```bash
# Reach an intranet target via the proxy
curl --socks5-hostname 127.0.0.1:57890 http://10.12.1.10/

# Hit a host rule via the proxy
curl -x http://127.0.0.1:57890 http://git.internal/
```

The minimal path is now up. Next steps:

- Multi-level relay chains: configure both `[[connectors]]` (fan out upstream) and `[listener]` (serve downstream); see "Architecture"
- Manage the whole network graphically: enable the server role in `anet-gui` plus a management-tier issued link (E2E + `eadmin`); see "Management Plane"
- Command-line management: `anet`; see "anet CLI"
