# Configuration File

## anet-svc start: `agile-net.toml`

```toml
# 节点显示名称（握手下发与可管理发现用）
name = "my-node"
# SQLite 路径（DATABASE_PATH 环境变量可覆盖）
db_path = "agile-net.db"
# Public address for share links / tunnel endpoints (AGILE_PUBLIC_HOST overrides)
public_host = "relay.example.com"

[api]
addr = "0.0.0.0:59090"
# 内置 HTTPS（生产推荐；API_TLS_CERT/API_TLS_KEY 环境变量可覆盖）
# tls_cert_path = "certs/api-cert.pem"
# tls_key_path  = "certs/api-key.pem"

# 上游角色：接受下游 relay 连入
[listener]
addr = "0.0.0.0:54430"
cert_path = "certs/relay-cert.pem"    # 不存在则自动生成自签并持久化
key_path  = "certs/relay-key.pem"
sni_hostname = "cdn.cloudflare.com"   # 自签证书 SAN / 对外 SNI

# 扇出角色：扇出到目标 relay（自动重连；[[connectors]] 数组可多目标扇出/容灾）
# 注意：[[connectors]] 仅启动导入——启动时若 DB 无同名 connector 则导入
# （name 取 upstream_addr，组 = 不收敛），运行时以数据库为准；
# 管理端「扇出」页 / anet connector 的增删改与启停即时生效（可挂权限组收敛）。
[[connectors]]
upstream_addr = "relay-a.example.com:54430"
token = "psk_..."
sni_hostname = "cdn.cloudflare.com"
advertise = ["10.12.0.0/16", "git.internal"]   # 向对端通告的可服务网段
# ca_cert_path = "certs/ca.pem"        # 自定义 CA
# pinned_cert_path = "certs/up.pem"    # 证书固定（生产推荐）
# insecure = true                      # 跳过证书校验（仅开发）

# 第二个扇出目标（可选，容灾/扇出到多个内网）
# [[connectors]]
# upstream_addr = "relay-b.example.com:54430"
# token = "psk_..."
# sni_hostname = "cdn.cloudflare.com"

# 节点本地代理（可选）
[proxy]
addr = "127.0.0.1:1080"                # 非 loopback 必须配置认证
# username = "u"
# password = "p"

# In-process embedded client role (optional): the client engine runs inside anet-svc
# [client]
# proxy_port = 57890
# manage_hosts = true
# nodes = [
#   "anet://connect?server=b1.example.com&port=54430&account=d:alice-laptop&password=psk_...&fp=aa11",
# ]

# ACME 自动证书（Let's Encrypt TLS-ALPN-01，热替换免停机）
# [acme]
# domain = "relay.example.com"
# email = "ops@example.com"
# staging = false
# renew_days = 30

# 文件日志（按天滚动）
# [log]
# dir = "logs"
# prefix = "agile-net"

# 限流参数（缺省内置值）
# [limits]
# max_connections = 1024
# max_pending_auth = 256
# auth_failures_per_minute = 20
# login_per_minute = 5
# login_lock_threshold = 5
# login_lock_minutes = 15
```

## Reverse Proxy / Domain Fronting (Federation P1)

The advertised address is decoupled from the listen address: `public_host` (public identity shown in
access links and tunnel endpoints; hot-applied from Console → Settings) plus `public_api_url`
(Console setting: the reverse-proxied API endpoint `http(s)://host[:port]`; access links then carry
the https scheme). Hard constraints:

- **The relay data plane requires L4 TCP passthrough**: the SNI is a mimicry hostname and passes
  through fine, but terminating its TLS at L7 breaks the private protocol and cert-fingerprint
  pinning (peers can no longer verify). Nginx `stream{}`, HAProxy `mode tcp` or an L4 LB listener all work.
- The admin API may sit behind an L7 HTTPS reverse proxy (TLS termination on 443/a domain is fine);
  put the full external endpoint into "Settings → Reverse-Proxy API Endpoint"
  (e.g. `https://anet.example.com`) and newly issued access links carry the https scheme.
- Sharing one public IP across nodes: split backends by port (the relay SNI is a mimicry value and
  cannot demultiplex multiple anet nodes); better still, a single entry node plus federation routing
  (fan-out registration converges each intranet's routes at the entry).
- The `anet init` wizard asks "is this a public rendezvous + external address", equivalent to the
  console setting, and writes `public_host`.

## anet-svc client: `client.toml`

```toml
proxy_port = 57890
manage_hosts = true          # resolve 规则自动维护系统 hosts（需管理员/root）

# 本地代理认证（可选）
# [proxy_auth]
# username = "u"
# password = "p"

# Link-style node list: one anet://connect delegated link per node
# (produced by unified issuance on the issuer; carries entry address + delegated token
#  + cert fingerprint pinning; disaster set entry/entryfp, E2E en, split emode=split,
#  management eadmin=1 are all carried by link parameters)
nodes = [
  "anet://connect?server=relay.example.com&port=54430&account=d:alice-laptop&password=psk_...&fp=ab12...",
]
```

Multiple nodes: put multiple links in `nodes`; routes merge in connection order (first-connected wins, while standard longest-prefix matching still takes precedence).

## Rule Types

| Type | Example | Semantics |
| --- | --- | --- |
| `ip-cidr` | `10.12.0.0/16` | CIDR range (longest-prefix match) |
| `host` | `git.internal` | Exact hostname |
| `host` (wildcard) | `*.dev.internal` | Domain suffix |
| `resolve: true` | Combined with host | The client maintains the system hosts file automatically (points to 127.0.0.1, forwarded via the local proxy) |
