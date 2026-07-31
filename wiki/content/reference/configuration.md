# 配置文件

## anet-svc serve：`agile-net.toml`

```toml
# 节点显示名称（握手下发与可管理发现用）
name = "my-node"
# SQLite 路径（DATABASE_PATH 环境变量可覆盖）
db_path = "agile-net.db"
# connect_url / 隧道端点对外地址（AGILE_PUBLIC_HOST 可覆盖）
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

# 下游角色：接入上游 relay（自动重连）
[connector]
upstream_addr = "relay.example.com:54430"
token = "psk_..."
sni_hostname = "cdn.cloudflare.com"
advertise = ["10.12.0.0/16", "git.internal"]   # 向上游通告的可服务网段
# ca_cert_path = "certs/ca.pem"        # 自定义 CA
# pinned_cert_path = "certs/up.pem"    # 证书固定（生产推荐）
# insecure = true                      # 跳过证书校验（仅开发）

# 节点本地代理（可选）
[proxy]
addr = "127.0.0.1:1080"                # 非 loopback 必须配置认证
# username = "u"
# password = "p"

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

## anet-svc client：`client.toml`

```toml
proxy_port = 57890
manage_hosts = true          # resolve 规则自动维护系统 hosts（需管理员/root）

# 本地代理认证（可选）
# [proxy_auth]
# username = "u"
# password = "p"

[[nodes]]
addr = "https://relay.example.com:59090"   # 或 host:port
username = "zhangsan"
password = "sk-..."
# insecure = true
# pinned_cert_path = "certs/node-a.pem"    # 证书固定 PEM
pinned_fingerprint = "ab12..."             # 或指纹固定（connect_url 自带）
```

多节点：写多个 `[[nodes]]`，路由按连接顺序合并（先连优先，标准最长前缀匹配仍优先）。

## 规则类型

| 类型 | 示例 | 语义 |
| --- | --- | --- |
| `ip-cidr` | `10.12.0.0/16` | CIDR 网段（最长前缀匹配） |
| `host` | `git.internal` | 精确域名 |
| `host`（通配） | `*.dev.internal` | 域名后缀 |
| `resolve: true` | 配合 host | 客户端自动维护系统 hosts（127.0.0.1 指向，经本地代理转发） |
