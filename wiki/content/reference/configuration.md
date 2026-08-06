# 配置文件

## anet-svc start：`agile-net.toml`

```toml
# 节点显示名称（握手下发与可管理发现用）
name = "my-node"
# SQLite 路径（DATABASE_PATH 环境变量可覆盖）
db_path = "agile-net.db"
# 接入链接 / 隧道端点对外地址（AGILE_PUBLIC_HOST 可覆盖）
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

# 进程内嵌客户端角色（可选）：anet-svc 进程内直接起客户端引擎，消费委托链接
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

## 反代/域名场景（联邦 P1）

对外展示地址与监听地址解耦：`public_host`（公网身份，接入链接与隧道端点的展示地址，控制台「设置」
热生效）+ `public_api_url`（控制台设置，API 反代端点 `http(s)://host[:port]`，接入链接随之携带
https scheme）。硬约束：

- **Relay 数据面必须 L4 TCP 透传**：SNI 是拟态主机名可直接穿透；L7 终结 TLS 会破坏私有协议与
  证书指纹钉值（对端将无法校验）。Nginx `stream{}` / HAProxy `mode tcp` / SLB TCP 监听均可。
- API 管理面可以 L7 HTTPS 反代（443/域名终结 TLS 没问题），此时把对外完整端点填入
  「设置 → API 反代端点」（如 `https://anet.example.com`），新签发的接入链接即带 https scheme。
- 多节点共用一公网 IP 时按端口区分后端（relay SNI 为拟态值，无法按 SNI 分流多 anet 节点）；
  更推荐单入口节点 + 联邦路由（扇出注册把各内网路由收敛到入口，见联邦模型）。
- `anet init` 向导会询问「本机是否公网会合点 + 对外地址」，与控制台设置等价，落 `public_host`。

## anet-svc client：`client.toml`

```toml
proxy_port = 57890
manage_hosts = true          # resolve 规则自动维护系统 hosts（需管理员/root）

# 本地代理认证（可选）
# [proxy_auth]
# username = "u"
# password = "p"

# 链接式节点清单：一条 anet://connect 委托链接一个节点
#（签发端统一签发产出，内含入口地址 + 委托令牌 + 证书指纹钉值三件套；
#  容灾集合 entry/entryfp、E2E en、分流 emode=split、管理档 eadmin=1 均由链接承载）
nodes = [
  "anet://connect?server=relay.example.com&port=54430&account=d:alice-laptop&password=psk_...&fp=ab12...",
]
```

多节点：`nodes` 写多条链接，路由按连接顺序合并（先连优先，标准最长前缀匹配仍优先）。

## 规则类型

| 类型 | 示例 | 语义 |
| --- | --- | --- |
| `ip-cidr` | `10.12.0.0/16` | CIDR 网段（最长前缀匹配） |
| `host` | `git.internal` | 精确域名 |
| `host`（通配） | `*.dev.internal` | 域名后缀 |
| `resolve: true` | 配合 host | 客户端自动维护系统 hosts（127.0.0.1 指向，经本地代理转发） |
