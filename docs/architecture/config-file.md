# 配置文件设计（与实现一致）

Node 启动时读取 `agile-net.toml`（可用第一个命令行参数指定路径），无配置文件则使用默认值。

## Node 配置 `agile-net.toml`

```toml
# 节点显示名称
name = "办公网跳板"

# 数据库路径
db_path = "agile-net.db"

# 对外公网接入地址（生成 connect_url 用，也可用环境变量 AGILE_PUBLIC_HOST）
public_host = "cdn.example.com"

# API + Web UI 监听（HTTP，生产建议前置 HTTPS 反代）
[api]
addr = "0.0.0.0:59090"

# 上游角色：接受下游节点与客户端连入
[listener]
addr = "0.0.0.0:54430"
# 证书不存在时自动生成自签证书并持久化（重启不变，支持客户端固定）
cert_path = "certs/relay-cert.pem"
key_path = "certs/relay-key.pem"
# 自签证书 SAN / 对外 SNI 伪装域名
sni_hostname = "cdn.cloudflare.com"

# 下游角色：主动连接上游节点（可省略）
[connector]
upstream_addr = "cdn.example.com:54430"
token = "psk_xxxxxxxxxxxxxxxx"
sni_hostname = "cdn.cloudflare.com"
# 向上游通告本节点可服务的网段/域名（多级路由）
advertise = ["10.12.0.0/16", "*.corp.internal"]
# TLS 信任策略（三选一，优先级 pinning > ca > insecure）：
pinned_cert_path = "certs/upstream.pem"   # 证书固定（推荐）
# ca_cert_path = "certs/ca.pem"           # 自定义 CA
# insecure = true                         # 跳过校验（仅开发）

# 本地代理入站（可省略）
[proxy]
addr = "127.0.0.1:1080"
# 暴露到非 loopback 时必须配置认证，否则为开放代理风险
# username = "proxy-user"
# password = "proxy-pass"

# ACME 自动证书（可省略；Let's Encrypt，TLS-ALPN-01 免停机签发/续期）
# [acme]
# domain = "cdn.example.com"       # 须解析到本节点 Relay 端口
# email = "ops@example.com"
# staging = false                  # 测试用 true（Staging 不受信但限流宽松）
# renew_days = 30                  # 到期前 30 天自动续期
# cert_path = "certs/acme-cert.pem"
# key_path = "certs/acme-key.pem"

# 管理 API HTTPS（可省略；配置后 API 以 HTTPS 提供，可复用 ACME 证书）
# [api]
# addr = "0.0.0.0:59090"
# tls_cert_path = "certs/acme-cert.pem"
# tls_key_path = "certs/acme-key.pem"

# 文件日志（可省略；按天滚动）
# [log]
# dir = "logs"
# prefix = "agile-net"

# 安全限流（可省略，值为默认值）
# [limits]
# max_connections = 1024          # Relay 最大并发连接
# max_pending_auth = 256          # Relay 最大待认证连接
# auth_failures_per_minute = 20   # Relay 认证失败限流
# login_per_minute = 5            # 登录限流
# login_lock_threshold = 5        # 连续失败锁定阈值
# login_lock_minutes = 15         # 锁定时长
```

## 环境变量

| 变量 | 说明 |
|------|------|
| `DATABASE_PATH` | 覆盖数据库路径 |
| `API_LISTEN` | 覆盖 API 监听地址 |
| `AGILE_PUBLIC_HOST` | 覆盖公网接入地址 |
| `AGILE_ADMIN_USERNAME` / `AGILE_ADMIN_PASSWORD` | 首次启动预置管理员（容器部署用，密码 ≥10 位） |
| `RUST_LOG` | 日志级别（tracing EnvFilter） |

## Client 配置 `agile-net-client.toml`

```toml
proxy_port = 57890
manage_hosts = true        # resolve 规则自动写系统 hosts

# 本地代理认证（可选）
# [proxy_auth]
# username = "user"
# password = "pass"

[[nodes]]
addr = "https://cdn.example.com:59090"   # 节点 API 地址
username = "zhangsan"
password = "sk-xxxxxxxx"                 # 创建账号时下发，仅存本机
insecure = false
# pinned_cert_path = "certs/node-a.pem" # 证书固定（推荐）
```

凭据缓存（GUI/Tauri 客户端）存于 `~/.anet/credentials.json`（Unix 权限 0600）。

规则缓存：客户端把最近一次的配置保存在内存中并支持离线合并路由（断网重连期间沿用旧规则，长轮询恢复后自动更新）。
