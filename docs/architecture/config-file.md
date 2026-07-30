# 配置文件设计

Node 启动时读取 `agile-net.toml` 配置文件，首次启动无配置文件则生成默认值。

## Node 配置

`agile-net.toml`

```toml
# 节点显示名称
node_name = "办公网跳板"

# 数据库路径（相对于工作目录或绝对路径）
db_path = "agile-net.db"

# API + Web UI 监听
[api]
listen = "0.0.0.0"
port = 443
# TLS 证书（留空则自动生成自签证书）
tls_cert = ""
tls_key = ""

# 上游角色（Listener）：接受下游节点和客户端连入
[listener]
enabled = true
# 与 api 共享端口和 TLS，通过协议层区分
# 无需额外配置

# 下游角色（Connector）：主动连接上游节点
[connector]
enabled = false
upstream_server = ""
upstream_port = 443
upstream_tls = true
relay_token = ""
# 重连配置
reconnect_base = 1        # 秒
reconnect_max = 60        # 秒

# 本地代理
[proxy]
enabled = true
listen = "127.0.0.1"
port = 7890

# 日志
[log]
level = "info"            # trace, debug, info, warn, error
# 日志输出：stdout, file, both
output = "both"
file = "agile-net.log"
max_size_mb = 100         # 单文件上限
max_files = 3             # 保留文件数
```

## Client 配置

Client 的配置存在用户本地目录：

- Windows: `%APPDATA%\AgileNet\config.json`
- macOS: `~/Library/Application Support/AgileNet/config.json`
- Linux: `~/.config/agile-net/config.json`

```json
{
  "proxy": {
    "listen": "127.0.0.1",
    "port": 7890,
    "auto_start": true
  },
  "nodes": [
    {
      "id": "local-uuid",
      "name": "办公网跳板",
      "server": "cdn.example.com",
      "port": 443,
      "tls": true,
      "account": "zhangsan",
      "password_encrypted": "aes256gcm:...",
      "enabled": true,
      "auto_connect": true
    }
  ],
  "hosts": {
    "managed": true,
    "backup_path": "hosts.bak"
  },
  "ui": {
    "language": "zh-CN",
    "start_minimized": false,
    "close_to_tray": true
  }
}
```

### 密码存储

Client 本地存储的密码使用 AES-256-GCM 加密：

```rust
// 密钥派生自机器唯一标识（machine-id + 用户名 + 固定 salt）
// 不是完美安全（本机有 root 就能解），但防止明文泄露
let key = derive_key(machine_id, username, SALT);
let encrypted = aes_gcm_encrypt(&key, password.as_bytes());
```

### 规则缓存

客户端拉取到的配置缓存在本地，断网时仍可使用上次的路由规则：

```
%APPDATA%\AgileNet\cache\
├── node-uuid1.json    # Node-B 的路由规则 + version
└── node-uuid2.json    # Node-C 的路由规则 + version
```
