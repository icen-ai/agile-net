# Node API

节点自身状态查询与服务控制，仅 Admin 可操作。

---

## GET `/api/v1/admin/node/status`

节点运行状态总览。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "node_name": "办公网跳板",
    "version": "0.1.0",
    "uptime": 86400,
    "roles": {
      "listener": {
        "enabled": true,
        "port": 443,
        "tls": true,
        "connected_connectors": 2
      },
      "connector": {
        "enabled": true,
        "upstream": "cdn.example.com:443",
        "status": "connected",
        "connected_since": "2025-07-29T10:00:00Z"
      }
    },
    "proxy": {
      "listen": "127.0.0.1:7890",
      "active_connections": 15,
      "rule_count": 8
    },
    "accounts": {
      "total": 12,
      "online": 5,
      "disabled": 2
    },
    "system": {
      "cpu_usage": 3.2,
      "memory_mb": 85,
      "open_fds": 128
    }
  }
}
```

---

## GET `/api/v1/admin/node/stats`

流量统计。

### 查询参数

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `period` | string | `1h` | `1h` / `24h` / `7d` / `30d` |
| `group_by` | string | `account` | `account` / `rule` / `time` |

### 响应 200 (group_by=account)

```json
{
  "code": 0,
  "data": {
    "period": "24h",
    "total_tx": 1073741824,
    "total_rx": 2147483648,
    "breakdown": [
      {
        "account_id": "uuid",
        "username": "zhangsan",
        "bytes_tx": 536870912,
        "bytes_rx": 1073741824,
        "connections": 45
      }
    ]
  }
}
```

### 响应 200 (group_by=time)

```json
{
  "code": 0,
  "data": {
    "period": "24h",
    "interval": "1h",
    "points": [
      { "time": "2025-07-30T00:00:00Z", "bytes_tx": 10240, "bytes_rx": 20480 },
      { "time": "2025-07-30T01:00:00Z", "bytes_tx": 15360, "bytes_rx": 30720 }
    ]
  }
}
```

---

## GET `/api/v1/admin/node/logs`

查询最近日志。

### 查询参数

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `limit` | u32 | 100 | 最大 1000 |
| `level` | string | - | `error` / `warn` / `info` / `debug` |
| `module` | string | - | `relay` / `proxy` / `auth` / `api` |
| `since` | string | - | ISO 8601 时间戳 |

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "time": "2025-07-30T14:30:00.123Z",
        "level": "info",
        "module": "relay",
        "message": "connector connected from 10.12.1.5",
        "fields": { "token": "tok_***", "remote_addr": "10.12.1.5:54321" }
      }
    ]
  }
}
```

---

## PUT `/api/v1/admin/node/settings`

更新节点设置。

### 请求

```json
{
  "node_name": "新的节点名",
  "listener": {
    "enabled": true,
    "port": 443,
    "tls_cert_path": "/etc/agile-net/cert.pem",
    "tls_key_path": "/etc/agile-net/key.pem"
  },
  "connector": {
    "enabled": true,
    "upstream_server": "cdn.example.com",
    "upstream_port": 443,
    "upstream_tls": true,
    "relay_token": "psk_xxx"
  },
  "proxy": {
    "listen_addr": "127.0.0.1",
    "listen_port": 7890
  }
}
```

所有字段可选，仅更新传入的字段。更改涉及网络监听的配置需要重启对应模块。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "applied": ["node_name", "connector.upstream_server"],
    "restart_required": ["listener"]
  }
}
```

---

## POST `/api/v1/admin/node/relay-tokens`

生成一个新的 relay PSK token，用于授权下游节点连入。

### 请求

```json
{
  "remark": "分公司跳板机"
}
```

### 响应 201

```json
{
  "code": 0,
  "data": {
    "token": "psk_xxxxxxxxxxxxxxxx",
    "remark": "分公司跳板机",
    "created_at": "2025-07-30T10:00:00Z"
  }
}
```

---

## GET `/api/v1/admin/node/relay-tokens`

列出所有 relay token。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "id": "uuid",
        "token_prefix": "psk_xxxx****",
        "remark": "分公司跳板机",
        "last_used_at": "2025-07-30T14:00:00Z",
        "created_at": "2025-07-30T10:00:00Z"
      }
    ]
  }
}
```

Token 全文仅创建时返回，列出时只显示前缀。

---

## DELETE `/api/v1/admin/node/relay-tokens/:id`

吊销 relay token。使用该 token 的下游节点会在下次心跳时被断开。

---

## GET `/api/v1/admin/node/metrics`

Prometheus 文本格式指标导出（admin 认证）。

### 响应 200

```
# HELP agilenet_uptime_seconds Node uptime
agilenet_uptime_seconds 86400
agilenet_peers 2
agilenet_online_clients 5
agilenet_peer_bytes{node_id="node-b",direction="up"} 1048576
agilenet_proxy_active_connections 15
agilenet_rules_total 8
...
```

指标：`uptime`、`peers`、`online_clients`、`peer_bytes{node_id,direction}`、
`proxy_active/total_connections`、`proxy_bytes{direction}`、`accounts_total/disabled`、`rules_total`。

---

## POST `/api/v1/admin/node/kick`

强制断开指定下游节点会话（kick）。被踢节点将按其退避策略自动重连；
如需永久封禁，请先吊销其 relay token 再 kick。

### 请求

```json
{ "node_id": "node-b" }
```

### 响应 200

```json
{ "code": 0, "data": { "kicked": true } }
```

### 错误

| code | 场景 |
|------|------|
| 40400 | 该节点当前不在线 |

---

## WebSocket `/api/v1/admin/node/events`

实时事件流。

### 认证

```
ws://node:443/api/v1/admin/node/events?token=<access_token>
```

### 事件格式

```json
{
  "type": "account.online",
  "time": "2025-07-30T14:30:00Z",
  "data": { "account_id": "uuid", "username": "zhangsan", "remote_addr": "1.2.3.4" }
}
```

### 事件类型

| type | 触发时机 |
|------|---------|
| `account.online` | 客户端上线 |
| `account.offline` | 客户端下线 |
| `connector.connected` | 下游节点连入 |
| `connector.disconnected` | 下游节点断开 |
| `config.updated` | 规则/权限组变更 |
| `stats.snapshot` | 每 30s 发送一次流量快照 |
