# Config API

客户端登录后拉取路由配置，是 Client 端最核心的接口。

---

## GET `/api/v1/client/config`

拉取当前账号权限组内的完整路由配置。

### 请求头

```
Authorization: Bearer <access_token>
```

### 响应 200

```json
{
  "code": 0,
  "data": {
    "version": 17,
    "node_name": "办公网跳板",
    "rules": [
      {
        "id": "uuid",
        "type": "ip-cidr",
        "value": "10.12.0.0/16",
        "resolve": false
      },
      {
        "id": "uuid",
        "type": "ip-cidr",
        "value": "10.152.0.0/16",
        "resolve": false
      },
      {
        "id": "uuid",
        "type": "host",
        "value": "git.internal",
        "resolve": true
      }
    ],
    "tunnel": {
      "server": "cdn.example.com",
      "port": 443,
      "tls": true,
      "heartbeat_interval": 30,
      "heartbeat_jitter": 5
    }
  }
}
```

| 字段 | 说明 |
|------|------|
| `version` | 配置版本号，单调递增，用于长轮询和缓存 |
| `node_name` | 节点显示名，客户端 UI 用 |
| `rules` | 该账号所属权限组关联的全部规则 |
| `rules[].type` | `ip-cidr` 或 `host` |
| `rules[].value` | CIDR 地址 或 主机名 |
| `rules[].resolve` | host 类型是否需要 DNS 解析 |
| `tunnel` | 隧道连接参数 |

---

## GET `/api/v1/client/config?wait=true&version=17`

长轮询：服务端挂起请求直到配置版本大于客户端当前版本，或超时 60s 返回 304。

### 查询参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `wait` | bool | 开启长轮询 |
| `version` | u64 | 客户端当前持有的版本号 |

### 响应 200

配置有更新，返回完整新配置（结构同上）。

### 响应 304

超时无更新，客户端应立即重新发起长轮询。

---

## POST `/api/v1/client/heartbeat`

客户端心跳上报，告知节点自己在线，同时可上报流量统计。

### 请求头

```
Authorization: Bearer <access_token>
```

### 请求

```json
{
  "uptime": 3600,
  "bytes_tx": 1048576,
  "bytes_rx": 2097152,
  "active_connections": 3
}
```

### 响应 200

```json
{
  "code": 0,
  "data": {
    "config_version": 18,
    "force_disconnect": false
  }
}
```

| 字段 | 说明 |
|------|------|
| `config_version` | 最新配置版本，客户端对比本地决定是否重新拉配置 |
| `force_disconnect` | Admin 强制踢下线标记 |

心跳间隔：60s。连续 3 次未收到心跳，节点标记该客户端为离线。
