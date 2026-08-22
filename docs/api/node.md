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
      "listen": "127.0.0.1:57890",
      "active_connections": 15,
      "rule_count": 8
    },
    "system": {
      "cpu_usage": 3.2,
      "memory_mb": 85,
      "open_fds": 128
    }
  }
}
```

### 流量核算字段（roles.fanout_traffic / roles.transit / traffic_24h）

`data.roles` 另含两个流量字段，`data` 顶层另含 24h 序列：

```json
{
  "code": 0,
  "data": {
    "roles": {
      "fanout_traffic": [
        { "name": "site-a", "bytes_up": 1048576, "bytes_down": 2097152 }
      ],
      "transit": {
        "bytes_up": 3145728,
        "bytes_down": 6291456,
        "pairs": [
          { "from": "proxy", "to": "node-c", "bytes_up": 1024, "bytes_down": 2048 },
          { "from": "node-a", "to": "local", "bytes_up": 512, "bytes_down": 512 }
        ]
      }
    },
    "traffic_24h": {
      "fanin":   [ { "hour": "2026-08-02 09:00", "up": 100, "down": 200 } ],
      "fanout":  [ { "hour": "2026-08-02 09:00", "up": 7, "down": 8 } ],
      "transit": [ { "hour": "2026-08-02 09:00", "up": 3, "down": 4 } ]
    }
  }
}
```

- `roles.fanout_traffic`：扇出逐条当前会话实时累计（connector name；断连为 0）。
- `roles.transit`：中继途径实时快照（自节点启动累计，桥接关闭时入账）。
  - `from` = 扇入对端 node_id / `proxy`（本地代理入站）/ connector name（上游经扇出 connector 的反向来流）
  - `to` = 下游对端 node_id / `local`（本机终结；代理 Forward 出站按本机终结计）
- `traffic_24h`：最近 24 小时按小时聚合（本地时间 `YYYY-MM-DD HH:00`；无数据小时缺省；
  fanin/fanout 跨标识汇总、transit 跨途径对汇总；数据源 `node_traffic_log` 表分钟级采样差分）。
- 三维互为独立视角：同一字节可能在 fanin 与 transit 中各计一次（前者按对端会话、后者按途径对）。

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
  "public_host": "anet.example.com",
  "public_api_url": "https://anet.example.com"
}
```

所有字段可选，仅更新传入的字段：

| 字段 | 说明 |
|------|------|
| `node_name` | 1-64 字符 |
| `public_host` | 公网会合点对外身份（公网 IP 或域名；接入链接与隧道端点的展示地址；保存即热生效，无需重启） |
| `public_api_url` | API 反代端点（federation P1：API 经 HTTPS 反代时的 scheme + 端口覆盖；`http(s)://host[:port]`，无路径；空串 = 清除。接入链接随之携带 https scheme） |

### 响应 200

```json
{
  "code": 0,
  "data": {
    "applied": ["node_name", "public_host"],
    "restart_required": []
  }
}
```

---

## GET `/api/v1/admin/federation/offered`

可授权池（federation P1）：在线扇入端点随握手上送的路由与权限组，来源 tag = 端点 node_id。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "node_id": "peer-c",
        "advertise": ["10.12.0.0/16", "git.internal"],
        "groups": [
          { "name": "git", "remark": "代码组", "rules": ["git.internal", "10.12.0.0/16"] }
        ]
      }
    ]
  }
}
```

仅在线端点入池（上送内容随扇入会话存活，断开即清除）；无 relay listener 时返回空列表。

---

## POST `/api/v1/admin/federation/adopt`

一键采纳：把池中的上送组物化为本地权限组（规则按 `(type, value)` 唯一性复用或新建）。
**命名主权**：组名 = 纯源组名（不带 `@node` 后缀），来源走 `adopted_node` 血缘 + UI 徽章；
本机组与采纳组可同名共存（唯一性分两层：本机 name 唯一 / 采纳组 (name, adopted_node) 唯一）。
审计 `federation.adopt`。

### 请求

```json
{ "node_id": "peer-c", "group": "git" }
```

### 响应 200

```json
{
  "code": 0,
  "data": { "id": "uuid", "name": "git", "rule_count": 2, "reused": 0 }
}
```

端点不在线 / 上送组不存在均返回 40400。采纳后的本地组与手工创建的组同构（只读活镜像，
`federation/adopted/{id}/copy` 可复制为可编辑本地组）；资源主侧的后续变更经 watcher
漂移写跟随（源离线保留快照）。

---

## POST `/api/v1/admin/node/relay-tokens`

生成一个新的 relay PSK token，用于授权下游节点连入。

### 请求

```json
{
  "remark": "分公司跳板机",
  "expose_control": false,
  "control_scope": "full",
  "group_id": "uuid",
  "guarded": false
}
```

| 字段 | 说明 |
|------|------|
| `remark` | 可选，0-256 字符（M3-T6 起即扇入列表中的对端显示名） |
| `my_name` | 可选，≤64 字符（M3-T6）：建议对端使用的自声明名称，预填进分享链接的 `myname` 词（仅随链接传递，不落库） |
| `expose_control` | 可选，默认 false：允许持该令牌的下游中继管理本节点 |
| `control_scope` | 可选，默认 `full`：管理授权档位 `ro` / `rules` / `full` |
| `group_id` | 可选，收敛权限组（对端粒度 ACL）；缺省/null = 不收敛，ID 不存在返回 40400 |
| `guarded` | 可选，默认 false（信任档 G3 深度防护）：该令牌下行 advertise 与他下行重叠即**拒绝**（非 guarded 只记 warning 审计）、上送组不进有效集（须 federation/adopt 人工采纳）、接入设备**强制审批**（覆盖全局 `device_pending_policy=allow`）；开启记 `relay_token.guarded` 审计，重叠事件记 `relay_token.advertise_conflict` 审计 |

### 响应 201

```json
{
  "code": 0,
  "data": {
    "id": "uuid",
    "token": "psk_xxxxxxxxxxxxxxxx",
    "token_prefix": "psk_xxxx****",
    "remark": "分公司跳板机",
    "expose_control": false,
    "control_scope": "full",
    "group_id": "uuid",
    "created_at": "2025-07-30T10:00:00Z",
    "share_url": "anet://fanout?server=anet.example.com&port=54430&token=psk_xxxxxxxxxxxxxxxx&sni=cdn.cloudflare.com&fp=ab12...",
    "endpoints": [
      { "kind": "public", "addr": "anet.example.com:54430" },
      { "kind": "lan", "addr": "192.168.1.5:54430" }
    ]
  }
}
```

扇入令牌分享链接化（federation P1）：`share_url` 为一键导入链接（`anet://fanout`，地址优先级 = 对外声明
`public_host` > 监听地址；含 SNI 与证书指纹钉值）；`endpoints` 为签发对话框的端点候选
（`public` 对外声明身份 / `lan` 同内网直连 / `local` 回环兜底），前端切换端点即重拼链接，无需重新请求。

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
        "expose_control": false,
        "control_scope": "full",
        "group_id": "uuid",
        "guarded": false,
        "last_used_at": "2025-07-30T14:00:00Z",
        "created_at": "2025-07-30T10:00:00Z"
      }
    ]
  }
}
```

Token 全文仅创建时返回，列出时只显示前缀。

---

## PUT `/api/v1/admin/node/relay-tokens/:id`

更新 relay token 的暴露开关、授权档位与收敛组。

### 请求

```json
{
  "expose_control": true,
  "control_scope": "rules",
  "group_id": null,
  "guarded": true
}
```

`group_id` 为**三态**：缺省 = 不变，`null` = 不收敛，字符串 = 挂到该组（记 `relay_token.set_group` 审计）。
`remark`（M3-T6 对端显示名）同样三态：缺省 = 不变，字符串 = 更新（记 `relay_token.set_remark` 审计）。
`guarded`（信任档 G3）同样三态：缺省 = 不变，true/false = 设置（记 `relay_token.guarded` 审计）；
变更即踢在线对端（同组变更契约）——重连后新档立即生效。

### 响应 200

返回更新后的 token 对象。

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
`proxy_active/total_connections`、`proxy_bytes{direction}`、`rules_total`。

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

浏览器 WebSocket 无法设置请求头；为不让 token 进访问日志与浏览器历史，认证走
**升级后首条消息**：连接建立后立即发送 access_token（5s 超时），服务端校验 admin
角色与 scope 档位（fail-closed）后才开始推送事件。

### 事件格式

```json
{
  "type": "consumer.online",
  "time": "2025-07-30T14:30:00Z",
  "data": { "session_key": "uuid" }
}
```

### 事件类型

| type | 触发时机 |
|------|---------|
| `consumer.online` | 消费者（委托令牌会话）上线（data.session_key） |
| `consumer.offline` | 消费者下线（data.session_key） |
| `connector.connected` | 下游节点连入 |
| `connector.disconnected` | 下游节点断开 |
| `peer.acl_denied` | 对端流量被收敛拒绝（data 含对端标识 `peer_label` 与 `target`） |
| `delegation.registered` | 委托令牌在本端点注册（data 含 `node_id` 与 `label`） |
| `delegation.revoked` | 委托令牌注册被吊销（data 含 `node_id` 与 `label`） |
| `stats.snapshot` | 每 30s 发送一次流量快照 |
