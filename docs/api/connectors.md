# Connectors API

扇出对端（connector）管理，仅 Admin 可操作。

connector 为一等入库资源：TOML `[[connectors]]` 仅启动导入（name 取 upstream_addr，组 = 不收敛），
运行时以数据库为准。本组接口的全部变更即时热生效（增/删/改/启停直接驱动连接装配）。

- `group_id` 挂权限组即对端收敛（对端隧道反向来的流量按组规则集合放行）；缺省 = 不收敛。
- 扇出 token 是对端签发的连接凭据：AES-256-GCM 加密落库（全库唯一可逆例外），
  **创建后不回显**（只允许重置）；审计不落 token 明文/密文。

---

## GET `/api/v1/admin/connectors`

列出全部扇出对端（含实时状态）。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "id": "uuid",
        "name": "机房B",
        "upstream_addr": "relay-b.example.com:54430",
        "token_prefix": "psk_xxxx",
        "sni_hostname": "cdn.cloudflare.com",
        "insecure": false,
        "ca_cert_path": "",
        "pinned_cert_path": "certs/up.pem",
        "advertise": "10.12.0.0/16,git.internal",
        "group_id": "uuid",
        "group_name": "办公组",
        "guarded": false,
        "enabled": true,
        "remark": "分公司出口",
        "state": "connected",
        "created_at": "2026-08-01T10:00:00Z",
        "updated_at": "2026-08-01T10:00:00Z"
      }
    ]
  }
}
```

`state` 为实时连接状态（`connected` / `connecting` / `reconnecting` / `disconnected`）；
`token_prefix` 仅用于辨认，非完整凭据。

---

## POST `/api/v1/admin/connectors`

创建扇出对端并热装配起连（装配失败不阻断创建，状态显示 `disconnected`）。

### 请求

```json
{
  "name": "机房B",
  "upstream_addr": "relay-b.example.com:54430",
  "token": "psk_xxxxxxxxxxxxxxxx",
  "sni_hostname": "cdn.cloudflare.com",
  "insecure": false,
  "ca_cert_path": "",
  "pinned_cert_path": "certs/up.pem",
  "advertise": ["10.12.0.0/16", "git.internal"],
  "group_id": "uuid",
  "guarded": false,
  "push_groups": ["uuid-g1", "uuid-g2"],
  "remark": "分公司出口"
}
```

| 字段 | 校验 |
|------|------|
| `name` | 必填，1-64 字符，全局唯一（冲突 40900） |
| `my_name` | 可选，≤64 字符（M3-T6）：握手上送给对端的自声明名称，空 = 节点 ID |
| `upstream_addr` | 必填，1-253 字符（host:port） |
| `token` | 必填，1-256 字符；加密落库，响应不回显 |
| `sni_hostname` / `ca_cert_path` / `pinned_cert_path` | 可选；证书固定优先级 pinned > ca > insecure |
| `insecure` | 可选，默认 false（跳过证书校验，仅开发用） |
| `advertise` | 可选，**字符串数组**（≤64 条，单条 ≤256 字符）；入库序列化为逗号拼接 |
| `group_id` | 可选；缺省/null = 不收敛；ID 不存在返回 40400 |
| `push_groups` | 可选，策略上送（federation P1）：本地权限组 ID 数组（≤32 个，去重，ID 不存在 40400）；随扇出握手推送给上游，进入其可授权池供一键采纳；缺省/空数组 = 不上送 |
| `guarded` | 可选，默认 false（信任档 G2 深度防护）：开启后保存校验强制 `pinned_fingerprint` 非空且 `insecure=false`（违反返回 40000 中文错误），guarded 连接的连接/上送/advertise 变更落审计并附变更字段摘要 |
| `remark` | 可选，0-256 字符 |

### 响应 201

返回完整 connector 对象（同列表项，含 `state` 与 `push_groups` 逗号拼接串）。

---

## PUT `/api/v1/admin/connectors/:id`

更新扇出对端。**全量替换语义**：除 `token` 外缺省字段即置默认值
（`group_id` 缺省/null = 不收敛）；`token` 留空/null = 保留原值，传入新值 = 重置；
`push_groups` 缺省 = 保留当前上送组，传入（含空数组）= 替换。
更新后先断旧连接再装配新连接。

### 响应 200

返回更新后的完整对象。审计 detail 只记 `token rotated/kept`，不落明文/密文。

---

## DELETE `/api/v1/admin/connectors/:id`

删除扇出对端并断开其连接。

### 响应 200

```json
{ "code": 0, "data": null }
```

---

## POST `/api/v1/admin/connectors/:id/enable`

启用：装配起连。

## POST `/api/v1/admin/connectors/:id/disable`

禁用：断开连接并从装配移除（DB 记录保留，`enabled=false`）。

### 响应 200

返回完整对象（含最新 `state`）。
