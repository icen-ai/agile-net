# Groups API

权限组管理，仅 Admin 可操作。

权限组是规则和账号之间的桥梁：一个账号属于一个权限组，权限组包含多条规则。

---

## GET `/api/v1/admin/groups`

列出全部权限组。

### 查询参数

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `page` | u32 | 1 | |
| `page_size` | u32 | 20 | 最大 100 |
| `q` | string | - | 搜索名称或备注 |

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "id": "uuid",
        "name": "开发组",
        "remark": "前后端开发人员",
        "rule_count": 3,
        "account_count": 5,
        "created_at": "2025-07-30T10:00:00Z",
        "updated_at": "2025-07-30T10:00:00Z"
      }
    ],
    "total": 3,
    "page": 1,
    "page_size": 20
  }
}
```

---

## GET `/api/v1/admin/groups/:id`

权限组详情，包含关联的规则列表。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "id": "uuid",
    "name": "开发组",
    "remark": "前后端开发人员",
    "rules": [
      { "id": "uuid", "type": "ip-cidr", "value": "10.12.0.0/16", "remark": "办公网" },
      { "id": "uuid", "type": "host", "value": "git.internal", "remark": "Git" }
    ],
    "accounts": [
      { "id": "uuid", "username": "zhangsan", "enabled": true }
    ],
    "created_at": "2025-07-30T10:00:00Z",
    "updated_at": "2025-07-30T10:00:00Z"
  }
}
```

---

## GET `/api/v1/admin/groups/:id/detail`

权限组身份总览：返回组下三类身份（账号 + 扇入令牌 + 扇出对端）。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "accounts": [{ "id": "uuid", "username": "zhangsan", "enabled": true }],
    "relay_tokens": [{ "id": "uuid", "token_prefix": "psk_xxxx", "remark": "分公司跳板" }],
    "connectors": [{ "id": "uuid", "name": "机房B", "upstream_addr": "relay-b.example.com:54430", "enabled": true }]
  }
}
```

---

## POST `/api/v1/admin/groups`

创建权限组。

### 请求

```json
{
  "name": "开发组",
  "remark": "前后端开发人员",
  "rule_ids": ["uuid1", "uuid2"]
}
```

| 字段 | 校验 |
|------|------|
| `name` | 必填，1-64 字符，全局唯一 |
| `remark` | 可选，0-256 字符 |
| `rule_ids` | 可选，关联的规则 ID 列表；ID 不存在返回 40400 |

### 响应 201

返回完整权限组对象（含 rules）。

---

## PUT `/api/v1/admin/groups/:id`

更新权限组。

### 请求

```json
{
  "name": "开发组(含前端)",
  "remark": "更新备注"
}
```

所有字段可选。**不包含 `rule_ids`**，规则关联通过下面的专用接口管理。

### 响应 200

返回更新后的完整权限组对象。

---

## PUT `/api/v1/admin/groups/:id/rules`

**全量设置**权限组关联的规则。

### 请求

```json
{
  "rule_ids": ["uuid1", "uuid2", "uuid3"]
}
```

语义：替换该组的全部规则关联。传空数组 `[]` 清空所有规则。

修改规则关联会触发 `config_version` 递增。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "rule_count": 3
  }
}
```

---

## DELETE `/api/v1/admin/groups/:id`

删除权限组。

如果组下还有账号，返回 40900：

```json
{
  "code": 40900,
  "message": "group has 3 accounts, reassign or delete them first"
}
```

`?force=true` 强制删除，组下账号同时删除。

### 响应 200

```json
{
  "code": 0,
  "data": null
}
```
