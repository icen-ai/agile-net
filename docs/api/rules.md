# Rules API

规则管理，仅 Admin 可操作。

规则属于节点全局资源，通过权限组授权给签发令牌、扇入令牌与扇出对端。

---

## GET `/api/v1/admin/rules`

列出全部规则。

### 查询参数

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `page` | u32 | 1 | |
| `page_size` | u32 | 20 | 最大 100 |
| `type` | string | - | 可选过滤：`ip-cidr`、`host` |
| `q` | string | - | 搜索 value 或 remark |

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "id": "uuid",
        "type": "ip-cidr",
        "value": "10.12.0.0/16",
        "resolve": false,
        "remark": "办公网段",
        "group_count": 2,
        "created_at": "2025-07-30T10:00:00Z",
        "updated_at": "2025-07-30T10:00:00Z"
      }
    ],
    "total": 5,
    "page": 1,
    "page_size": 20
  }
}
```

| 字段 | 说明 |
|------|------|
| `group_count` | 引用了该规则的权限组数量 |
| `remark` | 备注，便于管理 |

---

## POST `/api/v1/admin/rules`

创建单条规则。

### 请求

```json
{
  "type": "ip-cidr",
  "value": "10.12.0.0/16",
  "resolve": false,
  "remark": "办公网段"
}
```

### 验证规则

| 字段 | 校验 |
|------|------|
| `type` | 枚举：`ip-cidr`、`host` |
| `value` | ip-cidr：合法 CIDR 格式；host：合法域名 |
| `value` | 全局唯一（同 type + value 不允许重复） |

### 响应 201

```json
{
  "code": 0,
  "data": {
    "id": "uuid",
    "type": "ip-cidr",
    "value": "10.12.0.0/16",
    "resolve": false,
    "remark": "办公网段",
    "created_at": "2025-07-30T10:00:00Z"
  }
}
```

---

## PUT `/api/v1/admin/rules/:id`

更新规则。

### 请求

```json
{
  "value": "10.12.0.0/12",
  "remark": "扩大到整个 10.12 段"
}
```

所有字段可选，仅更新传入的字段。`type` 不可更改（删除后重建）。

### 响应 200

返回更新后的完整规则对象。

修改规则会触发 `config_version` 递增，watch 通道即刻生效。

---

## DELETE `/api/v1/admin/rules/:id`

删除规则。

如果规则已被权限组引用，返回 40900 并附带引用列表：

```json
{
  "code": 40900,
  "message": "rule is referenced by 2 groups",
  "data": {
    "groups": ["开发组", "运维组"]
  }
}
```

Admin 需先从权限组中移除该规则，或使用 `?force=true` 强制删除（同时解除所有引用）。

### 响应 200

```json
{
  "code": 0,
  "data": null
}
```

---

## POST `/api/v1/admin/rules/batch`

批量导入规则。

### 请求

```json
{
  "rules": [
    { "type": "ip-cidr", "value": "10.12.0.0/16", "remark": "办公网" },
    { "type": "ip-cidr", "value": "10.152.0.0/16", "remark": "测试网" },
    { "type": "host", "value": "git.internal", "resolve": true, "remark": "Git" }
  ],
  "on_conflict": "skip"
}
```

| `on_conflict` | 行为 |
|---------------|------|
| `skip` | 重复的跳过 |
| `overwrite` | 重复的更新 remark 等字段 |
| `error` | 有重复立即返回错误，全部不导入 |

### 响应 200

```json
{
  "code": 0,
  "data": {
    "created": 2,
    "skipped": 1,
    "updated": 0,
    "errors": []
  }
}
```
