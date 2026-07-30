# Accounts API

账号管理，仅 Admin 可操作。

账号是客户端的身份凭据，每个账号属于一个权限组，权限组决定该账号能访问哪些内网资源。

---

## GET `/api/v1/admin/accounts`

列出全部账号。

### 查询参数

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `page` | u32 | 1 | |
| `page_size` | u32 | 20 | 最大 100 |
| `group_id` | string | - | 按权限组过滤 |
| `enabled` | bool | - | 按状态过滤 |
| `q` | string | - | 搜索用户名或备注 |

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "id": "uuid",
        "username": "zhangsan",
        "group": {
          "id": "uuid",
          "name": "开发组"
        },
        "enabled": true,
        "online": true,
        "last_seen_at": "2025-07-30T14:30:00Z",
        "remark": "张三 - 前端",
        "created_at": "2025-07-30T10:00:00Z"
      }
    ],
    "total": 12,
    "page": 1,
    "page_size": 20
  }
}
```

| 字段 | 说明 |
|------|------|
| `online` | 是否在线（基于心跳判断） |
| `last_seen_at` | 最后心跳时间 |

---

## POST `/api/v1/admin/accounts`

创建账号，系统自动生成强密码。

### 请求

```json
{
  "username": "zhangsan",
  "group_id": "uuid",
  "remark": "张三 - 前端"
}
```

| 字段 | 校验 |
|------|------|
| `username` | 必填，3-32 字符，`[a-zA-Z0-9_-]`，全局唯一 |
| `group_id` | 必填，权限组 ID 必须存在 |
| `remark` | 可选，0-256 字符 |

### 响应 201

```json
{
  "code": 0,
  "data": {
    "id": "uuid",
    "username": "zhangsan",
    "password": "XkR7mNpQ2vH5bT3c",
    "group": {
      "id": "uuid",
      "name": "开发组"
    },
    "enabled": true,
    "remark": "张三 - 前端",
    "created_at": "2025-07-30T10:00:00Z",
    "connect_url": "agilenet://connect?server=cdn.example.com&port=443&account=zhangsan&password=XkR7mNpQ2vH5bT3c&tls=1"
  }
}
```

**`password` 和 `connect_url` 仅在创建时返回一次**，后续不可查看。Admin 需当场保存或生成二维码发给用户。

---

## PUT `/api/v1/admin/accounts/:id`

更新账号信息。

### 请求

```json
{
  "group_id": "new_group_uuid",
  "enabled": false,
  "remark": "张三 - 已离职"
}
```

所有字段可选。更改 `group_id` 会触发 `config_version` 递增，客户端长轮询收到新配置。

设置 `enabled: false` 后：
1. 该账号的 JWT 立即失效（加入黑名单）
2. 活跃的隧道连接在下次心跳时被踢下线
3. 无法重新登录

---

## POST `/api/v1/admin/accounts/:id/reset-password`

重置密码，生成新的强密码。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "password": "Yw9kPm3nRx6vJt2q",
    "connect_url": "agilenet://connect?server=cdn.example.com&port=443&account=zhangsan&password=Yw9kPm3nRx6vJt2q&tls=1"
  }
}
```

旧密码立即失效，旧隧道连接在下次心跳或 tunnel_token 过期时断开。

---

## GET `/api/v1/admin/accounts/:id/qrcode`

获取账号接入信息的二维码图片。

### 响应

```
Content-Type: image/png
(二维码 PNG 图片)
```

二维码内容是 `connect_url`。此接口不返回明文密码——仅对已有 password 的 connect_url 编码。因此**仅在创建账号或重置密码后**，Admin 调用此接口才有意义（密码已嵌入 connect_url 并临时缓存在内存中，10 分钟后清除）。

---

## DELETE `/api/v1/admin/accounts/:id`

删除账号。

### 响应 200

```json
{
  "code": 0,
  "data": null
}
```

删除后该账号的所有 token 立即失效，活跃连接被断开。
