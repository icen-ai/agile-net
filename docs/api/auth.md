# Auth API

客户端和 Admin 共用登录入口，通过返回的 `role` 区分身份。

---

## POST `/api/v1/auth/login`

登录，获取 JWT。

**频率限制**：5 次/分钟/IP，连续失败 5 次锁定 15 分钟。

### 请求

```json
{
  "username": "admin",
  "password": "password123"
}
```

### 响应 200

```json
{
  "code": 0,
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "tunnel_token": "tun_xxxx",
    "role": "admin",
    "expires_in": 900
  }
}
```

| 字段 | 说明 |
|------|------|
| `access_token` | API 认证，15min (admin) / 1h (client) |
| `refresh_token` | 刷新用，7d (admin) / 30d (client) |
| `tunnel_token` | 仅 role=client 返回，隧道数据面认证用，30d |
| `role` | `"admin"` 或 `"client"` |
| `expires_in` | access_token 剩余秒数 |

### 错误

| code | 场景 |
|------|------|
| 40100 | 用户名或密码错误 |
| 42900 | 登录过于频繁 |

---

## POST `/api/v1/auth/refresh`

用 refresh_token 换新的 access_token。

### 请求

```json
{
  "refresh_token": "eyJ..."
}
```

### 响应 200

```json
{
  "code": 0,
  "data": {
    "access_token": "eyJ...",
    "tunnel_token": "tun_yyyy",
    "expires_in": 900
  }
}
```

`tunnel_token` 仅 client 角色返回，每次刷新时一起更新。

### 错误

| code | 场景 |
|------|------|
| 40101 | refresh_token 过期 |
| 40102 | refresh_token 已被吊销 |

---

## POST `/api/v1/auth/logout`

登出，吊销当前 refresh_token。

### 请求头

```
Authorization: Bearer <access_token>
```

### 响应 200

```json
{
  "code": 0,
  "data": null
}
```

---

## POST `/api/v1/auth/init`

首次初始化节点管理员。**仅当数据库中无任何 admin 时可用。**

### 请求

```json
{
  "username": "admin",
  "password": "StrongPassword123"
}
```

### 响应 200

```json
{
  "code": 0,
  "data": {
    "admin_id": "uuid",
    "message": "admin created, please login"
  }
}
```

### 错误

| code | 场景 |
|------|------|
| 40300 | 已存在管理员 |
