# API 协议总览

## 角色与通信关系

```
Admin  ──────── HTTPS ────────> Node (API + 管理端 SPA / + 客户端 SPA /client)
Client ──────── TLS ──────────> Node (Relay 数据面，委托令牌即身份)
Node   ──────── TLS ──────────> Node (Relay Protocol)
```

## 基础约定

| 项 | 值 |
|----|-----|
| 基路径 | `/api/v1` |
| 内容类型 | `application/json` |
| 认证方式 | `Authorization: Bearer <jwt>` |
| 时间格式 | ISO 8601 `2025-07-30T12:00:00Z` |
| ID 格式 | UUIDv4 |

## 统一响应体

### 成功

```json
{
  "code": 0,
  "data": { ... }
}
```

### 分页

```json
{
  "code": 0,
  "data": {
    "items": [ ... ],
    "total": 42,
    "page": 1,
    "page_size": 20
  }
}
```

### 错误

```json
{
  "code": 40100,
  "message": "invalid credentials"
}
```

## 错误码

| 范围 | 类别 | 示例 |
|------|------|------|
| 40000–40099 | 请求格式 | 40000 bad_request, 40001 validation_failed |
| 40100–40199 | 认证 | 40100 invalid_credentials, 40101 token_expired, 40102 token_revoked |
| 40300–40399 | 授权 | 40300 forbidden, 40301 admin_only |
| 40400–40499 | 资源 | 40400 not_found |
| 40900–40999 | 冲突 | 40900 duplicate_name |
| 42900–42999 | 频率 | 42900 rate_limited |
| 50000–50099 | 服务端 | 50000 internal_error |

## 模块索引

| 模块 | 文件 | 说明 |
|------|------|------|
| 认证 | [auth.md](auth.md) | 登录、刷新、登出（管理端/客户端 SPA 共用 AdminAuth） |
| 规则管理 | [rules.md](rules.md) | CRUD + 批量导入 |
| 权限组管理 | [groups.md](groups.md) | CRUD + 规则绑定 + 身份总览 |
| 扇出管理 | [connectors.md](connectors.md) | connector CRUD + 启停 + 对端收敛 + 策略上送 |
| 统一签发 | [delegation.md](delegation.md) | 委托令牌签发/吊销 + 入口/信任/路由/并发四维度 |
| 节点状态 | [node.md](node.md) | 状态查询 + 流量统计 + WebSocket 事件 |
