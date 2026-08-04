# Delegation API（签发委托，federation P2/P3）

资源主直接向消费者签发接入凭据，经扇出上游代收，**无需创建本地账号**（仅 Admin 可操作）。

- 委托令牌与 relay token 同强度（`psk_` + 48 位、SHA-256 落库、明文仅签发时返回一次）；
- 注册走扇出会话控制帧（协议 v3 Ctrl）：逐上游注册、随会话自动重注册、吊销即断
  （离线上游随断线天然失效）；注册状态实时可见；
- **容灾集合**：同一令牌可注册多个上游（恰好一个主入口）；链接内嵌全量入口与逐入口
  证书指纹，客户端断开按序故障切换；
- **E2E（federation P3）**：引用组含 `e2e_required` 组时自动从主入口有效 advertise 集
  （手工 advertise ∪ 上送组规则）推导路由词（hint），链接携带 `ehint`——消费者全部
  Open 端到端加密，中继只见路由词；
  E2E 主密钥（HKDF(token)）AES-256-GCM 加密落库（第二个、也是最后一个可逆例外）。

---

## GET `/api/v1/admin/delegation/tokens`

列出全部委托令牌（组名已解析，容灾集合带逐上游实时注册状态）。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "id": "uuid",
        "token_prefix": "psk_xxxx",
        "label": "alice 的笔记本",
        "groups": [{ "id": "uuid", "name": "git", "e2e_required": false }],
        "mode": "dedicated",
        "hint_map": [{ "hint": "relay.internal", "groups": ["db-prod"] }],
        "regs": [
          {
            "connector_id": "uuid",
            "connector_name": "机房B",
            "upstream_addr": "relay-b.example.com:54430",
            "is_primary": true,
            "state": "registered"
          }
        ],
        "created_at": "2026-08-04T10:00:00Z"
      }
    ]
  }
}
```

`regs[].state`：`registered` / `pending`（注册中）/ `failed: <原因>` / `offline`（上游离线）/
`unsupported`（上游协议 < v3，不支持委托）。

---

## POST `/api/v1/admin/delegation/tokens`

签发委托令牌。**明文仅此一次**（`token` 字段），分享链接内含完整容灾集合与 E2E 路由词。

### 请求

```json
{
  "label": "alice 的笔记本",
  "group_ids": ["uuid", "uuid"],
  "regs": [
    { "connector_id": "uuid", "is_primary": true },
    { "connector_id": "uuid", "is_primary": false }
  ],
  "hint_map": [],
  "mode": "split"
}
```

- `label`：必填，≤128 字符（导入方可见，链接 `account=d:<label>` 标记）。
- `group_ids`：至少一个本地权限组 ID；组必须存在。
- `regs`：容灾集合，至少一条且**恰好一个主入口**；connector 必须存在。
- `hint_map`：可空。引用组含 `e2e_required` 组且未显式提供时，自动从主入口的**有效
  advertise 集**（手工 advertise ∪ 上送组规则，与上游路由表实际承载一致）推导单条路由词
  （CIDR → 网络号+1，`*.suffix` → `relay<suffix>`，具体主机 → 自身）；
  有效集为空时报错（无法生成可路由的词——请先为该扇出配置上送组或路由宣告）。
- `mode`：可空，默认 `dedicated`（**专线**——委托方整机流量进隧道，词表对委托方不可见）。
  `split`（**分流**）要求引用组含 `e2e_required` 组：链接携带 `emode=split`，委托方连上后
  经 E2E 配置通道（保留目标 `__anet_delegation_config__`，中继只见路由词）拉取令牌有效
  词表并改为选择性路由，拉取失败回退专线行为；签发端改规则后委托方重连即刷新。

### 响应 201

在 GET 的单项结构基础上追加：

```json
{
  "code": 0,
  "data": {
    "id": "uuid",
    "token": "psk_<48 chars>",
    "share_url": "anet://connect?server=relay-b.example.com&port=54430&account=d%3Aalice&password=psk_...&fp=aa11&ehint=relay.internal&entry=relay-b.example.com%3A54430%2Crelay-c.example.com%3A54430&entryfp=aa11%2C",
    "token_prefix": "psk_xxxx",
    "label": "alice 的笔记本"
  }
}
```

`share_url` 形态：`server/fp` = 主入口地址与 relay 证书指纹；`entry/entryfp` = 容灾集合
全量地址与逐入口指纹（单项可空 = 该入口回退 TOFU）；`ehint` = E2E 路由词（仅引用组含
`e2e_required` 组时出现）。审计事件 `delegation.issue`。

### 错误

- `40010`：参数校验失败（label 空/超长、组或 connector 不存在、无组、容灾集合空、
  主入口非恰好一个、E2E 组无可推导路由词）。

---

## DELETE `/api/v1/admin/delegation/tokens/{id}`

吊销：本地删除 + 向容灾集合内**每个在线上游**发吊销帧（离线上游随断线天然失效）；
B 侧清除注册并踢出该令牌的全部活动会话。审计事件 `delegation.revoke`。

### 响应 200

```json
{ "code": 0, "data": { "revoked": true } }
```

### 错误

- `40400`：委托令牌不存在。

---

## 相关审计事件

| 事件 | 来源 | 说明 |
|------|------|------|
| `delegation.issue` | C（签发端） | 签发（label/组数/集合大小；不记明文） |
| `delegation.revoke` | C（签发端） | 吊销 |
| `delegation.register` | B（中继端） | 扇出会话注册委托令牌（issuer + label） |
| `delegation.revoke` | B（中继端） | 注册被吊销/失效 |

审计严禁记录令牌明文、blob、E2E 明文与真实目标；E2E 会话仅路由词可记。
