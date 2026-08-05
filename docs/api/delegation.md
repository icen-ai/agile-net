# Delegation API（签发委托，federation P2/P3）

资源主直接向消费者签发接入凭据，经扇出上游代收，**无需创建本地账号**（仅 Admin 可操作）。

- 委托令牌与 relay token 同强度（`psk_` + 48 位、SHA-256 落库、明文仅签发时返回一次）；
- 注册走扇出会话控制帧（协议 v3+ Ctrl）：逐上游注册、随会话自动重注册、吊销即断
  （离线上游随断线天然失效）；注册状态实时可见；
- **容灾集合**：同一令牌可注册多个上游（恰好一个主入口）；链接内嵌全量入口与逐入口
  证书指纹，客户端断开按序故障切换；
- **E2E（federation P3）**：引用组含 `e2e_required` 组时自动签发 **entrust 路由词**
  （`en_<令牌哈希前 12 hex>`，协议 v4+）——**路由与权限组内容彻底分离：签发 E2E 委托不再
  要求上送组或路由宣告（零规则泄露，entrust 注册表免路由校验）**；主入口有效 advertise 集
  非空时另附 legacy hint 作旧端回退（链接同时携带 `en` 与 `ehint`，新端 v4+ 优先 en、旧端
  回退 ehint）。消费者全部 Open 端到端加密，中继只见不透明路由词；
  E2E 主密钥（HKDF(token)）AES-256-GCM 加密落库（第二个、也是最后一个可逆例外）；
- **令牌生命周期（v15+）**：签发可选 `expires_at` / `max_uses`（默认不限）；过期/用尽后
  注册同步停止上送（状态 `expired`/`exhausted`），签发端数据面同步硬拒。

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
`unsupported`（上游协议 < v3，不支持委托）/ `expired` / `exhausted`（令牌生命周期已尽，
注册同步不再上送）。

单项另含 `expires_at` / `max_uses` / `used_count` / `lifecycle`
（`active` / `expiring`<72h / `expired` / `exhausted`，列表徽标直用）。

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
- `hint_map`：可空。通常无需提供——E2E 令牌自动携带 entrust 词；主入口有效 advertise 集
  非空时自动追加一条 legacy 回退词（CIDR → 网络号+1，`*.suffix` → `relay<suffix>`，具体
  主机 → 自身）。显式提供时按提供值（entrust 词仍自动前置）。
- `mode`：可空，默认 `dedicated`（**专线**——委托方整机流量进隧道，词表对委托方不可见）。
  `split`（**分流**）要求引用组含 `e2e_required` 组：链接携带 `emode=split`，委托方连上后
  经 E2E 配置通道（保留目标 `__anet_delegation_config__`，中继只见路由词）拉取令牌有效
  词表并改为选择性路由，拉取失败回退专线行为；签发端改规则后委托方重连即刷新。
- `admin_scope`：可空，默认 `''`（纯数据面）。`ro` / `rules` / `full` = 授权管理本端点：
  引导票据经同一 E2E 配置通道下发（**要求引用组含 `e2e_required` 组**——票据绝不明文过
  中继），委托方桌面端经保留目标 `__anet_delegation_admin__` 桥接本端点管理控制台；
  `full` 档额外获得本端点已发现上游的报价，可穿透管理（blob 目标 `upstream:<节点名>`，
  签发端同会话嵌套信道直拨）。链接携带 `eadmin=1` 能力提示。
- `expires_at`：可空，默认永不过期（RFC3339 任意偏移或 `YYYY-MM-DDTHH:MM`，一律按 UTC
  规范化存储；早于当前时间判 400）。
- `max_uses`：可空，默认不限（正整数；按数据面打开次数计，签发端内存计数、缓存刷新时落库）。

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
全量地址与逐入口指纹（单项可空 = 该入口回退 TOFU）；`en` = entrust 词（E2E 令牌必有，
零泄露路由）；`ehint` = legacy E2E 路由词（主入口有效 advertise 集非空时附带，旧端回退）。
审计事件 `delegation.issue`。

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
