# Delegation API（统一签发）

资源主直接向消费者签发接入凭据，**令牌即唯一身份**（仅 Admin 可操作）。统一签发的四个维度：

- **入口 `entry_mode`**：`relay`（默认）经扇出容灾集合会合点进入，注册随上游会话存活；
  `direct` 消费者直连签发者本机 listener，自注册进签发者本地持久注册表（TLS 已端到端，
  信任档锁明文）。
- **信任档**：明文（默认）/ E2E（引用组含 `e2e_required` 组时自动携带 entrust 路由词
  `en_<令牌哈希前 12 hex>`，路由与权限组内容彻底分离，零规则泄露）/ E2E + 管理档
  （`admin_scope` 非空，引导票据经 E2E 配置通道下发，绝不明文过中继）。
- **路由 `mode`**：`dedicated`（默认，**专线**——委托方整机流量进隧道，词表不可见）/
  `split`（**分流**——词表经 E2E 配置通道下发换选择性路由，要求引用组含 `e2e_required` 组，
  拉取失败回退专线行为）。
- **并发 `concurrency`**：`single`（默认，同令牌新会话踢旧）/ `multi`（多会话并存，
  上限 `max_sessions`——签发时从 node_config `delegation_max_sessions` 读快照，默认 8）。

其他约束：

- 委托令牌与 relay token 同强度（`psk_` + 48 位、SHA-256 落库、明文仅签发时返回一次）；
- relay 入口的注册走扇出会话控制帧：逐上游注册、随会话自动重注册、吊销即断（离线上游
  随断线天然失效）；注册状态实时可见；
- E2E 主密钥（HKDF(token)）AES-256-GCM 加密落库（可逆存储例外之一）；
- **拓扑可见性 `visibility`**（M6）：`domain`（默认，跨域只见域主体）/ `disclose`（披露回执
  落 grant_receipt）/ `approve`（上游注册先压审批中心，批准后生效）；非默认档随链接
  `visibility` 词表达，消费端导入时弹条款卡确认（M4-T5）。
- **令牌生命周期**：签发可选 `expires_at` / `max_uses`（默认不限）；过期/用尽后注册同步
  停止上送（状态 `expired`/`exhausted`），签发端数据面同步硬拒。

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
        "admin_scope": "",
        "entry_mode": "relay",
        "concurrency": "single",
        "max_sessions": 8,
        "hint_map": [{ "hint": "en_ab12cd34ef56", "groups": ["db-prod"] }],
        "regs": [
          {
            "connector_id": "uuid",
            "connector_name": "机房B",
            "upstream_addr": "relay-b.example.com:54430",
            "is_primary": true,
            "state": "registered"
          }
        ],
        "created_at": "2026-08-04T10:00:00Z",
        "expires_at": null,
        "max_uses": null,
        "used_count": 0,
        "lifecycle": "active"
      }
    ]
  }
}
```

`regs[].state`：`registered` / `pending`（注册中）/ `failed: <原因>` / `offline`（上游离线）/
`expired` / `exhausted`（令牌生命周期已尽，注册同步不再上送）。direct 入口无 regs。

`lifecycle`：`active` / `expiring`（<72h）/ `expired` / `exhausted`，列表徽标直用。

---

## POST `/api/v1/admin/delegation/tokens`

签发委托令牌。**明文仅此一次**（`token` 字段），分享链接内含完整入口集合与 E2E 路由词。

### 请求

```json
{
  "label": "alice 的笔记本",
  "group_ids": ["uuid", "uuid"],
  "regs": [
    { "connector_id": "uuid", "is_primary": true },
    { "connector_id": "uuid", "is_primary": false }
  ],
  "mode": "dedicated",
  "admin_scope": "",
  "entry_mode": "relay",
  "concurrency": "single"
}
```

- `label`：必填，≤128 字符（导入方可见，链接 `account=d:<label>` 标记）。
- `group_ids`：至少一个本地权限组 ID；组必须存在。
- `regs`：仅 `entry_mode=relay` 使用——容灾集合，至少一条且**恰好一个主入口**；
  connector 必须存在。`direct` 模式忽略此字段。
- `entry_mode`：可空，默认 `relay`。`direct` = 消费者直连签发者本机 listener（链接入口
  集合 = 本端点对外声明 public_host > 内网直连枚举 > 回环兜底，逐入口钉本机 relay 证书
  指纹），自注册进本地持久注册表，无上游往返。
- `concurrency`：可空，默认 `single`（同令牌新会话踢旧留新）。`multi` = 多会话并存，
  上限为签发时 node_config `delegation_max_sessions` 快照（默认 8），响应 `max_sessions`
  回显该快照。
- `mode`：可空，默认 `dedicated`。`split` 要求引用组含 `e2e_required` 组：链接携带
  `emode=split`，委托方连上后经 E2E 配置通道（保留目标 `__anet_delegation_config__`，
  中继只见路由词）拉取令牌有效词表并改为选择性路由；签发端改规则后委托方重连即刷新。
- `admin_scope`：可空，默认 `''`（纯数据面）。`ro` / `rules` / `full` = 授权管理本端点：
  引导票据经同一 E2E 配置通道下发（**要求引用组含 `e2e_required` 组**），委托方桌面端
  经保留目标 `__anet_delegation_admin__` 桥接本端点管理控制台；`full` 档额外获得本端点
  已发现上游的报价，可穿透管理（blob 目标 `upstream:<节点名>`）。链接携带 `eadmin=1`
  能力提示。
- `expires_at`：可空，默认永不过期（RFC3339 任意偏移或 `YYYY-MM-DDTHH:MM`，一律按 UTC
  规范化存储；早于当前时间判 400）。
- `my_name`：可空，≤64 字符（M3-T6）：建议的消费者自声明名称，预填进生成链接的
  `myname` 词（仅随链接传递，不落库）。
- `max_uses`：可空，默认不限（正整数；按数据面打开次数计，签发端内存计数、缓存刷新时落库）。

### 响应 201

在 GET 的单项结构基础上追加：

```json
{
  "code": 0,
  "data": {
    "id": "uuid",
    "token": "psk_<48 chars>",
    "share_url": "anet://connect?server=relay-b.example.com&port=54430&account=d%3Aalice&password=psk_...&fp=aa11&en=en_ab12cd34ef56&entry=relay-b.example.com%3A54430%2Crelay-c.example.com%3A54430&entryfp=aa11%2Cbb22",
    "token_prefix": "psk_xxxx",
    "label": "alice 的笔记本"
  }
}
```

`share_url` 形态（`anet://connect`）：`server/fp` = 主入口地址与证书指纹钉值；
`entry/entryfp` = 入口集合全量地址与逐入口指纹（relay 模式 = 容灾集合主入口在前；
direct 模式 = 本端点端点候选）；`en` = entrust 词（E2E 令牌必有，零泄露路由）；
`emode=split` 仅分流档携带；`eadmin=1` 仅管理档携带。审计事件 `delegation.issue`。

### 错误

- `40001`：参数校验失败（label 空/超长、组或 connector 不存在、无组、relay 模式容灾集合
  为空或主入口非恰好一个、entry_mode/concurrency/mode/admin_scope 非法、分流/管理档无
  E2E 组、过期时间早于当前、用量上限非正整数）。

---

## DELETE `/api/v1/admin/delegation/tokens/{id}`

吊销：本地删除 + 向容灾集合内**每个在线上游**发吊销帧（离线上游随断线天然失效；
direct 入口清除本地注册并踢出活动会话）。审计事件 `delegation.revoke`。

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
| `delegation.issue` | 签发端 | 签发（label/组数/集合大小/入口模式；不记明文） |
| `delegation.revoke` | 签发端 | 吊销 |
| `delegation.register` | 中继端 | 扇出会话注册委托令牌（issuer + label） |
| `delegation.revoke` | 中继端 | 注册被吊销/失效 |

审计严禁记录令牌明文、blob、E2E 明文与真实目标；E2E 会话仅路由词可记。
