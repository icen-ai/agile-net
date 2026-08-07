# Devices / Sessions / Approvals API

节点信任与身份体系（node.md M2/M3/M5）管理端接口，全部 AdminAuth。

- **设备注册表**：每台握手验签通过的设备一行（`device_fp` = 设备公钥哈希），人工认证绑定逻辑持有者（subject），状态机 `pending → certified / revoked`（终态）。
- **会话清单**：listener 上全部活会话的逐设备/逐会话行（三页签「监听 | 连接 | 签发」展开数据源）。
- **审批中心**：人眼裁决事件统一收口（类型可插拔），附言 appeal ≤3 / notice 单发。

---

## GET `/api/v1/admin/sessions`

活会话清单。

### 响应 200

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "session_id": "sess_0abc…",
        "session_key": "delegated:<token_hash>:<node_id> 或 node_id",
        "kind": "consumer | fanin",
        "node_id": "（fanin 行）对端 node_id",
        "display": "（fanin 行）令牌备注显示名",
        "device_fp": "sha256(pubkey) hex",
        "my_name": "对端自声明名",
        "ip": "203.0.113.24",
        "connected_at": 720,
        "bytes_up": 1048576,
        "bytes_down": 18874368,
        "channels": 3,
        "token_hash": "（consumer 行）",
        "token_label": "前端团队-专线",
        "entry": "direct | relay"
      }
    ]
  }
}
```

`connected_at` 为在线秒数；流量为当前会话累计（前端差值算实时速率）。

## POST `/api/v1/admin/sessions/kick`

踢单会话（先送达 SessionNotice `kicked` + 可选一次性附言）。

请求：`{ "session_key": "...", "message": "可选" }`

## POST `/api/v1/admin/sessions/kick_token`

踢某委托令牌的全部消费会话（工具栏「全部下线」）。

请求：`{ "token_hash": "...", "message": "可选" }`

## POST `/api/v1/admin/sessions/kick_fanin`

踢某扇入令牌的在线节点会话（监听页「全部下线」；该端点重连即视新会话）。

请求：`{ "token_hash": "...", "message": "可选" }`

---

## GET `/api/v1/admin/devices?state=&q=`

设备列表。`state` ∈ pending / certified / revoked；`q` 搜指纹/持有者/自声明名/备注。
行含 `online`、`sessions`（活会话数）、累计 `bytes_up/bytes_down`。

## GET `/api/v1/admin/devices/:fp`

设备详情：注册表行 + `openssh`（OpenSSH 格式公钥）+ 活会话数组。

## POST `/api/v1/admin/devices/:fp/certify`

认证到逻辑持有者（加绑 = 同 subject 多设备）。请求 `{ "subject": "小明", "remark": "前端 MacBook" }`。
自动结清该设备的 pending 认证审批项。

## POST `/api/v1/admin/devices/:fp/revoke`

吊销（终态）：活会话按 `device_revoked` 踢断，附言随通知一次性送达。请求 `{ "message": "可选" }`。

## POST `/api/v1/admin/devices/rebind`

换机一键三连：认证新设备（继承持有者/备注/累计流量）+ 吊销旧 + 旧机按 `device_replaced` 踢断。
请求 `{ "old_fp": "...", "new_fp": "...", "message": "可选" }`。

## GET / PUT `/api/v1/admin/devices/policy`

未认证设备数据面策略：`{ "policy": "block" }`（默认，拒开等审批）| `"allow"`（放行插灰旗）。

## GET `/api/v1/admin/devices/:fp/traffic?range=24h|7d|30d`

设备流量时序（device_session 台账聚合）：`{ series: [{ts, up, down}], bucket_secs }`（24h=5min / 7d=1h / 30d=1d）。

## GET `/api/v1/admin/devices/:fp/activity`

7×24 活跃热力（近 30 天）：`{ cells: [{weekday, hours:[{sessions, bytes}×24]} ×7] }`，weekday 0=周日。

## GET `/api/v1/admin/devices/:fp/sessions`

历史会话（≤200 条，新→旧）：entry/ip/起止/bytes/close_reason（被踢会话可见 `kicked` 等原因码）。

---

## GET `/api/v1/admin/approvals?state=`

审批列表（默认全部，pending 在前），`messages` 内联（appeal=申请人附言 / notice=操作告知）。

## POST `/api/v1/admin/approvals/:id/decide

裁决：`{ "action": "approve" | "reject" | "reject_revoke", "subject"?, "remark"?, "notice"? }`

- approve（device_certify）：认证设备（可改 subject/remark）；（device_rebind）：执行换绑。
- reject：拒绝（附 notice 一次性告知），pending 会话按 `kicked` 踢断。
- reject_revoke：拒绝并吊销（终态），会话按 `device_revoked` 踢断。

全部动作落审计。WS 事件：新审批 `approval.new`；吊销设备再来连 `auth.rejected`。
