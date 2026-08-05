# 前端业务逻辑审查 · 问题清单（GUI 桌面端 + 管理端）

> 审查时点：2026-08-05 · 针对 `apps/desktop/ui/*.js`（app.js / app-core.js / app-views.js / app-subscription.js / app-hero.js / app-logs.js / app-settings.js）与部分命令层（Rust）
> 性质：业务逻辑缺陷清单，非代码风格审查。按「置信度 × 影响」排序。
> 状态：部分已修复——逐条核实与修复结果见文末「§8 修复状态（2026-08-05 批次）」。

---

## 0. 总览

| 严重度 | 数量 | 说明 |
|--------|------|------|
| 🔴 高（真实 bug） | 3 | 事件拦截漏、空态误判、状态缓存不同步 |
| 🟠 中（竞态/误导） | 3 | 速率序列尖峰、双写同一 DOM、远程面裸 confirm |
| 🟡 低（一致性） | 3 | 预置进 combo 悬空、重复空态判定、冗余轮询拉取 |

---

## 1. 🔴 高 — 真实 bug

### 1.1 dashboard 卡片点击跳转的拦截不覆盖 label 文本

**位置**：`apps/desktop/ui/app.js:249`

```js
$('dash-grid').addEventListener('click', (e) => {
  if (e.target.closest('.switch, button, input, select, a, .group-tabs')) return;
  const card = e.target.closest('[data-goto]');
  if (card) switchView(card.dataset.goto);
});
```

**问题**：`.switch` 是自定义开关容器，`change` 事件在原生 `<input type=checkbox>` 上冒泡。点开关滑块 → `closest('.switch')` 命中 → return（正确）；但**点 label 文本**（`.switch` 内、不含 `input` 的部分）→ 不命中拦截 → 触发 `switchView` 跳页。同卡片内点开关文字却跳到别的视图，行为不一致。

**建议**：把 `closest('input')` 扩为 `closest('.switch, input, button, ...)` 已含 input，真正缺的是对「开关 label 的点击」也应放行——拦截 `e.target.closest('.switch label, .switch span')` 或统一由 `change` 事件决定（点 label 走原生 toggle 即 `change`，不触发跳转）。

### 1.2 空状态把「已保存但未连接」的扇入也判成非空

**位置**：`apps/desktop/ui/app-views.js:5-11`

```js
function updateOnboarding(nodes) {
  const empty = (!nodes || nodes.length === 0) && !(window._credsRaw || []).length;
  $('onboarding').style.display = empty ? 'block' : 'none';
  const dg = $('dash-grid');
  if (dg) dg.style.display = empty ? 'none' : '';
}
```

**问题**：有 2 个已保存扇入但都没连接 → `_credsRaw.length=2` → `empty=false` → 不显示引导；dashboard 卡片网格显示但全空（无连接、无流量），中间态 UI 空洞。正确语义应是「无任何连接 **且** 无任何已保存扇入」才显示空态引导。

### 1.3 `_rolesCache` 状态缓存只在变更点手动维护，悬浮球切模式后不同步

**位置**：`apps/desktop/ui/app-core.js`（`window._rolesCache`）、`apps/desktop/ui/app-hero.js:106-114`（`Hero.renderMode` 读 `r.system_proxy` / `r.tun_mode` / `r.sub_mode`）

**问题**：`initRoles` 一次性缓存 `get_role_settings`；此后仅 `app-settings.js` 在 `set_system_proxy`、`sub-mode`、`set_sysproxy_lock` 等变更点手动回写 `_rolesCache.xxx`。但 **`proxy_mode_set`（悬浮球菜单切 system/local/TUN 模式）** 走的是 `set_tun_mode` / `set_system_proxy`，其中 `set_tun_mode` 成功路径不更新 `_rolesCache.tun_mode`（只有 `applyTunStatus` 在轮询时回写，切完立刻读可能滞后），且悬浮球切「local/system」模式没有回写点 → 首页模式文案滞后。

**建议**：把「角色/模式」的缓存回写收敛到一处（如命令返回后统一 `window._rolesCache = { ...window._rolesCache, ...changed }`），或改为 `get_role_settings` 在轮询中低频刷新。

---

## 2. 🟠 中 — 竞态 / 数据误导

### 2.1 `SubTraffic` 内核重启归零时总序列出现巨大尖峰

**位置**：`apps/desktop/ui/app-subscription.js:113-125`

```js
const total = t.up_total + t.down_total;
if (this._last !== null) {
  let delta = total - this._last;
  if (delta < 0) delta = total;   // 重启归零 → 新总量当一帧 delta
  this.series.push(delta);
  ...
}
```

**问题**：`delta < 0` 时把「重启后的新总量」当作一帧增量塞进 90 点序列，sparkline 出现与真实流量无关的巨大尖峰，误导用户以为刚重启就跑了大量流量。方向速率 `dUp/dDown` 已用 `Math.max(0, …)` 钳到 0（正确），总序列却走了不同逻辑。

**建议**：`delta < 0` 时不应 push（跳过该帧）或 push 0；与方向速率的语义对齐。

### 2.2 `refreshSubs` 与 `refreshGroups` 竞态写同一 `#proxy-sub-desc`

**位置**：`apps/desktop/ui/app-subscription.js:43-45`（`refreshSubs` 写 `proxy-sub-desc`）、`:242`（`refreshGroups` 在 `PROXY_CACHED` 时也写）

**问题**：同一 10s 轮询周期内两个函数都可能写 `proxy-sub-desc`；内核未运行但代理缓存存在时，`refreshGroups` 会把正常态描述覆盖成「cached 态描述」，时序不定。两个数据源写同一个 DOM 无归属约定。

### 2.3 Web 远程面导出凭据用原生 `window.confirm` 裸提示明文

**位置**：`apps/desktop/ui/app-views.js:937-939`

```js
if (HTTP_MODE && !window.confirm(AgI18n.t('views.export-confirm'))) return;
```

**问题**：远程 iframe 面板用原生 confirm，样式不一致；且部分嵌入式 WebView 中 `window.confirm` 恒返回 true，等于**裸漏明文凭据**而无确认。导出内容含明文密码（`views.export-confirm` 文案本身也声明了）。

**建议**：HTTP_MODE 下复用现有模态（如 anet 导入的 confirm 模态）或至少二次输入；禁止依赖原生 confirm 返回值。

---

## 3. 🟡 低 — 一致性 / 欠考虑

### 3.1 预置放行规则可被 combo 引用后删除，成员悬空无提示

**位置**：`apps/desktop/src/custom_rules.rs`（`remove` 级联清 combo 成员）+ `apps/desktop/ui/app-views.js`（`allRuleChoices` 不排除预置）

**问题**：预置规则（`managed=false`、`id=preset-*`）与用户规则一样可被塞进 combo；删掉预置后 combo 成员变「失效引用」，`effective_rules` 静默忽略，UI 无提示。行为可用但缺用户反馈。

### 3.2 空态判定双份逻辑 + 重复触发

**位置**：`apps/desktop/ui/app-views.js:5-11`（`updateOnboarding`）、`:866`（`refreshCreds` 尾部再次调用）

**问题**：`refreshNodes` 尾部调 `updateOnboarding`，`refreshCreds` 又调一次；且 `refreshCreds` 每次轮询都无条件 `renderCredList` 重绘 `creds-list`（无 sig 守卫）——每个 10s 周期比其它列表多一次全量 DOM 重建。

### 3.3 一次 10s 轮询周期内 `server_status` 被拉取 3 次

**位置**：`apps/desktop/ui/app-views.js`（`refreshAdminEntry`）、`app-views.js`（`renderDashFanout`）、`app-settings.js`（`refreshServerPanel`），均调用 `invoke('server_status')`；`mainTick10s` 同时触发三者

**问题**：`refreshNodes → refreshAdminEntry → server_status`、`renderDashFanout → server_status + list_server_connectors`、`refreshServerPanel → server_status` 在同一轮询周期内重复拉取同一数据源。可合并为一次拉取后分发，影响小但浪费。

---

## 4. 后续建议（不在本轮修复范围）

- 前端「签名变更检测 + 全量重绘」约定总体健康，问题集中在**状态多源写同一 DOM**与**空态/拦截边界条件**。
- 修复顺序建议：1.1 → 1.2 → 2.1 → 2.3（直观 bug 优先），再处理 1.3 / 2.2 / 3.x。

---

## 5. 连接状态刷新问题（桌面端 + 管理端）

> 追加时点：2026-08-05 · 现象：①连接后先显示「未连接」，过几秒才正确；②被扇入/扇出断开后仍显示「正常」几秒，且流量统计不对。

### 5.1 委托（delegated）连接首连状态滞后

**位置**：`crates/client/src/client.rs:845-851`（`list_nodes` delegated 分支）、`connect_delegated`（`:724-801`）、`spawn_delegated_supervisor`（`:1565-1630`）

**根因**：委托连接 `connect_delegated` 首连同步成功后，`NodeState.status` 初始为 `Connected`（`:757`），但 **`opener.current`（`DelegatedOpener` 的当前隧道槽）在 `connect_delegated_entry` 返回后才 store**；而 `list_nodes` 的 delegated 状态修正走 `d.is_connected()` → 读 `opener.current`（`client.rs:845-851`）。首连成功瞬间 `opener.current=None` → 状态回退 `r.state.status.clone()`（仍是 Connecting）→ 前端显示「未连接」。**要等 supervisor 循环 500ms 后 `set_delegated_status(Connected)` 才纠正** → 「过几秒才显示已连接」。

**建议**：`connect_delegated` 首连成功后同步 `set_delegated_status(&inner, &node_id, Connected, Some(&entries[0]))`，消除首连与 supervisor 之间 ~500ms 的状态空窗。

### 5.2 断开后 UI 延迟 + 流量统计误导

**位置**：`apps/desktop/ui/app-views.js:49-55`（`refreshNodes` 签名对比）、`:826-837`（`trackFaninTraffic` delta）、`crates/client/src/client.rs:804-823`（`disconnect`）

**根因**：
1. 远程断开 → `tunnel` state 先变 `Reconnecting`（`client_tunnel.rs:287`）→ `run()` 自动重连。断开瞬间 `refreshNodes` 拿到的 `list_nodes` 数据里 status 仍是 Connected（500ms 轮询粒度内），**前端 10s 轮询 + 签名对比**：若本次轮询 `bytes_up/down` 未变且 status 未变 → 签名等于上一轮 → 不重绘 → 旧 DOM 显示「已连接」几秒。
2. `disconnect_node` 后前端只 `refreshNodes(true)` + `refreshCreds()`（`app-views.js:545-553`），但 `refreshCreds` 的 `renderCredList` 读 `_nodeStatus`（`refreshNodes` 构建的旧缓存）——节点移除后 `_nodeStatus[key]=undefined`，**渲染走「已断开」分支是对的**，但列表重绘只在 `refreshNodes` 的签名变化分支里触发，存在跳过窗口。
3. 流量统计：`trackFaninTraffic` 的 `delta = total - _last; if (delta < 0) delta = total`——断开/重连归零时把「新总量」当一帧 delta 塞进序列 → 图表尖峰/下坠（与 `app-subscription.js` `SubTraffic` 同 bug，见 2.1）。

**建议**：
- `disconnect` / `disconnect_all` 后**主动触发一次前端刷新**（`disconnect_node` 已 `refreshNodes(true)`，但应连带 `refreshCreds()` 之后立即重绘，或用事件广播）。
- 统一 `delta < 0` 语义：跳过该帧（`trackFaninTraffic` 与 `SubTraffic` 一致），断开即停不产生尖峰。
- `tunnel.run()` 的 500ms 轮询粒度已够，但 `list_nodes` 对「断开瞬间」的判定建议以 `tunnel.state() != Connected` 为准（Reconnecting 也视为未连接），避免断开瞬间误报 Connected。

### 5.3 管理端 fan-in 状态刷新（`crates/node/ui/app.js`）

**位置**：`crates/node/ui/app.js:1130-1162`（`loadFaninStatus`）、`:1178-1192`（`renderFaninPeers`）

**现状**：`loadFaninStatus` 10s 轮询，`renderFaninPeers` 每次调用都 `innerHTML` 全量重绘（**无签名对比**）；`FED_OFFERS`（可授权池）随 `loadFaninStatus` 一并拉取。扇入断开时：`L.peers` 由服务端 `roles.listener` 返回的在线集合决定，peer 断开 → 下次轮询 `peers` 不再包含该节点 → 表格消失（正确，但 10s 窗口内显示旧的）。管理端无「未连接」中间态，断开直接消失而非显示「已断开」。

---

## 6. advertise（路由宣告）可见性缺失 → 委托签发无法确认「有还是没有」

> 追加时点：2026-08-05 · 现象：C（内网）扇出到 B（公网），C 签发分流/专线委托时报「主入口扇出没有任何可路由项」类错误；B 和 C 两端都**找不到任何界面能确认 advertise 是否存在**，委托能否签发只能靠试。

### 6.1 根因：advertise 只在握手时单向流动，任何 UI 都不展示它

**位置**：
- `crates/node/src/service/connectors.rs:684-705`（`effective_advertise_of` = 手工 advertise ∪ push 组规则）
- `crates/core/src/relay/connector.rs:311-320`（`effective_advertise` = 静态 advertise ∪ push 组规则 ∪ 客户端隧道规则）
- `crates/core/src/relay/listener.rs:776-795`（`serve_node_session` → `set_peer_routes` → `peer_advertise` 表）
- `crates/node/src/api/handlers/federation.rs:26-64`（`offered` 接口其实返回了 `advertise`，但 UI 没渲染）

**问题**：advertise 是扇出方（C）在握手 `AuthRequest.advertise` 上送给上游（B）的字段，进了 B 的 `peer_advertise` 路由表后，**没有任何一个界面把它展示出来**：
- **C 侧**：桌面端「扇出」卡片只显示 `upstream_addr · token · SNI`（`app-views.js:1005-1011`），`list_server_connectors` 虽返回 advertise 字段但 UI 不渲染；「扇出」编辑弹窗能填 advertise / 勾 push 组，但保存后回看无有效值展示。
- **B 侧**：管理端「扇入」页 `renderFaninPeers`（`crates/node/ui/app.js:1184-1189`）只显示 `node_id · up · down · pool`，不渲染 advertise 列；且 `hasPool = !!(o && (advertise.length || groups.length))` —— **advertise 和 groups 全空时连「可授权池」入口按钮都不显示**，更无从确认。
- **委托签发弹窗**：勾 E2E 组后 hint 自动派生失败时，`delegation.rs:140-146` 只笼统报「路由宣告与上送组规则均为空」，**不披露主入口当前 `effective_advertise` 的实际值**（到底是手工 advertise 空、还是 push 组空、还是组里没规则），无法定位是配置缺项还是组没绑规则。

### 6.2 自查手段（修复前可用）

- **C 侧**（查主入口扇出是否真的可路由）：
  ```bash
  sqlite3 ~/.agile-net/gui/embedded-node/node.db "SELECT name, advertise, push_groups FROM connector;"
  ```
  `advertise` 列有值，或 `push_groups` 引用了含规则的组 → 可派生 hint；两者都空 → 必报错。
- **B 侧**（看 C 到底宣告了什么）：
  ```
  GET /api/v1/admin/federation/offered
  ```
  看 `items[]` 里对应 C 的 `node_id` 的 `advertise` 数组；为空即 C 未宣告任何路由，B 路由表也没有 C 的任何项。

### 6.3 建议修复

1. **管理端扇入页**：给 `renderFaninPeers` 加 advertise 列（`poolDetailHtml` 已有 adv badge 渲染，只差表格列），peer 全空时也要显示「无宣告」而非无入口。
2. **桌面端扇出页**：卡片/详情显示 advertise 有效值（含 push 组并入后的结果）。
3. **委托签发报错改进**：`delegation.rs:140-146` 失败分支改为列出「主入口 `advertise=[]`、`push_groups=[]`（含组规则数）」实际值，直接指出缺哪一项。
4. **（可选）E2E 组规则并入 advertise**：把「本地 E2E 组规则」并进 `effective_advertise_of`，勾 E2E 组即自动送路由，减少手工 advertise 的维护摩擦（见下节）。

---

## 7. 延伸讨论：AC 通讯模型（C 只宣告组名、B 纯哑管道）——仅讨论，未实现

> 承接 6.4 · 用户提出：C 宣告一个 E2E 权限组（如含 10 条规则），**不把 10 条规则推给 B**，只宣告「组名」作粗粒度路由词；A 访问落入组名 → Open 带组名给 B → B 仅按组名路由到 C → C 解密出真实目标后再用本地规则裁决。B 自始至终不知道组内具体规则 = 「AC 通讯」。

### 7.1 现状为何不成立

- **注册校验**：`listener.rs:973-977` `resolve_peer(&h.hint)` 必须路由回 C —— 依赖 advertise 生成的 CIDR/域名路由表；纯组名不参与路由（`rebuild_routes` 只认 CIDR/suffix/host）。
- **ACL 前置**：`listener.rs:958-960` `wanted` 必须非空（= C 推上来的组 ∩ token 组），完全不推组会直接 `no known groups` 拒注册。
- **外层 ACL**：`listener.rs:1095` 用 `acl_rules`（= 推上来组的 10 条规则并集）逐 Open 裁决；不推规则则 B 无 ACL 可做。
- **hint 绑定**：`listener.rs:1112-1113` 要求 `e2e.hint == target_addr` 且 `hint ∈ stamp.hints` —— hint 当前是字面地址，不是组名。

### 7.2 要让它成立需动 3 处协议层

1. **kid 直连路由**：对 E2E 专用 token，B 按 `kid → issuer` 直接投递，不再依赖 `resolve_peer(hint)`（`listener.rs:973`、`1112` 解除地址绑定）。
2. **放开外层 ACL**：这类零知识 token 跳过 `listener.rs:1095` 的 `acl_rules` 裁决（真实目标封在 E2E blob 内，B 读不到，外层粗栅栏无意义）。
3. **执法收到 C 端点**：每个 E2E Open 必须解密后由 C 本地组二次裁决，未封/封错直接拒。

### 7.3 收益 / 代价（信任 B0 的账本）

- **收益**：B 看不到 10 条规则（只看组名 + hint）；无法基于规则的中间人篡改/选择性放行；被攻破也读不到真实目标。
- **代价**：滥用防护全在 C（恶意消费者借道 C 滥发 Open 由 C 兜底拒绝，出口带宽有限）；B 只能做粗粒度降级（丢包/限速/拒绝转发 = 纯 DoS）；路由与授权从此绑定组名（多策略需多组名/多 hint）。

### 7.4 状态

仅讨论。未立项，未改代码。最小闭环（方案 A：`issue_token` 允许 `hint = 组名` + `register_delegated` 按 kid 映射 issuer + ACL 放行）可作为首个验证原型；完整方案（方案 B：kid 直连路由）待架构评审。


---

## 8. 修复状态（2026-08-05 批次）

> 对 §1–§6 逐条核实，并合入本轮新发现问题的修复。`cargo test --workspace` 391 全绿、clippy 干净。

### 8.1 原清单逐条核实

| 条目 | 结论 | 说明 |
|------|------|------|
| §1.1 dashboard 卡片 label 点击穿透 | 未修（属实，本轮未要求） | 待后续批次 |
| §1.2 空态把已保存未连接判非空 | 未修（属实，本轮未要求） | 待后续批次 |
| §1.3 `_rolesCache` 悬浮球切模式不同步 | 未修（属实，本轮未要求） | 待后续批次 |
| §2.1 `SubTraffic` delta<0 尖峰 | **已修** | `delta < 0` 改为 `delta = 0`（跳过该帧），与方向速率 `Math.max(0,…)` 语义对齐；`app-subscription.js` 与 §5.2③ 的 `trackFaninTraffic`（`app-views.js`）同 bug 一并修复，全仓仅此 2 处 |
| §2.2 `proxy-sub-desc` 双写竞态 | 未修（属实，本轮未要求） | 待后续批次 |
| §2.3 Web 远程面裸 `window.confirm` | 未修（属实，本轮未要求） | 全仓仅 `app-views.js` 一处裸 confirm |
| §3.x 低优先级一致性 | 未修 | 待后续批次 |
| §5.1 委托首连状态滞后 | **核实不成立** | `opener.current` 在 `connect_delegated_entry` 返回前已同步 store（`client.rs:746`），`NodeState` 初始即 `Connected`（`:757`）；supervisor 不纠正首连、GUI `connectWith` 强制刷新。首连无空窗，原分析系误读 |
| §5.2 断开后 UI 延迟 + 流量误导 | 部分已修 | ③流量尖峰已修（见 §2.1）；①②刷新窗口问题本轮未动 |
| §5.3 管理端 fan-in 刷新 | **已修** | `loadFaninStatus`：`federation/offered` 拉取移到 L 签名早退之前，独立 `psig` 签名，`poolChanged` 时同样重绘——可授权池变化不再被早退吞掉 |
| §6.1 advertise 可见性 | **已修** | 管理端扇入页新增「宣告路由」列（徽标 ≤3 + `+N`，全空显示「无宣告」入口）；桌面端扇出卡片显示有效广告路由（`effective_advertise`，`ServerConnectorView` 新字段）；签发报错列出主入口 advertise 实际值与各上送组规则数（`delegation.rs`） |

### 8.2 本轮新发现并已修复

1. **委托链接丢失 `emode=split`（用户实测）**：分享卡片 `shareCardBind.currentLink()` 每次 render 重建链接时未带 `emode`/`eadmin`（`crates/node/ui/app.js`）；`crates/client/src/connect_url.rs` `connect_url_of` 委托凭据同样丢全部委托参数，改走 `build_delegate_url`（entries/entry_fps/ehint/emode/eadmin 全保留）。两处修复后分流档链接消费端正确出现 E2E 权限组规则。
2. **分流档静默降级无感知**：split 档已连接但规则仍含 `0.0.0.0/0` 全量兜底时，桌面端委托凭据卡片显示 b-warn「分流未生效」徽标（`app-views.js` renderCredList）。
3. **桌面端弹窗小窗溢出 + 开关拉满宽**（截图问题）：`.modal` 加 `max-height: calc(100vh - 48px); overflow-y: auto`；`.modal input{width:100%}` 改为 `input:not([type=checkbox]):not([type=radio])`——根因是该规则后于 `input[type=checkbox]{width:32px}` 且特异性同级，把统一开关样式冲掉。管理端 `.modal` 本有 max-height 且无此全局规则，不受影响（泛化排查：两端其余弹窗结构同构，无同类问题）。
4. **扇入/扇出权限组收敛改多选（组集并集）**：`relay_token.group_id` / `connector.group_id` 由单组升级为逗号分隔组集（ACL = 各成员组规则并集；单 id 向后兼容）。
   - `service/acl.rs`：`build_group_router` 逐成员并集（未知成员贡献空 = 逐成员 fail-closed）；`handle(group_id, db)` 首取即时编译（不再等 rebuild 扫到，新建即收敛）。
   - **DB v14 `multi_group_acl`**：重建 relay_token / connector 两表摘掉 `group_id` 的 FOREIGN KEY（pool 全连接 `foreign_keys=ON`，CSV 存不进带 REFERENCES 的列）。
   - DB 层：`group_attachment_count` CSV 感知（逐成员计数），`list_connectors` / `list_relay_tokens` / `get_relay_token` 组名逐成员拼名（`group_name_map`）。
   - API 校验（connectors / relay_tokens POST+PUT / groups 附件展示）与桌面端 `validate_group` 全部 CSV 逐成员校验，E2E 组拒绝挂收敛。
   - 前端：管理端扇入令牌新建/编辑、扇出新建/编辑三处单选 select 改复选列表（E2E 组禁用 + 徽标）；桌面端扇出弹窗同步改复选列表（`GroupOption` 新增 `e2e_required`）。
   - CLI：`--group` 支持逗号分隔多组（`resolve_id_set`），connector update 空值显式解绑。
