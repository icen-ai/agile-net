# 节点信任与身份体系重构 · 实施任务书

> **可执行文档**：本文档由专题讨论稿重排为里程碑 + 任务清单。讨论过程见 git 历史。
> 设计原型：`target/badge-preview/index.html`（静态页，全部场景已对齐）。
>
> 总目标：把"来源硬塞进名字"的污染式实现，重构为**名字干净 + 来源/认证独立成徽章 + 设备身份可验 + 节点全生命周期可观测**的形态。

---

## 0. 已拍板决策快照（执行不得回翻重议）

1. **命名主权**：组名永远干净（源组名），来源独立成徽章；`group` 唯一约束改 `(name, adopted_node)` 联合唯一
2. **认证标**：Lucide `badge-check` 为唯一节点认证标（satellite 方案废弃）；tooltip 分 `pin`/`tls` 两档，`insecure` 不显示
3. **设备身份**：每安装自生成 ed25519 密钥对（`ring` 自研，**严禁依赖 OpenSSH/ssh-keygen/gpg**，平台矩阵 Android/iOS/macOS/Windows/Linux）；私钥进平台安全存储（keyring 优先、0600 兜底）；`node_id` = 设备公钥哈希派生（自证 ID）；握手 Ctrl 帧挑战验签。**禁止退化为"本地 UUID 自报"**（指纹会被 UI/日志/截图展示，可见即可冒名）
4. **人工认证制**：设备默认待认证、不显示徽章；管理员在「连接 | 签发」表格手动认证 + 填备注才出 `badge-check + 备注名` 胶囊；状态机 `待认证 → 已认证 / 已吊销（终态，永不复用）`；换机 = 一键"认证新 + 迁移备注 + 吊销旧"
5. **hover 身份卡**：胶囊 hover 弹居中卡片（社交软件式）：标题（认证备注）/ 节点名称（对方「我的名称」）/ 指纹 / 设备公钥（OpenSSH 格式可复制）/ 认证信息 / 情况（按扇入/扇出/签发上下文变化）
6. **传递认证**：双向 opt-in（connector/listener 各一开关）；认证记录**起源节点 relay 证书私钥签名、中间跳盲转**；每端「认证信任名单」显式控制（默认 = 直连互信对等同一跳）；本地认证优先、本地可独立吊销、吊销带签名传播；名单外来源降级「参考认证」一键采纳
7. **拓扑可见性三档**：`domain`（默认，跨域只见域主体 + 可选聚合计数）/ `disclose`（拓扑可知，逐持有者签名回执、只披露不执法）/ `approve`（拓扑审批，再分享进待决队列）。原则：**持有即建交、传输即隐身、可见性边界 = 行政域边界、责任与可见性匹配、控制不依赖枚举**；非 anet 转发（frp 等）原理性不可见，归因到直接持有人为止，用量异常旗只作线索不作定罪
8. **审批中心**：全部人眼裁决事件统一收口，类型可插拔；申请人附言 ≤3 条（pending 会话 Ctrl 上行）；动作 = 批准（可改备注）/ 拒绝 / 拒绝并吊销，全审计
9. **客户端感知**：标题栏通知 icon + 角标 + 侧栏「通知」菜单；吊销/踢下线/拒绝审批可随附**一次性告知**（一次一条、随操作定稿不可追改）；**双通道送达**（在线随帧推送 + 离线握手拒绝响应带回）；标准 `reason_code` 兜底
10. **双向命名三字段**：一切关系实体表单统一「目标名称（本地）| 我的名称（上送对端）| 备注（本地私密）」；链接加 `myname` 词；三字段组沉淀共享表单组件，**严禁各表单自造命名字段**
11. **设备级流量 B 口径**：实时速率（采样/差值）+ 历史累计；新表 `device_session` 会话断开 flush（时序/历史/热力三吃），`node_traffic_log` 保持节点级
12. **全局约束**：pre-launch 直改 DB 基线（无迁移链）；数据面零冲击（group.id 路由 / ACL / E2E 不动）；无 SSH 式手工换钥匙流程；多设备自服务认证走 `__anet_delegation_admin__` 桥接

---

## 0+. 实施期裁决补充（2026-08，与 §0 同级效力）

1. **node_id 拆两层**：`device_fp` = ed25519 公钥哈希（握手验签的可验证身份，认证/徽章/画像/统计主键）；`node_id` 保留自声明语义，只做路由/命名空间键（`Outbound::Tunnel`、上送组血缘、`#connector` 后缀不受影响）。认证实体 = 设备绑定**逻辑持有者**：支持**换绑**（认证新设备 + 迁移备注与累计统计 + 吊销旧）与**加绑**（多设备挂同一持有者、统计聚合）——换机/多机数据不丢。
2. **挑战验签零 RTT**：不单独下发 nonce——设备签名挑战从 TLS exporter secret（RFC 5705，rustls 支持）派生，天然防重放且绑定 TLS 会话。
3. **私钥存储**：不进 OS keyring（不污染用户环境）；存产品数据目录 0600 文件，整机一份、客户端/服务端双角色共用。M2 先做桌面 + 文件；Android Keystore wrap / iOS Keychain 为后续小任务。
4. **M6 帧面**：M2 只预留 Ctrl 帧类型码位 + reason_code 表；联邦消息 schema 到 M6 再定（pre-launch 协议可随时改，不盲画）。
5. **M1-T1 谓词修正**（已落地）：`adopted_node` 是 `''` 非 NULL——部分索引为 `UNIQUE(name) WHERE adopted_node=''` + `UNIQUE(name, adopted_node) WHERE adopted_node!=''`；采纳组 INSERT 时即带血缘（`create_adopted_group`），杜绝两步写撞本地唯一索引。
6. **流量/性能红线**：实现中发现浪费公网流量/服务器性能/网络 IO 的设计（空转轮询、全量同步、过密心跳、重复往返）必须顺手修正；新增任何周期任务先过一遍「空转成本」。
7. **UX 主动补全授权**：文档未覆盖但提升数据安全或操作便捷性的前端/端点，允许并鼓励主动添加。
8. **工程方式**：子 Agent 解禁（用户授权）；破坏性改造无需任何兼容层。

---

## 1. 里程碑总览

| 里程碑 | 内容 | 依赖 | 风险 |
| --- | --- | --- | --- |
| **M1** 显示层重构 | 命名主权 + badge-check 认证标 | 无 | 低（不动协议/数据面） |
| **M2** 设备身份层 + 协议面一次成型 | 设备密钥、握手验签、全部帧/链接字段、DB 新表 | 无 | 中（协议面，需一次定义完） |
| **M3** 管理端裁决面 | 三页签会话管理、人工认证、审批中心、设备画像 | M2 | 中 |
| **M4** 客户端感知面 | 通知中心、吊销告知、审批中状态、本机身份卡 | M2（帧字段） | 中 |
| **M5** 设备级流量 B 口径 | 流量细化设备维度 + 双值渲染 | M2（device_fp 主键） | 低 |
| **M6** 联邦增强 | 传递认证、拓扑可见性三档 | M2 + M3 | 高（联邦通道，按需启动） |

执行顺序：**M1 → M2 → M3 / M4 并行 → M5 → M6**。M3 与 M4 共享 M2 的协议面，可同时展开。

---

## M1 显示层重构（命名主权 + 认证标）

### 任务清单

- [ ] **M1-T1 DB 基线**：`group` 表 `UNIQUE(name)` 改为**两个部分唯一索引**——`UNIQUE(name) WHERE adopted_node IS NULL` + `UNIQUE(name, adopted_node) WHERE adopted_node IS NOT NULL`
  - ⚠️ SQLite 的 UNIQUE 视 NULL 为互不相等，单一 `UNIQUE(name, adopted_node)` 会放过多条本机同名组，必须用部分索引（改动：`crates/node/src/db/migrations.rs` 基线）
- [ ] **M1-T2** `service::federation::adopt_name` 删 `@node` 拼接，直接用源 `name`；联邦握手 `PushedGroupMsg.name` 传纯组名（顺带治掉后缀叠加 bug）
- [ ] **M1-T3** `apps/desktop/ui/icons.js` 新增 `badge-check`；沉淀共享渲染 helper `srcBadge(node, title)` / `nodeBadge(node, auth)`（联邦蓝 `--info` / 成功绿 `--ok`，tooltip 分 `pin`/`tls`）
- [ ] **M1-T4** 全部组选择器/列表接入 `srcBadge`（管理端签发页、桌面端列表）；桌面 `list_embedded_groups` 补 `adopted_node` 字段
- [ ] **M1-T5** 扇出连接表对端节点列接入 `nodeBadge`（认证状态取自 TLS 校验结果：`pinned_fingerprint` > `pinned_cert` > `ca` > `insecure`）

### 验收标准

- 本机组 `git` + 采纳 peer-c 的 `git` + 采纳 peer-d 的 `git` 三者共存，展示均为纯名 + 来源徽章
- 两处上送同名组不再撞名；采纳组重推不出现 `@` 后缀叠加
- `rtk cargo test --workspace` 全绿；数据面（路由/ACL/委托签发）行为零变化

---

## M2 设备身份层 + 协议面一次成型

> **关键执行原则**：协议面（握手字段、Ctrl 帧、链接词、reason_code）在本里程碑**一次定义完**，M3/M4/M6 只消费不新增，避免多次协议变更。

### 任务清单

- [ ] **M2-T1 core 设备密钥模块**（`crates/core`）：`ring` ed25519 生成/签名/验签；`node_id = sha256(pubkey)` 派生；公钥导出 OpenSSH `authorized_keys` 格式文本（仅展示）
- [ ] **M2-T2 client 私钥存储**（`crates/client/credential.rs`）：首启生成，keyring 优先（Windows 凭据管理器 / macOS 钥匙串 / Android Keystore / iOS Keychain）、0600 文件兜底
- [ ] **M2-T3 握手挑战验签**：listener 在 Ctrl 握手帧下发随机 nonce，设备签名回传；验签失败拒连；`node_id` 与公钥绑定校验（防自报冒名）
- [ ] **M2-T4 协议帧字段（一次成型）**：
  - `AuthRequest` / token_register 加 `my_name`（自声明，不参与认证判断）、设备公钥 + 签名
  - 吊销/关闭/拒绝帧加 `reason_code` + 可选一次性附言（E2E 档随信封加密）
  - 握手拒绝响应支持原因带回（离线告知通道）
  - pending 会话附言上行帧（≤3 条，服务端计数执法）
  - 标准 reason_code 表：`revoked_by_admin` / `device_replaced` / `device_revoked` / `token_expired` / `kicked` / `pending_approval` / …
- [ ] **M2-T5 链接格式**：`core::link` + `aglink.js` 同步加可选 `myname` 词（与 `d:` label 并存：label = 目标名称建议，myname = 我的名称）
- [ ] **M2-T6 DB 基线新表**（详见 §5 汇总，随基线一次建完）：`device_registry` / `approval` / `approval_message`

### 验收标准

- 重装/换机 = 新指纹；同指纹重连验签通过；伪造他人指纹验签失败拒连
- 被吊销设备重连收到 `device_revoked` + 附言；指纹可截图传播无冒名风险
- `rtk cargo test --workspace` 全绿（含新旧指纹、验签失败、reason_code 全路径用例）

---

## M3 管理端裁决面（会话管理 + 人工认证 + 审批 + 设备画像）

### 任务清单

- [ ] **M3-T1 三页签可展开资源行**（监听 | 连接 | 签发）：资源行显示名称/前缀/在线数 `online/cap`/状态徽章/E2E 标；展开为逐设备/逐会话表（设备名+认证标、IP、入口、时长、流量、会话 key、所属令牌）；操作 = 单设备踢下线 + 工具栏全部踢下线
  - API：逐令牌在线会话聚合查询（listener 会话级数据按 `session_key`/token 聚合暴露）；踢下线复用 conlog kill / relay 会话关闭下沉逐会话粒度
- [ ] **M3-T2 人工认证状态机**：设备行认证按钮 + 备注弹窗；换机场景 UI 提示「疑似『X』换机」一键三连（认证新 + 迁移备注 + 吊销旧）；吊销列表命中再来 → 拒连 + 红色告警
  - 认证前数据面策略（签发档位）：默认「未认证拒开等审批」/ 可选「放行插灰旗」
- [ ] **M3-T3 hover 身份卡共享组件**（沉淀 `components.css`，两端复用）：六行结构（标题/节点名称/指纹/公钥可复制/认证信息/情况区按上下文切换）
- [ ] **M3-T4 审批中心**：可插拔事件注册表；首批类型 = 设备认证申请 / 换机审批（locked 签发）/ 参考认证采纳；审批项内联附言展示；动作三件套 + `record_audit_log`；WS `approval.new` + 菜单角标
- [ ] **M3-T5 设备画像页**：列表（在线/离线/待认证/已吊销 + 筛选搜索）+ 详情页（Hero + KPI 条 + ag-tabs 五页签），设计规格见下「设备画像设计规格」
- [ ] **M3-T6 命名三字段服务端表单**：connector / listener / relay token / 签发委托表单接共享三字段组件；签发者「我的名称」预填进生成链接
- [ ] **M3-T7 共享组件与图标批次**：`AgChart.bars`（横向条形图）/ `AgChart.heat`（7×24 热力格）/ `.agkpi`（KPI 卡，首页 dstat 摘要泛化：值+标签+环比箭头）/ `.agtimeline`（垂直时间线）/ `.agcopy`（mono 可复制字段，指纹/公钥/会话 key 通用）；icons.js 新增 `fingerprint` `key-round` `monitor-smartphone` `stamp` `ban` `history` `route` `timer` `calendar-days` `trending-up` `bell` `triangle-alert`

### 设备画像设计规格（M3-T5）

**页面骨架**：Hero 身份卡（徽章+备注名 / 指纹 mono 可复制 / 公钥折叠 OpenSSH 格式 / 认证状态+来源 / 异常旗 / 操作按钮）→ KPI 条（累计↑↓ / 今日 / 在线时长 / 会话数 / 持有令牌 / 最近在线，带环比箭头）→ ag-tabs 五页签（概览 | 流量 | 会话 | 资源 | 事件），页签按需加载 + 页面隐藏停轮询守卫。

- **概览**：实时速率 sparkline（在线活图，1-2s 轮询带可见性守卫）；**7×24 活跃热力图**（画像感核心：一眼区分"朝九晚五的人"与"跑批机器"，同时是 M6 用量异常旗数据源）；异常启发式 chips（并发目标数异常 / 7×24 持续在线 / 流量超个人画像——只插旗不定罪）
- **流量**：时序上下行面积图（24h/7d/30d 切换）；资源组分布横向条形图；B 口径双值
- **会话**：历史会话表（起止/时长/入口 direct·relay/IP/上下行/**关闭原因**——直接消费 M2 `reason_code`，被踢会话在设备视角可见"被管理员断开"）；在线会话置顶可踢
- **资源**：持有令牌卡（label/入口/并发档/生命周期徽标）+ 可达资源组树；**设备视角路由模拟器**（输入 host → 该设备实际命中哪条规则/哪个组，复用 `decide_inbound` 同款逻辑的只读演练）
- **事件**：垂直时间线合并三源（audit_log + approval + device_registry）：认证/审批/换机迁移/吊销/踢下线/备注变更/令牌签发

**API**（全 AdminAuth + `db_call` offload）：

```
GET    /devices                      列表（状态/来源/令牌筛选，paginate.rs 分页）
GET    /devices/{fp}                 身份 + 认证 + KPI 聚合
GET    /devices/{fp}/traffic?range=  时序桶（24h=5min / 7d=1h / 30d=1d）
GET    /devices/{fp}/traffic/groups  资源组分布
GET    /devices/{fp}/sessions        历史会话（游标分页）
GET    /devices/{fp}/resources       持有令牌/可达组/路由档
POST   /devices/{fp}/route-test      路由模拟（host → 命中链，只读）
GET    /devices/{fp}/events          合并时间线
GET    /devices/{fp}/activity        7×24 活跃热力聚合
```

**IA 原则**：**device_fp 全局可路由实体**——三页签设备行、审批项、拓扑图、连接记录中出现的指纹/设备名，全部可点击跳设备画像页。

### 验收标准

- multi 令牌下逐设备可见、可踢；换机全流程（审批 → 迁移 → 吊销旧）跑通
- 审批中心四类操作全审计；附言超 3 条被拒
- 侧栏新增「审批」「设备」菜单（2 字对齐）；轮询签名检测不因徽章/角标频闪

---

## M4 客户端感知面（通知 + 告知 + 身份卡）

### 任务清单

- [ ] **M4-T1 通知中心**：标题栏通知 icon + 未读角标（anet-gui 主窗 / 客户端 SPA 一致）+ 侧栏「通知」菜单；本地持久收件箱；点击跳上下文
- [ ] **M4-T2 吊销告知渲染**：有附言显示管理员原话 + reason_code；无附言显示标准原因码文案；离线重连握手拒绝带回的消费
- [ ] **M4-T3 审批中状态**：pending 显示「等待 C 审批」（停止无限重连转圈，低频保活探测）；附言输入入口（≤3 条，本地计数提示）
- [ ] **M4-T4 本机身份卡**：查看/复制本机指纹 + 公钥（OpenSSH 格式）；我的认证状态/签发者备注名回显
- [ ] **M4-T5 条款明示**：导入带 `visibility=disclose/approve` 条款链接时弹条款卡确认
- [ ] **M4-T6 命名三字段客户端表单**：凭据表单三字段（目标名称 = 链接建议值可改）；导入向导提示填「我的名称」

### 验收标准

- 被吊销设备（在线/离线两种）均收到告知；审批全程状态可见、可附言
- 导入含 myname/visibility 条款链接全流程正确解析渲染
- 三字段表单与 M3 服务端同一共享组件实现

---

## M5 设备级流量 B 口径

### 任务清单

- [ ] **M5-T1 DB 基线**：新表 `device_session`（会话断开 flush 一行：device_fp, token, entry, ip, start, end, bytes_in/out, close_reason）——流量时序/会话历史/活跃热力**一张表三吃**；`node_traffic_log` 保持节点级 rollup 不动
- [ ] **M5-T2 断开 flush hook**：会话断开把 `MuxSession.bytes_in/out` + 会话元信息落盘 `device_session`（close_reason 取自 M2 reason_code）
- [ ] **M5-T3 会话级实时速率**：dstat 采样管线下沉会话级（1-2s 增量 EWMA）或 WS 推累计值前端算差值
- [ ] **M5-T4 前端双值渲染**：会话行/设备页流量列「实时速率 + 累计」双值；设备画像流量区图表（agchart）

### 验收标准

- "这个设备这周用了多少"随时可查；断开重连累计不丢；实时速率与 dashboard 节点级口径一致

---

## M6 联邦增强（传递认证 + 拓扑可见性）

### 任务清单

- [ ] **M6-T1 认证传播消息**（联邦 Ctrl 通道，push_groups 同机制）：记录带起源节点 relay 证书签名；中间跳盲转 + 哈希去重；认证/吊销事件增量推送 + 新会话全量同步
- [ ] **M6-T2 传递认证开关与名单**：connector/listener 各加「传递认证」开关（默认关，双向 opt-in 生效）；节点级「认证信任名单」配置；名单外 → 参考认证档（灰标 + 一键采纳）；本地优先 + 本地独立吊销 + 吊销传播；hover 卡加「认证来源：X·节点名（经 Y 转发）」行
- [ ] **M6-T3 visibility 三档**：`delegated_token` / 组上送 / 认证传播共用 `visibility=domain|disclose|approve` 字段；`grant_receipt` 表 + 回执分级（域主体聚合计数 / 逐持有者全图 / 逐持有者 + 待审批）；回执抗扣压（严格档未确认分支停更）
- [ ] **M6-T4 拓扑视图**：C 端持有图渲染 + 待审批队列；消费端条款明示回执侧；用量异常启发式旗标（conlog + dstat 画像，只作线索）

### 验收标准

- C 认证设备在 B（互信对）直接带徽章、卡片显示来源；B 转发 C 认证到 D 仅当 D 名单含 C 时生效
- disclose 档：员工再签发事件 C 可见；approve 档：不批不生效；domain 档：只见域主体
- 被攻破中间跳伪造起源签名验签失败

---

## 2. DB 基线变更汇总（一次改完，严禁分批返工）

| 表 | 变更 | 所属 |
| --- | --- | --- |
| `group` | 删 `UNIQUE(name)`，建两个部分唯一索引（本机/采纳分离） | M1-T1 |
| `device_registry` | 新表：token_hash, device_fp, pubkey, remark, state(pending/certified/revoked), certified_by(来源节点), 认证人/时间, first_seen, last_seen, 累计流量 | M2-T6 |
| `approval` | 新表：类型(可插拔)/状态/关联对象/创建与裁决人时间 | M2-T6 |
| `approval_message` | 新表：approval_id, 方向(申请人附言/操作告知), body, ≤3 条约束 | M2-T6 |
| `device_session` | 新表：device_fp, token, entry, ip, start, end, bytes_in/out, close_reason（会话断开 flush；时序/历史/热力三吃），`node_traffic_log` 保持节点级不动 | M5-T1 |
| `grant_receipt` | 新表：artifact_ref, holder node/device_fp, lineage 血缘段, visibility 档, 起源签名, 状态 | M6-T3 |
| `delegated_token` | 加 `visibility` 列（domain/disclose/approve，默认 domain） | M6-T3 |
| `connector` / relay listener 配置 | 「传递认证」开关 + 节点级「认证信任名单」 | M6-T2 |

## 3. 协议面变更汇总（M2 一次成型）

| 面 | 变更 |
| --- | --- |
| 握手 | 挑战 nonce + ed25519 验签；`AuthRequest` 加 `my_name` + 设备公钥/签名；拒绝响应带 `reason_code` + 可选附言 |
| Ctrl 帧 | 吊销/关闭帧带 `reason_code` + 一次性附言；pending 会话附言上行（≤3）；认证/吊销传播与持有回执（M6 消费，帧格式 M2 预留） |
| 链接 | 加可选 `myname` 词（`core::link` / `aglink.js` 同步）；visibility 条款随委托链接表达 |

## 4. 全局非目标（明确不做）

- 不做 A 口径（单会话累计）——已选 B 口径，存活期累计复用内存
- 不为认证标引入新颜色体系——统一吃现有 token（`--info` / `--ok`）
- 不改数据面：group.id 路由、ACL 收敛、E2E、委托签发逻辑全不动
- 不做个人主密钥/助记词漫游身份、不接 passkey/WebAuthn（远期）
- 不做自动信任推断：认证信任名单一律人工维护，不按拓扑/域名自动扩
- 设备私钥默认不可导出；「身份导出备份」（PIN 加密）留待 v1.5 评估
- 无 SSH 式手工换钥匙流程；不探测/不定罪非 anet 转发（frp 类）

## 5. 相关文件 / 参照

- 设计原型：`target/badge-preview/index.html`；设计规范：`docs/architecture/ui-design.md`
- 联邦采纳：`crates/node/src/service/federation.rs`（`adopt_name` / `adopted_node` 血缘）
- 共享图标/渲染：`apps/desktop/ui/icons.js`（新增 `badge-check`）、`apps/desktop/ui/`（`srcBadge` / `nodeBadge` / hover 身份卡沉淀）
- 会话/流量底座：`crates/core/src/mux.rs`（`MuxSession.bytes_in/out`、Ctrl 握手帧）、`crates/node/src/proxy/conlog.rs`（kill 开关）
- 设备身份底座：`crates/client/src/credential.rs`（keyring/0600）、`ring` ed25519（已依赖）
- 流量落盘：`crates/node/src/db/logs.rs`（`node_traffic_log`）；DB 基线：`crates/node/src/db/migrations.rs`
