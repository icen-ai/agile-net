# 联邦模型 P2+P3 实施计划（域内身份与签发委托 + E2E 载荷加密）

> 设计蓝本：`docs/todo/federation.md`（§2 关键设计决策为约束）；前置：P1 已落地（`docs/plan/federation.md`）
> 状态：**已实施**（2026-08-04；切片 1–11 全部落地，`cargo test --workspace` 377 全绿 +
> 双 workspace clippy 零告警；端到端验收 `crates/node/tests/federation_p2_test.rs` /
> `federation_p3_test.rs`；实施偏差见 §9）
> 交付约定：P2 与 P3 一次实施、一份验收；切片 1–5 构成可独立交付的完整 P2（§6）

---

## 1. 决策锁定（四个关键决策点；如有异议先改本节再开工）

### 1.1 P2 签发委托形态：**会话内注册，无迷你 CA**（推荐方案，替代原文档「迷你 CA」）

- **注册通道即信任通道**：C 扇出到 B 的会话已完成 relay token 认证；委托令牌经该会话上的控制帧
  注册（token 哈希 + 组引用 + 路由词表），会话本身即身份证明——不需要逐令牌签名，不需要 CA。
- **生命周期随会话**：委托令牌只在签发者的扇出会话存活期间有效（与 P1 上送组入池同一语义）。
  语义天然正确：C 离线时 A 反正到不了 C 的资源。于是「吊销沿链传播」整体消失——
  C 断线或发吊销帧 → B 删注册 + 踢会话，**吊销即断**成立；B 侧零落库（仅审计），无 TTL、无吊销列表。
- 域内身份 = `node_id + token 哈希`；同身份第二会话**踢旧留新**（容忍重启抖动，防劫持边界与
  relay token 吊销等价）+ 审计；同 B 多扇出连接强制身份后缀（`name#connector`）。
- 被否方案：自包含签名令牌 + TTL + 吊销列表（B 可离线验签，但吊销传播与密钥轮换复杂度显著上升）；
  完整迷你 CA（身份最强，但引入密钥仪式与证书生命周期管理，与 relay token 信任根重复）。

### 1.2 P2 多上游入口：**容灾集合 + 主入口（v1 正式范围）**

- M 多宿主扇出 B1/B2/B3 时，签发对话框两层选择：**注册目标多选（容灾集合，默认全选在线上游）**
  + **主入口单选**（链接首连地址；其余为容灾备援，按 C 侧扇出会话延迟/优先级排序）。
- **容灾集合语义**：委托令牌逐 B 注册（各 B 会话级注册表独立）；吊销逐 B 发送；
  C 与某 B 断线 → 该 B 注册自动失效——集合语义与会话级生命周期自洽，零跨 B 对账。
- **信任含义（签发 UI 明示）**：透明档下容灾集合 = 「让谁看见流量」的集合（任一活 B 可见）；
  E2E 档下集合仅是可用性/成本决策（B 只见 hint）。
- **容灾是重连级**：B 离线 → 隧道断开 → 客户端按入口列表故障切换，在飞 TCP 连接断开由应用层
  重试（与一切 VPN 行为一致；不同 B 不同 IP，TCP 级无缝迁移不可能）。
- **E2E 与入口无关**：密钥 = HKDF(令牌明文)，漫游换 B 不换密钥，C 照解——HKDF 方案天然容灾就绪。
- 被否/延期方案：v1 只单入口（被用户场景否决：主入口离线应可漫游活节点）；
  TCP 级无缝漫游（物理不可能，不立项）。

### 1.3 P3 E2E 密钥：**HKDF(令牌明文) PSK，零握手**（推荐）

- `e2e_key = HKDF-SHA256(ikm=token_plaintext, salt="anet/e2e/v1", info="")`：
  A 从链接中的令牌推导，C 签发时同样推导；**B 只有哈希，推不出**——零握手帧、零额外往返。
- 代价：无前向安全性（令牌泄露则历史流量可解）。威胁模型中 B 本就是网络观察者 + 逐跳 TLS 终点，
  泄露窗口窄；Noise_NK 带内握手（带 FS）留作 P3.5 文档化延伸（§8）。
- E2E 仅适用于**委托令牌**（B-local 账号的流量终点就是 B，无 E2E 语义）。

### 1.4 P3 强制粒度：**按权限组 `e2e_required`**（推荐，与原文档一致）

- 组新增标记（DB v10）：「要求端到端加密」。校验规则：e2e_required 组**不可**用于本地账号、
  relay token 收敛与 connector 收敛（那些主体无 E2E 密钥），仅委托令牌可挂；
  组标记随上送传播（B 代执法用），采纳到上游的组带同名标记。
- 组内目标全程 E2E；混合组并存（未标记组保持透明档）。

---

## 2. P2 详细设计

### 2.1 协议 v3（向后兼容矩阵）

- `PROTOCOL_VERSION = 3`。新增控制帧 `FrameType::Ctrl`（JSON payload，会话控制面与数据面分离）：
  - `{op:"token_register", token_hash, label, groups:[...], hint_map:[{hint, groups:[...]}]}`
  - `{op:"token_revoke", token_hash}`
- `OpenChannel` 扩展：`{ target_addr, target_port, groups?: Vec<String>, e2e?: E2eOpen }`
  （serde default，旧端忽略新字段）。
- 版本协商：B 记下游版本（AuthRequest.version），C 记上游版本（AuthOk.version）；
  任一侧 < 3 → 委托注册不可用（C 侧签发 UI 对该上游置灰并说明），其余功能不变。
  v2 老下游接 v3 上游、v3 下游接 v2 上游均正常工作（无 Ctrl 帧流量）。

### 2.2 委托令牌（C 侧签发与存储）

- C 生成 `psk_` + 48 位（与本地 relay token 同熵）；明文仅进链接，C 库存哈希：
  **表 `delegated_token`（DB v10）**：`id, token_hash UNIQUE, token_prefix, label, groups (JSON 组名数组),
  hint_map (JSON), created_at`；
  **表 `delegated_token_reg`**：容灾集合逐上游一行（`token_id→delegated_token, connector_id→connector,
  is_primary`），主入口一行 `is_primary=1`。
- **自动重注册**：connector 每次（重）连成功（AuthOk v3+）后，把**该 connector 名下**的全部
  `delegated_token` 逐条重发 `token_register`——B 侧无状态，重连即恢复，无需对账；
  容灾集合内各上游独立注册、独立失效。
- 吊销：C 删除本地记录并向集合内**每个在线上游**发 `token_revoke`；上游断线天然吊销（仅该上游）。
- hint_map 语义：**路由词表**——B 只拿 hint（粗规则），A 的真实目标经 E2E blob 或透明档组规则到达；
  透明档令牌的 hint_map 由 C 从所引用组的上送规则自动生成（与 B 代执法词表一致）；
  E2E 令牌的 hint_map 由 C 管理员（或签发 UI 默认）选粗规则，细规则 R1 可以只存 C 本地（§4.3）。

### 2.3 委托注册表（B 侧，会话级）

- `DelegatedRegistry: DashMap<token_hash, DelegatedToken{issuer: node_id, groups, hint_map, label}>`，
  挂在 listener 上，随 issuer 会话断开朗清空（与 peer_groups 同生命周期）。
- `token_register` 校验：groups 非空（或空 = 签发者全部上送组）；
  **hint 必须命中 issuer 当前 advertised routes**（否则无法路由，拒绝注册并回执错误原因）。
- 客户端认证扩展（`DbTokenValidator::validate`，kind=Client）：本地 `tunnel_token_hash` 未命中后
  查委托注册表 → 命中则构造 Client 身份：ACL = issuer 上送组 ∩ 令牌 groups 的规则并集（透明档）
  或 hint_map 词表（E2E 档，§4）；会话标记 `delegated=issuer`，审计携带签发者。
- 踢出：revoke/断线时按 token_hash 踢会话（复用现有 `disconnect_client` 路径，
  委托会话以 `delegated:<token_hash>` 为会话键）。

### 2.4 会话组标识与 C 侧按组执法

- B 转发委托会话的 Open 时携带 `groups`（该会话令牌引用的组名，透明档）。
- C 侧（connector `handle_open`）：Open 携带 groups 时，目标必须命中
  **C 本地同名组规则并集**（组名只认 C 本地存在的，未知名忽略；全部未知 → 拒绝 + 审计）。
- 不携带 groups 的 Open 维持现状（connector 级 PeerAcl 作为**外圈基线**继续生效，纵深防御；
  会话级逐组执法为内圈主机制，兑现原文档「按组执法」）。

### 2.5 签发 UI（共享管理端 SPA，双端自动获得）

- 扇出页新增「签发委托」页签：签发表单（**注册目标多选** = 容灾集合（默认全选在线上游）→
  **主入口单选**（默认集合第一个）→ 选本地组多选 → 备注 → 生成）→
  复用 P1 分享卡片（链接入口 = 主入口地址，`entry=` 携带容灾集合全量地址与逐入口指纹）；
  列表（label / 组 / 容灾集合（主入口徽标 + 各 B 在线状态）/ 创建时间 / 吊销按钮）。
- 信任含义明示：透明档集合 = 流量可见集合；E2E 档集合 = 可用性集合（签发卡片 ahelp 固定文案）。
- API（C）：`GET/POST /api/v1/admin/delegation/tokens`、`DELETE .../:id`（响应携带逐上游注册状态）；
  审计事件 `delegation.issue` / `delegation.revoke` / `delegation.register(上游回执失败)`。
- 桌面端：嵌入式控制台 iframe 自动获得；扇出页「企业联邦对接」条目文案更新为签发委托入口。

### 2.6 链接格式扩展（多入口容灾）

- 委托链接沿用 `anet://connect`（账号语义 = 客户端接入），`password` = psk_ 令牌，
  `account` = `d:<label>`（委托标记，导入 UI 显示「由 <C> 签发」）；
- `server` + `fp` = **主入口**地址与 relay 证书指纹（与 P1 链接同构）；
- `entry` = 逗号分隔的 `host:port` 全量入口列表（含主入口，容灾顺序即优先级）；
- `entryfp` = 与 `entry` 平行的逐入口 relay 指纹列表（C 签发时本就钉着每个 B 的指纹，
  全部内嵌；单项可空 = 该入口回退 TOFU 并随凭据持久化）；
- 解析扩展（aglink.js / core::link 同步）：`entry/entryfp` 新参数（旧解析器忽略未知参数，
  旧客户端打开多入口链接 = 只用主入口，优雅降级）。

### 2.7 P2 验收（端到端测试）

`federation_p2_test.rs`：C 签发委托令牌（git 组，容灾集合 = B1/B2 双注册）→ 链接发 A →
A 以 kind=Client 认证 B1（委托注册表命中）→ ACL = C 的 git 组规则 →
B1 路由至 C（Open 带 groups）→ C 按本地 git 组放行；
**容灾**：B1 停掉 → A 按 entry 列表切换 B2 → 同样认证成功、路由至 C；
C 吊销 → B1/B2 注册表同时清除 + A 会话即断；C 断线 → 委托自动失效、重连自动重注册恢复。

---

## 3. DB v10 迁移

```sql
-- 委托令牌（federation P2：资源主直接对消费者签发，经扇出会话注册到上游代收）
CREATE TABLE delegated_token (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    groups       TEXT NOT NULL DEFAULT '[]',   -- JSON 组名数组（C 本地组名）
    hint_map     TEXT NOT NULL DEFAULT '[]',   -- JSON [{hint, groups}]（E2E 路由词表）
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 容灾集合：逐上游注册一行（主入口 is_primary=1；随扇出会话自动重注册）
CREATE TABLE delegated_token_reg (
    token_id     TEXT NOT NULL REFERENCES delegated_token(id) ON DELETE CASCADE,
    connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
    is_primary   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_id, connector_id)
);

-- E2E 强制标记（federation P3：按权限组；不可挂本地账号/relay token/connector）
ALTER TABLE "group" ADD COLUMN e2e_required INTEGER NOT NULL DEFAULT 0;
```

## 4. P3 详细设计

### 4.1 密钥与帧

- `e2e_key = HKDF-SHA256(ikm=token_plaintext, salt="anet/e2e/v1", info="")`（32B）。
- Open 扩展：`E2eOpen { kid: String(token_hash 前 8 hex), hint: String, blob: String(base64) }`；
  `blob = AES-256-GCM(e2e_key, nonce=0, json{target_addr, target_port, groups, chan_salt(16B 随机)})`。
  `kid` 供 C 在已签发令牌集中查密钥（B 只见哈希前缀，本就知道全哈希）。
- **信道子密钥**：`chan_key = HKDF-SHA256(ikm=e2e_key, salt=chan_salt, info="chan")`——
  chan_salt 由 A 逐信道随机生成（blob 内携带），**跨会话/跨信道 nonce 零重用**
  （裸 `channel_id‖seq` 在重连后会撞 nonce，AES-GCM nonce 重用是灾难性的，此为硬性纪律①）。
- 数据面：该信道后续 Data chunk 逐块 AEAD（chan_key，nonce = `direction(1B) ‖ chunk_seq(8B)`）。
- **接收端严格序列校验**：乱序/重复 chunk 即弃即断（硬性纪律②——B 无法伪造新密文，
  但可重放旧块造成 DB 级重复突变，收端必须 fail closed）。
- 实现位置：客户端隧道 opener（e2e 包装）与 C 侧 connector `handle_open`（e2e 解包）之间新增
  `relay::e2e` 编解码层；mux/帧格式零改动（全部承载于 Open/Data payload）。

### 4.2 B 侧盲转与 C 侧 fail-close

- E2E Open：B 校验会话令牌的 hint_map 覆盖 `hint`（B 代执法的词表边界，**只见粗规则**），
  按 hint 命中 advertised routes 转发给 C；blob 原样透传。B 对 E2E 会话只见「给 C」。
- **C 侧 fail-close（硬性纪律③，堵配置降级）**：配置下发经 B 之手，B 可抹掉 e2e_required
  标记诱使 A 明文直发；C 的 connector 对**命中本地 e2e_required 组规则的未加密 Open 一律拒绝**——
  降级攻击退化为 DoS（可用性本是 B 的物理权力，容灾集合对冲），绝不退化为明文泄露。
- 透明档与 E2E 并存：会话内逐 Open 决定（按目标命中的组是否 e2e_required）。

### 4.3 粗广告 + 本地细授权（R1 场景兑现）

- C 对 B 只广告/注册粗 hint；细规则 R1 只存 C 本地组（该组可不上送）。
- C 侧 e2e 解包后：按 blob.groups 的**本地组规则全集**（含 R1）执法 → 连接 R1。
- B 全程无感知：授权集合（blob 内）与目标（blob 内）都不可见。

### 4.4 客户端改造（多入口容灾 + E2E 包装）

- 委托链接导入即标记委托凭据（`account` 前缀 `d:`）；配置下发携带 e2e_required 组词表
  （B 转发 C 的组标记）与 hint 词表。
- **入口候选列表**：凭据保存 `entry/entryfp`（无 entry 参数 = 单入口，现状兼容）；
  首连 = 主入口；隧道断开 → 按 entry 顺序故障切换（逐入口指数回退 + full jitter，
  切换事件上报日志/灵动岛；全部失败回主入口重试循环）。
- 逐入口指纹钉值：`entryfp` 平行列表；缺项 TOFU 并随凭据持久化（与 P1 钉值语义一致）。
- opener 对命中 e2e_required 的目标走 §4.1 包装；密钥 = HKDF(凭据密码)。
- 非委托凭据 / 非 e2e 目标：零行为变化。

### 4.5 P3 验收（端到端测试）

`federation_p3_test.rs`：e2e_required 组挂委托令牌 → A 经 B 访问 R1（仅 C 本地规则）→
可达；B 侧断言：转发记录只见 hint（无 R1 字样），B 代执法词表不含 R1；
非 e2e 组目标保持透明档（B 代执法按上送规则生效）。
**安全三纪律断言**：未加密 Open 命中 e2e_required 组 → C 拒绝（fail-close）；
重放旧 chunk → 收端弃断（序列校验）；跨会话同 (channel,seq) 无 nonce 重用（子密钥盐隔离）。

---

## 5. 安全与审计

- 委托令牌与 relay token 同强度（`psk_` + 48 位、哈希落库、明文仅签发时一次）；
  注册/吊销/认证失败沿用常量时间比较 + IP 限流 + 随机延迟（复用现有路径）。
- B 的委托注册表是**易失状态**（内存）：无持久化泄露面；重启即清，C 重连重注册。
- **E2E 三条硬性纪律**（详见 §4.1/§4.2，验收测试逐条覆盖）：
  ① 每信道随机盐派生子密钥（跨会话 nonce 零重用）；
  ② 接收端严格序列校验（乱序/重放即弃即断）；
  ③ C 侧 fail-close（命中 e2e_required 组的未加密 Open 一律拒绝，堵 B 的配置降级）。
- E2E 信道认证性：blob 只有 A/C 能解（密钥 = HKDF(令牌)），**解密成功即完成对信道来源的认证**，
  无需额外签名。
- 审计：C 侧 `delegation.issue/revoke`；B 侧 `delegation.register/revoke`（含 issuer）、
  `delegation.auth_fail`（按 IP 限流）、E2E 会话只记 hint，严禁记录 blob/明文/目标。
- e2e_required 组挂载校验在组/账号/令牌/connector 四个写入口统一拦截（单点校验函数）。
- 诚实天花板（文档化，不掩盖）：元数据/流量分析可见（非 Tor 目标）；
  v1 无前向安全性（B 录流量 + 事后令牌泄露 → 历史可解，P3.5 Noise_NK 补齐）；
  令牌即信任根（端点泄露 = 令牌能力全失，靠吊销 + PIN + 一次性 ticket 缓解）。

## 6. 实施切片（顺序；1–5 = 完整 P2，可独立交付）

1. 协议 v3：Ctrl 帧 + OpenChannel 扩展 + 版本协商（core；兼容矩阵测试）
2. C 侧：delegated_token + delegated_token_reg 表（v10）+ 签发/吊销/容灾集合重注册（db + connectors 钩子）
3. B 侧：委托注册表 + validate 扩展 + hint 校验 + 会话踢出（listener + relay_auth）
4. 会话组标识：OpenChannel.groups 传递 + C 侧 per-open 组执法（core connector）
5. 签发 UI：管理端扇出页「签发委托」页签（容灾集合多选 + 主入口单选）+ API + 分享卡片复用（含桌面 iframe 自动获得）
6. 链接与客户端容灾：`entry/entryfp` 解析（aglink.js + core::link）+ 凭据候选列表 + 故障切换（client）
7. E2E 编解码与转发：relay::e2e + B 盲转 + C 解包执法 + 客户端包装（core + client）
8. e2e_required 组标记全链：组 DB/UI + 上送传播 + 四入口校验 + 客户端词表
9. 环合收尾：同身份踢旧 + 同 B 多连接身份后缀 + 审计
10. 验收：federation_p2_test.rs（含容灾切换）/ federation_p3_test.rs + 全量回归
11. 文档：docs/todo/federation.md 状态、AGENTS.md、docs/api、wiki 双语

## 7. 非目标（本期）

- TCP 级无缝漫游（物理不可能；容灾 = 重连级故障切换，见 §1.2）；
- Noise_NK 前向安全性握手（P3.5，§8）；
- B-local 账号的 E2E（无语义：B 即终点）；
- NAT 穿透（原 P4，仍为非必需）。

## 8. P3.5 延伸（文档化，不实施）

- **FS 握手**：C 在上送中携带 X25519 公钥（会话注册信任通道），A 经配置下发获得；
  每 (A,C) 会话 Noise_NK 带内握手（首信道一次，后续信道复用会话密钥 + channel binding），
  前向安全性覆盖「B 录流量 + 事后令牌泄露」窗口。
- **一次性 ticket 委托**：委托令牌加 max_uses/expires（注册帧携带，B 侧计数），
  面向「临时外部专家」场景。

## 9. 实施偏差记录（落地时收敛，2026-08-04）

以下为实施过程中对设计的有意收敛，与上述章节冲突时以本节为准：

1. **blob 随机 nonce（纪律①的彻底化）**：§4.1 原写 `blob = AES-256-GCM(e2e_key, nonce=0, ...)`——
   同一 e2e_key 下多信道 blob 会撞 nonce。落地改为 `blob = base64(nonce12 ‖ ct)`（逐信道随机
   nonce），chan_salt 仍在 blob JSON 内派生信道子密钥。
2. **`ehint` 链接参数 + A 侧「全部 E2E」模型**：A 不知道组词表（链接只含地址/凭据/指纹）。
   落地形态：hint_map 非空的委托链接携带 `ehint=<hint>`，A 侧全部 Open 走 E2E 包装
   （透明组流量同受保护，C 解包后统一执法）；无 ehint = 全透明档。旧客户端忽略 ehint——
   透明组仍可用，E2E 组被 C fail-close 拒绝（优雅降级成立）。
3. **空 blob.groups = 令牌全集**：消费端不知道组名；C 侧 DelegationEngine 的 kid 缓存携带
   令牌组名集，空 blob.groups 解包后继承填充——R1 细组（不上送）由此对 B 完全隐形。
4. **MuxSession 事件通道**：`start(...)` 的 `open_tx` 参数升级为 `SessionEvents{open_tx, ctrl_tx}`
   （Ctrl 帧固定走 channel 0 投递），未来控制面扩展不再加参数。
5. **ChannelOpener 返回 BoxedChannel**：`AsyncChannel` blanket trait + boxed stream，
   DelegatedOpener 的 E2eStream 包装对所有消费方（SOCKS/HTTP 入站、多跳转发）透明。
6. **委托节点路由模型**：委托凭据注册全量路由（`0.0.0.0/0` + 通配域名 `*`）——消费者整机
   流量即目的；多节点冲突遵循既有 first-connected-wins 语义。
7. **同身份踢旧的清理条件化**：旧会话退出路径按 mux 指针 `remove_if` 匹配——修掉重连抖动下
   旧会话误删新会话路由/上送组/委托注册的并发 bug（存量缺陷，随本批次修复）。
8. **`NodeServer::stop` 关闭已建会话**：新增 `RelayListener::shutdown_all()`——原实现只杀
   accept loop，同进程 stop 后旧 TLS 会话残存（GUI 角色停止语义同步正确化）。
9. **委托会话键**：`delegated:<token_hash>` 复用 clients 表与 disconnect_client 踢出路径；
   委托流量不经账号流量日志（account_id 非本地账号，JOIN 自然落空，无异常）。
10. **hint 校验语义**：注册时逐 hint 验证 `resolve_peer(hint) == issuer`（可直接路由回签发者），
    比「命中 advertised routes 词表」更严且实现更简。
11. **存储**：delegated_token.groups 存**组 ID** JSON 数组（原计划组名）——改名安全；
    注册帧构建时 resolve 为组名（悬空跳过 + warn）。e2e_key 恒推导并加密落库
    （AES-256-GCM，同 connector token 机器密钥，第二可逆例外），避免「透明令牌后挂 E2E 组」
    的补签窗口。
12. **advertise 自动并集上送组规则（2026-08-04 补充）**：原设计要求扇出方手工维护 advertise
    路由宣告，hint 从其中派生——实践中只配上送组（push_groups）的端点会导致整条数据面
    （采纳组流量、透明/E2E 委托）在上游路由表无回程路由，签发 E2E 委托直接 400。落地收敛：
    `RelayConnector::effective_advertise()` = 手工 advertise ∪ 上送组规则（∪ 客户端隧道
    再发布路由，既有）；语义即「上送组 = 资源邀约 = 路由声明」。上送组变更本就走重连重推，
    advertise 随之热更新，无新帧无新槽位。签发侧 hint 派生走同一并集
    （`connectors::effective_advertise_of`），保证 hint 恒落在对方路由表实际承载的集合内。
13. **消费接入双档：专线（dedicated）/ 分流（split，2026-08-05 补充）**：偏差 6 的全量路由
    模型正名「专线」——规则对委托方不可见、整机流量进隧道。新增分流档：链接携带
    `emode=split`（缺省 = 专线，旧客户端忽略优雅降级为专线），A 侧连上后经 **E2E 配置通道**
    （保留目标 `__anet_delegation_config__`，blob 内寻址、B 全程只见 hint）拉取令牌有效
    词表（含不上送的 R1 细规则——E2E 密封下发，B 依旧盲），路由从全量换为词表；拉取失败
    回退全量（专线行为恒安全）。C 侧 `DelegationHooks::delegation_rules(kid)` 本地应答
    （有效密钥即授权，应答内容恒为令牌自身词表，无越权面）；C 改规则后 A 重连/故障切换即
    刷新。分流档要求引用组含 e2e_required 组（签发 400 拦截）；DB v11
    `delegated_token.mode` 落库（徽标展示与链接重建）。
14. **委托管理授权 + 穿透管理（2026-08-05 补充）**：E2E 配置通道升级为 `DelegationConfig`
    （rules + admin + upstreams）。`delegated_token.admin_scope`（DB v13，''/ro/rules/full）
    非空即管理档：票据经配置通道下发（**仅限 E2E**——票据绝不明文过 B，签发 400 拦截），
    消费端桌面经保留目标 `__anet_delegation_admin__` 桥接签发端 loopback API 打开控制台
    （票据 kind 沿用 `relay`——admin_ticket CHECK 仅允许 account/relay，attribution 靠
    `deleg:<label>@<kid>` subject）。full 档额外收到签发端 manageable 注册表的上游报价，
    经 blob 目标 `upstream:<node_name>` 让签发端在同一会话上开嵌套信道直拨上游控制端点
    （A→E2E→C→扇出会话→B API 全链，B 依旧只见 hint）。链接新增 `eadmin=1` 能力提示
    （旧端忽略，仅丢管理入口）。旧端兼容性不变；「先复制再编辑」语义同采纳镜像。
