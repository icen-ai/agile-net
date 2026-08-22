# 信任档（Guard Profile）统一——「深度防护」贯穿三边界（待办）

> **纯规划文档**：全部未实施。目标：一次 AI 会话可完整执行本文全部批次。
>
> 来源：安全审计四决策项裁定（`docs/audit/REPORT.md` §决策项，2026-08-22 产品拍板）+
> 「把信任升格为贯穿产品的统一概念」设计讨论。
>
> 裁定回顾：①明文档保留+签发警示；②抗关联按需可选（默认不做）；③advertise 默认不验证
> （跨机构联邦时再评估）；④bearer 冒充由信任模型+设备门控覆盖。**本方案默认行为零变化，
> 一切额外防护只在显式开启「深度防护」后生效**——与四条裁定严格一致。

---

## 1. 概念与命名

产品内所有「对该端点/该凭据启用全部有代价的额外校验」的决策统一为一个概念：

- **名称**：`深度防护`（en: `Deep Guard`）；内部标识 `guarded`（`0|1`）
- **禁止负向文案**：不出现「不信任」「不受信」字样（勾选即骂对方的部署心理 + 内网政治问题）
- **统一视觉**：三处入口同一 switch 样式 + 同一盾牌徽标（icons.js 新增 `shield-alert`，
  列表项 guarded 时渲染 `<span class="badge b-warn">深度防护</span>`）
- **统一代价披露**：开关旁 ahelp 一句话写明代价（见 §4 各挂载点）

## 2. 三挂载点与执法矩阵

信任决策分布在三个边界，物理上是三个开关、共享同一概念与内部命名 `guarded`。

| # | 挂载点 | 谁决策 | guarded 开启后的增量执法 | 现状机制（复用，不重造） |
|---|--------|--------|--------------------------|--------------------------|
| G1 | 委托签发对话框（GUI `dt-modal` + 管理 SPA 签发弹窗） | 签发者（对消费者将经过的中继路径的判断） | ①强制 E2E（trust 档锁 plain 禁选）；②抗关联填充子选项可选 | 信任档=组 `e2e_required` 标记；F15 direct×e2e fail-close 已有 |
| G2 | 扇出连接编辑（GUI `fo-modal` + 管理 SPA 新建扇出） | 下游节点（对上游的判断） | 无钉值拒绝保存；`insecure` 复选禁用；`push_groups` 默认清空且勾选需二次确认；连接/上送/advertise 变更全部落审计 | `pinned_fingerprint` 钉值列、`connAuthTier` 徽章（pin>tls>insecure）已有 |
| G3 | 扇入 relay token 管理（管理 SPA 扇入页签发/编辑） | 中继管理员（对下行的判断） | 该 token 下行 advertise **重叠检测拒绝**（与他下行 CIDR/域名冲突即拒+审计）；上送组不进有效集（须走 federation/adopt 人工采纳）；该 token 接入设备**强制审批**（覆盖全局 `device_pending_policy=allow`） | `rebuild_routes` 路由并集、`sanitize_pushed_groups` 清洗、`device_gate` 门控已有 |

**默认（非 guarded）行为逐项不变**：G3 非 guarded 的 advertise 重叠只记 warning 审计（告警
版，不拒绝）——这是③裁定「跨机构联邦时再评估」的落地形态：现在就能看见冲突，想执法再开档。

## 3. 数据与协议

### 3.1 DB 列（pre-launch 直改基线 v1 的 CREATE TABLE，禁止迁移链）

- `connector` 加 `guarded INTEGER NOT NULL DEFAULT 0`
- `relay_token` 加 `guarded INTEGER NOT NULL DEFAULT 0`
- `delegated_token` 加 `anti_correlate INTEGER NOT NULL DEFAULT 0`（G1 的②子选项；
  G1 的强制 E2E 不需要列——它只是 UI 锁定 trust 档 + 组选择约束，最终仍由组 e2e_required 表达）

### 3.2 链接词（`core::link`，唯一解析器 `aglink.js` 双端同步）

- 新词 `pad=1`：抗关联填充档，仅与 `ek`（E2E 密钥）词共存；`pad` 存在而 `ek` 缺失 = 解析错误
- 生成侧：签发 G1 勾选抗关联时拼入 anet:// 链接；解析侧 `AgLink.parse` 带出 `pad` 字段，
  消费端凭据新增 `padding: bool`（`crates/client` Credential 结构 + 落库）

### 3.3 填充算法（G1②的执法点，两端对齐）

- 桶粒度 2048 字节；`ChannelCipher::seal` 前 payload 填充至 `ceil(len/2048)*2048`
  （填充区=随机字节，信封 nonce 已保证语义安全，填充无需独立认证）
- 消费端 `E2eStream`/`ChannelCipher` 构造带 `bucket: usize`（0=不填充）；签发端 unwrap
  侧同样以桶对齐校验/剥离（尾部随机区直接丢弃，明文长度由信封内长度字段承载——若现
  信封无显式长度字段，则在密文前追加 2 字节明文长度前缀，两侧同步）
- mux 层既有 16KB−0..2047 帧抖动保持不变（两层正交）
- 预期代价：小包密集流带宽 +5~15%（文档/ahelp 如实标注）

### 3.4 重叠检测算法（G3 挂点 `listener.rs rebuild_routes`）

- `AdvertisedRoutes.cidrs.insert(cidr, node_id)` 前查同 CIDR 不同 node_id → 冲突；
  域名表同理（`domains`/后缀表）。冲突时查该 node_id 对应下行会话的 token guarded 位：
  - guarded → 拒绝该条 advertise（该下行其余条目不受影响）+ `record_audit_log`
    （detail 含冲突 CIDR 与两个 node_id）
  - 非 guarded → 路由照旧并集 + warning 级审计（每对冲突只记一次，避免刷屏）
- token guarded 位随会话认证带入 listener 会话上下文（`AuthRequest` 侧已有 token 组集
  读取路径，同行扩展）

## 4. UI 与文案（双端一致：桌面 + 管理 SPA）

三处开关统一结构：`label 深度防护` + `.switch` + ahelp 代价说明 + 列表徽标。

| 挂载 | 开关位置 | ahelp 代价文案（zh 模板） | 徽标位置 |
|------|----------|---------------------------|----------|
| G1 | dt-modal 信任档下方整行（勾选后 trust 三档中「明文」禁用变灰） | 「强制端到端加密；可再勾选抗关联填充（流量轮廓抗关联，带宽约 +5~15%）」 | 已签发列表该令牌行 `b-warn` 徽标 |
| G2 | fo-modal 指纹钉值行下方整行 | 「必须钉值对端证书指纹、禁用 insecure 跳过校验；上送权限组需显式勾选」 | 扇出连接列表行徽标 |
| G3 | 管理 SPA relay token 编辑弹窗整行 | 「下行路由声明与他人重叠将被拒绝；上送组须人工采纳方生效；接入设备强制审批」 | 扇入 token 列表行徽标 |

- **G1 明文警示（默认生效，与 guarded 无关，裁定①落地）**：trust 档选中「明文」时
  下方出现警示条（`net-banner` 样式）：「明文档下中继可审计全部内容——适用于自有内网
  可审计场景；流量将经过不受信中继时请改用端到端档」
- i18n：新键前缀 `guard.*`（`guard.on/off/label/g1Tip/g2Tip/g3Tip/plainWarn/antiCorrelate/
  badge` 等），入 `lang/desktop-views.js`（桌面）与 `lang/admin.js`（管理端），zh/en 双语
- `icons.js` 收录 `shield-alert`（双端唯一图标表规范）

## 5. 实施批次（一次会话按序全做的顺序）

### 批 1 — 文案与开关 UI（无行为变化）
1. G1 明文警示条（GUI dt-modal + 管理 SPA 签发弹窗，trust=plain 时显示）
2. 三处 guarded switch + ahelp + i18n 键 + `shield-alert` 图标（先接线存内存，不落库）
3. 验收：`cargo check` 双 workspace；`node --check`；语言切换重渲正常（onChange 清签名）

### 批 2 — 数据与执法（G2/G3 全量）
1. DB 基线三列（§3.1）；`add_server_connector`/`update_server_connector`/relay token
   CRUD 请求体加 `guarded` 字段透传落库
2. G2 保存校验：guarded 且无 `pinned_fingerprint` → 拒绝（错误消息中文，GUI/SPA 双端
   弹内联错误）；guarded 时 fo-modal insecure 复选 disabled
3. G3 执法：§3.4 重叠检测（含 guarded 位随会话带入）+ 设备门控覆盖（guarded token 的
   pending 设备无视全局 allow，走审批中心既有流程）+ 上送组不进有效集
   （`effective_advertise` 并集处按 guarded 跳过上送组规则）
4. 测试（全部进 `crates/core/tests/` 或既有套件，命名照现风格）：
   - `guarded_advertise_overlap_rejected`：两下行同 CIDR，guarded 后到者被拒 + 审计断言
   - `unguarded_overlap_only_warns`：非 guarded 并集照旧 + warning 审计一次
   - `guarded_token_forces_device_approval`：全局 allow 下 guarded token 设备仍 pending
   - `guarded_pushed_groups_not_auto_effective`：上送组不进 effective_advertise
   - connector 层保存校验单测（无钉值拒绝）
5. 验收：`cargo test --workspace` 全绿；`anet connector list`（CLI）能显示 guarded 列

### 批 3 — 抗关联填充（G1②）
1. 链接词 `pad`（`core::link` 生成/解析 + `aglink.js` 对齐 + 单测 roundtrip 双语言）
2. `ChannelCipher` 桶参数与填充/剥离（§3.3；含明文长度前缀决策的落地与两侧一致性测试
   `e2e_padding_bucket_roundtrip`：seal 后长度恒为 2048 倍数，unwrap 还原原文）
3. 签发链路：`delegated_token.anti_correlate` → `issue_token` → 链接拼 `pad`；消费端
   Credential.padding → E2eStream bucket
4. G1 UI：guarded 勾选后「抗关联填充」子复选出现（默认关）
5. 验收：既有 E2E 全部回归测试不动通过；新增填充测试绿；`pad` 无 `ek` 时解析报错测试

### 范围外（本文档明确不做，防执行漂移）
- 挑战-响应令牌（协议 v5 演进，F13 彻底解法）
- 恒速整形/掩护流量（抗关联二期）
- 跨机构联邦的 advertise 审批流（等联邦真实部署需求）
- transparent 档删除或默认值变更（裁定①=保留）

## 6. 总验收清单

- [ ] `cargo test --workspace` 与桌面 workspace 测试全绿（新增 ≥6 项测试）
- [ ] `cargo clippy --workspace -- -D warnings` 干净
- [ ] 三处 guarded 开关双端（GUI+管理 SPA）样式/文案/徽标一致，i18n zh/en 齐
- [ ] 明文警示条只在 trust=plain 出现
- [ ] guarded connector 无钉值保存被拒；insecure 禁用
- [ ] guarded relay token 三项执法各有测试断言
- [ ] `pad` 词 roundtrip + 无 ek 报错 + 填充桶长度断言
- [ ] 默认路径（一切不勾 guarded）行为与改动前逐项一致——这是裁定的硬约束
