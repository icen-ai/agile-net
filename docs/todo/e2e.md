# E2E 委托信息泄露与 Entrustment Number 方案（讨论记录）

> 来源：2026-08-06 架构讨论，聚焦当前 P3 E2E 模型在实践中暴露的信息泄露路径
> 关联：P2+P3 实施记录 `docs/plan/federation-p2p3.md`、联邦设计蓝本 `docs/todo/federation.md`
> 状态：**已实施**（en_xxx 主体方案 + §7 缺陷批次 + §8 令牌生命周期均已落地，见 §10 实施记录；
> 遗留非目标见 §9， Noise_NK 前向安全性仍属 P3.5 延伸）

---

## 1. 问题：E2E 委托实际的信息泄露面

### 1.1 设计预期 vs 实操

P3 的设计目标是"B 只做盲转发，不见权限组内容"。`docs/plan/federation-p2p3.md` §4.2 明确写道：

> B 代执法的词表边界，**只见粗规则**……B 对 E2E 会话只见「给 C」。

但实际操作中存在一个强制性路径，使 B **完整看到** C 的权限组内容。

### 1.2 泄露路径（逐层追踪）

**第一层：签发委托要求路由可达**

`crates/node/src/api/handlers/delegation.rs:110-179` — 当签发 E2E 委托时，系统从主入口扇出的
`effective_advertise` 自动推导 hint。若 `effective_advertise` 为空（既不填手工 advertise，
也不在扇出连接中勾选上送组），签发直接返回 400 错误：

> "引用组含端到端加密组，但主入口扇出没有任何可路由项……请为该扇出配置路由宣告，或勾选含规则的上送组"

**第二层：勾选上送组后，完整规则推送给 B**

`crates/core/src/relay/connector.rs:311-403` — C 连接 B 时，`effective_advertise()` 将
手工 advertise 和 push_groups 的**每一条规则**取并集，打包进 `AuthRequest.advertise`。
同时 `AuthRequest.groups` 包含完整的 `PushedGroupMsg`：

```rust
// 发给 B 的 AuthRequest 内容：
AuthRequest {
    advertise: ["10.0.1.0/24", "git.internal", "db-prod.internal"],   // ← 全量 IP/Host
    groups: [PushedGroupMsg {
        name: "开发组",        // ← 组名
        rules: [...],          // ← 完整规则文本
        e2e_required: true     // ← E2E 标记
    }],
}
```

`crates/core/src/proto/message.rs:22-32` — `PushedGroupMsg` 结构体包含 `name`、`rules[]`
（字符串数组，每条规则的完整文本）、`e2e_required` 标记。全部以明文方式编码在 AuthRequest 中。

**第三层：B 的控制台完整展示可采纳池**

`crates/core/src/relay/listener.rs:785-791` — B 收到后存入 `peer_groups` DashMap：

```rust
let groups = sanitize_pushed_groups(groups);
self.peer_groups.insert(node_id.clone(), groups);
```

B 的控制台"可采纳池"展示来自 C 的权限组：组名、每条规则（IP 段/域名）、E2E 标记，全部可见。

### 1.3 泄露总结

| 泄露内容 | 泄露途径 | 泄露对象 |
|----------|----------|----------|
| C 的权限组名称（如"开发组""数据库组"） | AuthRequest.groups[].name | B 管理员 |
| C 的权限组规则（IP 段、域名、Host） | AuthRequest.groups[].rules[] + advertise[] | B 管理员 |
| 哪些组启用了 E2E | AuthRequest.groups[].e2e_required | B 管理员 |
| hint 可反推规则 | `10.0.1.0/24 → 10.0.1.1`，`*.internal → relay.internal` | B 管理员/日志分析 |

### 1.4 根因

**"路由可达性"和"权限组内容"被绑在了一起。** 要让 B 能把流量路由到 C，就必须在 B 的路由表中插入条目。
当前唯二的条目来源——手工 advertise 和 push_groups 规则——都直接暴露了权限组的完整内容。
E2E 的 `blob` 加密保护了数据面的目标地址，但控制面的权限组宣告是明文路径。

---

## 2. 方案：Entrustment Number（`en_xxx`）

### 2.1 核心思路

将"路由键"从"有语义的 hint（可反推规则）"替换为"无语义的不透明 ID（`en_xxx`）"，
实现**路由与权限组内容的彻底分离**。

```
现在:
  C → B: 宣告 "我能路由 10.0.1.0/24, git.internal"  → B 知道 C 的规则
  B 路由: 10.0.1.0/24 → C, git.internal → C
  A Open: hint = "relay.internal"                    → B 查路由表转发给 C

en_xxx 后:
  C → B: 宣告 "请把我注册为 en_abc123def456"         → B 只知道 en_xxx → C
  B 路由: en_abc123def456 → C                        → 零信息泄露
  A Open: hint = "en_abc123def456"                   → B 查 entrust 表转发给 C
  C 收到后: 解密 blob，按本地组规则执法                → 授权完全在 C 侧
```

### 2.2 数据流对比

```
【当前 E2E 流】

C ──扇出 Auth──▶ B    advertise: [10.0.1.0/24, git.internal]
                       groups: [{name:"开发组", rules:[...], e2e_required:true}]
                       → B 的控制台完整可见

C ──Ctrl 注册──▶ B    token_register { hint_map: [{hint:"10.0.1.1", groups:["开发组"]}] }
                       → B 校验 resolve_peer("10.0.1.1") == C

A ──E2E Open──▶ B    E2eOpen { kid, hint:"10.0.1.1", blob:base64(nonce||AES(real_target)) }
                       → B 查 DelegatedRegistry + 路由表 → 转发给 C


【en_xxx 流】

C ──扇出 Auth──▶ B    advertise: []                   ← 空！不需要宣告任何路由
                       groups: []                      ← 空！不需要推送任何权限组

C ──Ctrl 注册──▶ B    token_register { hint_map: [{hint:"en_abc123", groups:["开发组"]}] }
                       → B 发现 en_ 前缀 → 直接记录 en_abc123 → C
                       → 不调用 resolve_peer()，不要求 C 有广告路由

A ──E2E Open──▶ B    E2eOpen { kid, hint:"en_abc123", blob:base64(nonce||AES(real_target)) }
                       → B 查 entrust registry → 找到 C → 转发
```

### 2.3 两种模式的适用性

**专线模式（dedicated）—— strictly better**

专线模式下 A 整机流量全部进隧道（路由 `0.0.0.0/0`），B 不需要知道规则来做路由决策。
当前仍然宣告 hint_map + groups 给 B，是纯粹的冗余信息泄露。用 `en_xxx` 后 B 从始至终
不知道 C 在服务什么资源。

**分流模式（split）—— 同样完全可用**

分流模式下 A 做选择性路由（只把命中词表的流量送隧道）。但：
- 一个委托 token 只关联一个 issuer C，所有流量都路由到同一个 C
- 分流决策完全在 A 侧本地完成（A 从 E2E 配置通道拉取词表后更新本地路由）
- B 只需要知道"这些流量去 C"，不需要知道"属于哪个组"

因此分流模式下 `en_xxx` 同样可以**完全替代** hint。

### 2.4 安全收益量化

| 攻击面 | 当前 | en_xxx 后 |
|--------|------|-----------|
| B 通过 advertise 反推 C 的网络拓扑 | 可能（CIDR + 域名列表） | **不可能**（空 advertise） |
| B 通过 push_groups 看到组名+规则 | 完整可见 | **不可见**（不推送） |
| B 通过 hint 反推规则 | 可能（CIDR→地址, *.suffix→域名） | **不可能**（纯随机字符串） |
| B 做流量关联分析 | 可按 hint 分组关联 | 可按 en_xxx 分组（但 en_xxx 无语义） |
| B 截断/篡改配置降级攻击 | 已由 E2E fail-close 防御 | 不变 |
| 元数据/流量分析 | 不受影响（非 Tor 目标） | 不变（B 仍见时间/大小/方向） |

---

## 3. 实现路径

### 3.1 改动范围

| 文件 | 改动 | 行数估计 |
|------|------|----------|
| `crates/node/src/service/delegation.rs` | 新增 `generate_ent_id()`，签发时写入 hint_map | ~15 |
| `crates/core/src/relay/listener.rs` | B 侧：注册校验 en_ 前缀跳过路由检查；Open 路由查 entrust registry | ~40 |
| `crates/core/src/proto/message.rs` | `CtrlMessage::TokenRegister` 可选增加 ent_id 字段 | ~10 |
| `crates/client/src/connect_url.rs` | 链接解析新增 `en=` 参数 | ~15 |
| `crates/node/src/api/handlers/delegation.rs` | 签发 API：entrust 模式下跳过 effective_advertise 校验 | ~20 |
| 测试 | en_xxx 注册/路由/吊销全路径；en/ehint 共存场景 | ~80 |
| **合计** | | **~180** |

### 3.2 `en_xxx` 生成策略

```rust
/// 从 token_hash 派生出确定性的 entrust ID（推荐：确定性 → 可复现，不额外存储）
pub fn generate_ent_id(token_hash: &str) -> String {
    // 前 12 hex chars → 48 bit 空间，碰撞概率可忽略
    format!("en_{}", &token_hash[..12])
}

/// 备选：完全随机（每次签发不同 en_id，防止 B 跨 token 关联分析）
pub fn generate_ent_id_random() -> String {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("getrandom");
    format!("en_{}", base62url(&buf))
}
```

推荐使用确定性派生（方案一）—— 减少存储，便于调试时 C 侧关联，且同一个 token 在
多 B 容灾集合中注册时 en_xxx 一致（语义正确）。

### 3.3 B 侧 entrust registry

```rust
// 在 RelayListener 上新增（或复用 DelegatedRegistry 扩展一个索引）
entrust_registry: DashMap<String, String>,  // en_xxx → issuer node_id

// 注册时（handle_node_ctrl）：
fn register_delegated(&self, msg: &CtrlMessage, issuer: &str) {
    for h in &msg.hint_map {
        if h.hint.starts_with("en_") {
            // 不调用 resolve_peer()——en_xxx 是 issuer 自创的不透明 ID
            // 不存在"抢占其他节点路由词"的滥用面
            self.entrust_registry.insert(h.hint.clone(), issuer.to_string());
            continue;
        }
        // 现有路径：hint 必须能路由回 issuer
        if self.resolve_peer(&h.hint) != Some(issuer.to_string()) { ... }
    }
}

// 路由时（route_open）：
fn route_open(&self, target: &str) -> Option<Destination> {
    if let Some(issuer) = self.entrust_registry.get(target) {
        return resolve_peer(issuer.value());  // 通过 issuer node_id 找到连接
    }
    self.resolve_peer(target)  // 现有路径
}
```

### 3.4 链接格式

```
【当前】
anet://connect?server=relay-b.example.com&port=54430&account=d:alice&password=psk_...
  &fp=aa11&ehint=10.0.1.1&emode=split&entry=...

【en_xxx 后】
anet://connect?server=relay-b.example.com&port=54430&account=d:alice&password=psk_...
  &fp=aa11&en=en_abc123def456&emode=split&entry=...
```

- `en=` 参数与 `ehint=` **互斥但兼容**：旧客户端忽略 `en=`，需保留 `ehint=` 作为 fallback
- 混合部署期间：签发时同时携带 `en=` 和 `ehint=`（新客户端用 `en=`，旧客户端自动降级到 `ehint=`）
- `en=` 为空或缺失 → 回退现有 ehint 路径

### 3.5 C 签发时不再需要 push_groups

这是最关键的体验改善。签发 `en_xxx` 模式委托时：

- **不需要** 在扇出连接中勾选上送组
- **不需要** 手工填写 advertise 路由
- 签发校验跳过 `effective_advertise_of()` 调用
- hint_map 直接填入 `[{hint: "en_abc123", groups: [...]}]`

```rust
// crates/node/src/api/handlers/delegation.rs 签发逻辑改动：
if req.entrust.unwrap_or(true) {
    // entrust 模式（默认启用）：hint_map 用 en_xxx，不要求路由宣告
    let ent_id = delegation::generate_ent_id(&token_hash);
    hint_map = vec![HintEntry {
        hint: ent_id,
        groups: group_names.clone(),
    }];
    // 跳过 effective_advertise 校验
} else {
    // 传统模式（显式 opt-out）：保持现有行为
    // derive hint from effective_advertise...
}
```

---

## 4. 待讨论的问题

### 4.1 entrust 模式 vs 传统 hint 模式的切换粒度

- **per-token（推荐）**：签发时选择，token 存 mode 标记。灵活性最高。
- **per-connector**：在扇出连接上设置"此连接启用 entrust 模式"，该连接的所有委托自动用 en_xxx。
- **全局默认**：新版本默认 entrust，旧行为通过配置保留。

### 4.2 B 侧可观测性下降的缓解

`en_xxx` 后 B 的日志从有意义的 hint 变为随机字符串，排查需要 C 侧关联。缓解方案：
- C 的签发记录中保存 `en_xxx ↔ hint_map` 的映射（可复现，因为 en_xxx 从 token_hash 派生）
- B 的审计日志记录 `en_xxx → issuer node_id` 映射（已有，来自注册帧）
- 排查时在 C 侧通过 en_xxx（即 token_hash 前缀）反查即可

### 4.3 是否完全移除 push_groups 路径

`en_xxx` 落地后，E2E 委托不再需要 push_groups。但 push_groups 在以下场景仍有价值：
- **可采纳池**（Federation P1）：上游从下游采纳组，需要看到组名和规则（这是设计意图——看到的
  是"我愿意公开供采纳的组"，不是"我内部使用的 E2E 组"）
- **透明档委托**：B 代执法需要规则内容

建议：**不删除 push_groups**，而是在签发 E2E 委托时不再强制要求 push_groups 非空。
C 管理员可以自主决定一个 E2E 组是否要出现在可采纳池中。

### 4.4 防滥用考量

当前 B 用 `resolve_peer(hint) == issuer` 防止恶意节点注册不属于自己的路由词来劫持流量。
`en_` 模式下这个校验被跳过。

**安全分析**：
- `en_xxx` 是 issuer 自创的不透明 ID，**不存在"抢占其他节点路由词"的滥用面** —— 因为 `en_xxx`
  不在任何节点的路由表中，是 issuer 独享的命名空间
- B 的 entrust registry 记录 `en_xxx → issuer`，这个映射由 issuer 自己在 `token_register`
  帧中声明 —— 一个 issuer 只能把自己的 en_xxx 指向自己，不能窃取其他 issuer 的 en_xxx
  （因为 token_hash 不同，en_xxx 也不同）
- **残余风险**：恶意节点注册大量 en_xxx 填满 B 内存 → 复用现有 `PEER_*_CAPS` 上限机制
  （`crates/core/src/relay/listener.rs:115-121`）

### 4.5 P3.5 Noise_NK 前向安全性的交互

`en_xxx` 和 P3.5 Noise_NK（前向安全性握手）是**正交**的：
- `en_xxx` 解决的是 B 知道"哪些流量属于哪些权限组"的信息泄露
- Noise_NK 解决的是"B 录流量 + 事后令牌泄露 = 历史可解"的时间窗口
- 两者互补，互不阻塞

---

## 5. 实施切片（建议顺序）

1. **核心：en_xxx 生成与注册**：`generate_ent_id()` + B 侧 entrust registry + en_ 前缀跳过路由校验
2. **签发侧：跳过 effective_advertise 强制要求**：entrust 模式下的 E2E 委托签发不再要求 push_groups/advertise 非空
3. **链接：`en=` 参数**：链接格式扩展 + 客户端解析 + ehint fallback 兼容
4. **清理：可选 push_groups**：E2E 组在扇出连接中的 push_groups 从"强制"变为"可选"
5. **验收：端到端测试**：en_xxx 全路径 + en/ehint 共存 + 旧客户端降级
6. **文档**：docs/api/delegation.md 更新 + wiki 双语同步

---

## 6. 非目标（本期）

- `en_xxx` 替代透明档委托的 hint（透明档 B 必须代执法，语义上需要规则内容；不在本方案范围内）
- `en_xxx` 周期性轮换（防止 B 长期关联分析）—— 可通过重新签发委托实现，不需要协议支持
- TCP 级无缝漫游（物理不可能，容灾 = 重连级故障切换，与 en_xxx 无关）

---

## 7. E2E 现有缺陷清单（全面审查）

> 审查时间：2026-08-06。覆盖密码学层、协议层、B 侧转发、C 侧解包、客户端包装、令牌生命周期。

### 7.1 🔴 严重

#### 7.1.1 信息泄露：push_groups 明文暴露

- **定位**：`crates/core/src/relay/listener.rs:785-791`, `connector.rs:311-403`, `message.rs:22-32`
- **现象**：E2E 组的组名 + 完整规则（IP/Host）+ e2e_required 标记通过 AuthRequest 明文送到 B
- **根因**：路由可达性（advertise）和权限组内容（push_groups）绑定在同一数据结构中
- **后果**：B 的控制台"可采纳池"完整展示 C 的 E2E 权限组内容
- **修复方向**：§2 en_xxx 方案

#### 7.1.2 无前向安全性（Forward Secrecy）

- **定位**：`crates/core/src/relay/e2e.rs:80-82`
- **现象**：整个 E2E 安全模型的信任根是单个静态 PSK（psk_ token）

  ```rust
  e2e_key = HKDF-SHA256(ikm=token, salt="anet/e2e/v1", info="")
  ```

- **后果**：B 录下所有 TLS 解密后的密文流量，事后通过任何途径拿到令牌明文 → 所有历史会话全部解密
- **加重因素**：E2E 令牌本身**没有过期机制**（见 §7.2.1），一个令牌签发后永久有效，放大了 PFS 缺失的影响窗口
- **当前状态**：已在 `docs/plan/federation-p2p3.md` §8 文档化为 P3.5 Noise_NK 延伸，未实施
- **缓解**：令牌泄露窗口窄（B 本就是 TLS 终点），但不应依赖此前提

#### 7.1.3 en_xxx 缺失（已讨论）

- **定位**：`crates/node/src/api/handlers/delegation.rs:110-179`
- **现象**：E2E 委托签发强制要求 push_groups 或 advertise 非空，否则 400 报错
- **后果**：C 管理员被迫向 B 暴露权限组内容才能签发 E2E 委托
- **修复方向**：§2 en_xxx 方案

#### 7.1.4 全平台令牌无内置过期/时间控制

- **定位**：全部令牌表结构 — `relay_token`（[migrations.rs:64-71](crates/node/src/db/migrations.rs)）、
  `connector` 的 token_enc、`delegated_token`（[models.rs:233-257](crates/node/src/db/models.rs)）、
  `account` 的 `tunnel_token_hash`（[migrations.rs:49-62](crates/node/src/db/migrations.rs)）

- **现象**：**所有类型的令牌全部没有时间或用量限制字段**：

  | 令牌类型 | 用途 | 过期字段 | 用量字段 |
  |----------|------|---------|---------|
  | `relay_token` (扇入) | 下游节点接入上游 | **无** | **无** |
  | `connector.token_enc` (扇出) | 内网节点连接公网入口 | **无** | **无** |
  | `delegated_token` (委托) | 资源主直接对消费者签发 | **无** | **无** |
  | `account.tunnel_token_hash` (客户端) | 终端用户接入 | **无** | **无** |
  | `admin_ticket` (管理引导票据) | 管理会话引导 | ✅ expires_at + max_uses | ✅ 有 |

  只有 `admin_ticket` 是例外，它有完整的 7 天 TTL + max_uses 控制。

- **DB 表结构对比**：

  当前 `relay_token` 表（[migrations.rs:64-71](crates/node/src/db/migrations.rs)）：
  ```sql
  CREATE TABLE relay_token (
      id           TEXT PRIMARY KEY,
      token_hash   TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
      remark       TEXT NOT NULL DEFAULT '',
      last_used_at TEXT,        -- ← 仅追踪最后使用时间，不限制
      created_at   TEXT NOT NULL DEFAULT (datetime('now'))
      -- ❌ 无 expires_at, max_uses
  );
  ```

  当前 `account` 表（[migrations.rs:49-62](crates/node/src/db/migrations.rs)）：
  ```sql
  CREATE TABLE account (
      id                TEXT PRIMARY KEY,
      ...
      tunnel_token_hash TEXT,
      enabled           INTEGER NOT NULL DEFAULT 1,  -- ← 只有启/禁用开关
      ...
      -- ❌ token 无独立的 expires_at / max_uses
  );
  ```

  当前 `delegated_token` 表（[migrations.rs:239-261](crates/node/src/db/migrations.rs)）：
  ```sql
  CREATE TABLE delegated_token (
      id           TEXT PRIMARY KEY,
      ...
      mode         TEXT NOT NULL DEFAULT 'dedicated',
      -- ❌ 无 expires_at / max_uses
  );
  ```

- **后果**：
  - **扇入令牌（relay_token）**：签发后永久有效，若泄露则攻击者可长期作为下游节点接入
  - **扇出令牌（connector）**：C 连接 B 的 psk_ 永久有效，无法做周期性轮换
  - **委托令牌（delegated_token）**：见 §7.1.2 的加重因素 — PFS 缺失 + 永久有效 = 历史流量全量风险
  - **客户端令牌（account tunnel_token）**：终端用户凭据泄露后无限期可用
  - **所有场景**：唯一的防御是管理员**手动吊销**（删除记录）—— 这依赖管理员及时发现泄露

- **修复方向**：
  - 所有令牌表增加 `expires_at` 列（可空，空 = 永不过期，兼容现状）
  - 委托令牌增加 `max_uses` 列（可空，面向 P3.5 一次性 ticket）
  - B 侧认证时增加过期校验（本地令牌 validator + 委托注册表均可加）
  - 不影响现有令牌（默认无过期），新签发的令牌可选择设置过期时间
  - 与 admin_ticket 模型保持一致

### 7.2 🟡 中等

#### 7.2.1 A 侧 E2E Open 的 groups 字段语义不精确

- **定位**：`crates/client/src/client.rs:228`
- **现象**：客户端 seal_open 时 groups 恒为空数组 `&[]`
- **C 侧处理**：`crates/node/src/service/delegation.rs:305-309` — 空 groups 回填为令牌的全部组
- **语义问题**：A 的每个 Open 都以"该 token 的全部组"身份发起，而不是"匹配该连接的那一个组"。
  如果令牌挂了多个权限组（如"开发组"和"运维组"），A 访问一个开发组规则就能通过 ACL（运维组也可能命中）
- **安全影响**：限于同一 issuer 的 token 内部，不跨 token / 不跨 issuer，但语义不够细粒度
- **修复方向**：客户端在 seal_open 时根据目标地址匹配本地路由表，填入对应的 groups

#### 7.2.2 管理授权票据 TTL 过长且无会话级轮换

- **定位**：`crates/node/src/relay_auth.rs:27-28`

  ```rust
  pub(crate) const RELAY_TICKET_TTL_SECS: i64 = 7 * 24 * 3600;  // 7 天
  pub(crate) const RELAY_TICKET_MAX_USES: i32 = 10000;
  ```

- **现象**：管理票据通过 E2E 配置通道下发（不经过 B），但 TTL 长达 7 天、可用 10000 次
- **后果**：如果 A 的机器被攻破，攻击者在 7 天内可通过票据直接操作 C 的管理 API
- **缓解因素**：票据通过 E2E 通道密封下发，B 不可见；吊销扇出令牌可链式失效
- **修复方向**：缩短 TTL（如 1 小时）、减少 max_uses、增加 per-session ticket refresh 机制

#### 7.2.3 e2e_required 标记变更无通知机制

- **定位**：`crates/core/src/relay/connector.rs:783-789` (discipline 3 fail-close)
- **现象**：C 管理员修改组的 e2e_required 标记后，`DelegationEngine::refresh_groups()` 更新缓存，
  但不会吊销已签发 token 或踢出已有会话
- **后果**：
  - 取消 e2e_required：已连接 A 继续走 E2E 路径，新建连接的 A 走透明路径（A 不知道变化）
  - 新增 e2e_required：已连接 A 的透明流量不再被 C fail-close 保护（因为 token 签发时该组不是 e2e_required）
- **修复方向**：e2e_required 变更时触发 token 重评估或客户端通知

#### 7.2.4 B 侧委托注册表依赖 issuer 已推送 push_groups

- **定位**：`crates/core/src/relay/listener.rs:947-960` — `register_delegated()` 的 groups 交集逻辑
- **现象**：注册时 token 的 groups 必须与 issuer 的 pushed groups 取交集；push_groups 为空 → 注册被拒绝
- **后果**：即使签发了委托令牌，如果 issuer 的扇出连接没有推送 push_groups，注册帧也会被 B 拒绝
- **关联**：与 §7.1.1 和 §7.1.3 同源——控制面授权与数据面路由耦合
- **修复方向**：§2 en_xxx 方案一并解决（en_xxx 模式下跳过 groups 交集校验）

### 7.3 🟢 低等 / 设计改进

#### 7.3.1 kid 空间仅 32 bit

- **定位**：`crates/core/src/relay/e2e.rs:85-87`

  ```rust
  pub fn kid_of(token_hash: &str) -> &str {
      token_hash.get(..8).unwrap_or(token_hash)  // 8 hex chars = 32 bit
  }
  ```

- **现象**：kid 取 token_hash 前 8 个 hex 字符（32 bit 空间）
- **理论风险**：同一 B 上签发大量 token 时 kid 碰撞概率非零（2^16 = 65536 后有 50% 碰撞概率）
- **实际影响**：碰撞导致 C 用错误 e2e_key 解密 blob → auth 失败 → OpenFail（DoS，非安全漏洞）
- **实际概率**：单个 issuer 的 token 数量远小于 65536，实践中概率极低
- **修复方向**：如果担心 → kid 扩到 12 hex chars（48 bit）或 16 hex chars（64 bit）

#### 7.3.2 E2E 配置通道拉取失败无用户通知

- **定位**：`crates/client/src/client.rs:1667-1669`

  ```rust
  Err(e) => {
      warn!(..., "delegated config fetch failed — keeping catch-all routes");
      return;
  }
  ```

- **现象**：分流模式下配置拉取失败 → 静默保持全量路由（专线行为）
- **安全性**：正确（退到更保守的行为）
- **用户体验**：A 不知道配置拉取失败，所有流量都走隧道
- **修复方向**：客户端 UI 通知（灵动岛 / 托盘图标状态变更）

#### 7.3.3 WASM 平台 CSPRNG 未验证

- **定位**：`crates/core/src/relay/e2e.rs:127` — `rand::random()` 用于 blob nonce 和 chan_salt
- **现象**：`rand` crate 在 WASM 目标上默认使用 `OsRng`，如果未来支持 WASM 客户端需确认 CSPRNG 可用性
- **当前影响**：无（客户端不支持 WASM）
- **修复方向**：如果引入 WASM 目标，增加 CSPRNG 可用性检查或使用 `getrandom` 的 WASM 后端

#### 7.3.4 ChannelCipher seq 无回卷保护（理论）

- **定位**：`crates/core/src/relay/e2e.rs:199-203`
- **现象**：`send_seq: u64` 和 `recv_seq: u64` 无限递增，无回卷检查
- **理论风险**：seq 回卷导致 nonce 重用（AES-GCM 灾难性后果）
- **实际影响**：u64 × 16KB = 2^58 TB，单个信道生命周期内不可能达到
- **修复方向**：文档化"信道生命周期内 seq 不得回卷"；在 `seal()` / `open()` 中加 saturating 检查

---

## 8. 令牌生命周期统一设计（建议）

### 8.1 现状

当前系统中只有 `admin_ticket` 有过期和用量控制。四种主要令牌类型全部缺失此能力。

### 8.2 建议的统一模型

```sql
-- 为四种令牌增加过期控制（向后兼容：DEFAULT NULL = 永不过期）
ALTER TABLE relay_token     ADD COLUMN expires_at TEXT;   -- NULL = never
ALTER TABLE relay_token     ADD COLUMN max_uses   INTEGER; -- NULL = unlimited
ALTER TABLE delegated_token ADD COLUMN expires_at TEXT;
ALTER TABLE delegated_token ADD COLUMN max_uses   INTEGER;
ALTER TABLE account         ADD COLUMN tunnel_expires_at TEXT; -- 仅 tunnel_token_hash 的过期

-- connector 的 token 是内部生成的，不需要用户可见的过期控制
-- 但可考虑增加 connector.token_rotated_at 用于自动轮换
```

### 8.3 验证点

- **B 侧**：
  - `DbTokenValidator::validate_node()` — relay_token 过期检查
  - `DbTokenValidator::validate_client()` — account tunnel_token 过期检查
  - `register_delegated()` — delegated_token 过期/用量检查（注册帧携带或 B 侧从注册信息中获取）
- **C 侧**：
  - `DelegationEngine` — e2e_unwrap 前检查 token 是否过期（本地判断，不依赖 B）
- **UI**：
  - 签发时可选设置过期时间（默认不限制，兼容现状）
  - 列表展示过期状态（有效/即将过期/已过期）

### 8.4 实施优先级

| 令牌类型 | 优先级 | 理由 |
|----------|--------|------|
| delegated_token | **高** | PFS 缺失 + 永久有效 = 最大风险窗口 |
| relay_token | 中 | 下游节点接入，泄露面小于委托令牌 |
| account tunnel_token | 中 | 终端用户凭据，可通过 disable 代替 |
| connector token | 低 | 内部生成，管理面已可删除 connector 记录 |

---

## 9. 非目标（本期）

- `en_xxx` 替代透明档委托的 hint（透明档 B 必须代执法，语义上需要规则内容；不在本方案范围内）
- `en_xxx` 周期性轮换（防止 B 长期关联分析）—— 可通过重新签发委托实现，不需要协议支持
- TCP 级无缝漫游（物理不可能，容灾 = 重连级故障切换，与 en_xxx 无关）
- Noise_NK 前向安全性握手（已在 P3.5 延伸中文档化，本期不实施）
- 一次性 ticket 委托的 max_uses（在 P3.5 文档化，可在令牌生命周期统一设计中顺便支持）
- Connector token 自动轮换（长期优化，非本期）

---

## 10. 实施记录（2026-08-06，已落地）

### 10.1 en_xxx 主体方案（§2/§3/§5 全部切片）

- **生成与注册**：`core::relay::e2e::{ENTRUST_PREFIX, entrust_id_of(token_hash)}`（`en_<哈希前12hex>`
  确定性派生）；B 侧 entrust 注册表（`en_→签发者`，`en_` 前缀 hint 免 `resolve_peer` 校验、
  无推送组时组名交集跳过（§7.2.4 一并解决，声明组仅观测、透明档 ACL 空 fail-closed）、
  `route_open` 先查 entrust、随会话清空/吊销即断、`MAX_ENTRUST_PER_ISSUER=1024`）。
- **签发侧**：`issue_token` 对含 e2e_required 组的令牌自动前置 entrust 词；advertise 派生
  legacy hint 降级为旧端可选回退——**原 400 强制（§1.2/§7.1.3）已删除**。
- **协议**：`PROTOCOL_VERSION=4` + `PROTOCOL_VERSION_ENTRUST` 门槛；C 注册同步对 <v4 上游
  自动剥离 en_ hint（其余条目照常注册）。
- **链接**：`en=` 参数（core link / aglink.js 双底座），`ehint` 保留作旧端回退；客户端
  `DelegatedOpener` 按当前会话 `server_version()` 选词（v4+ 用 en、旧端用 ehint）。
- **验收**：`crates/node/tests/federation_p3_test.rs::p3_entrust_zero_disclosure`——
  无 push_groups/无 advertise 签发 201、B 可授权池零泄露断言、entrust 路由、A 经盲转到达
  网段、吊销清表；旧 p3 测试更新为 entrust+legacy 共存。
- **混合部署语义**：新 C→旧 B 注册剥离 en_ hint（E2E-only 令牌注册失败带因）；新 A→旧 B
  用 en_ 词被 B fail-closed（正确保守行为）；双侧全新即零泄露。

### 10.2 §7 缺陷批次

| 条目 | 状态 | 落地 |
|------|------|------|
| §7.1.1 push_groups 明文泄露 | **已修** | en_xxx 后 E2E 委托不再要求 push_groups/advertise（§4.3 决策：push_groups 保留给可授权池/透明档，E2E 组是否入池由 C 管理员自主） |
| §7.1.2 无前向安全性 | 未做（P3.5 非目标） | Noise_NK 延伸，见 §9；令牌生命周期（§8）已收窄暴露窗口 |
| §7.1.3 签发强制 push/advertise | **已修** | 同上（400 删除） |
| §7.1.4 令牌无过期 | **已修** | §10.3 |
| §7.2.1 A 侧 groups 恒全集 | **已修** | `DelegationConfig.groups` 命明明细（serde 兼容旧签发端）；客户端配置通道逐组编译匹配器，分流档 seal 命中组名，未命中回退继承全集 |
| §7.2.2 票据 7 天/10000 次 | **已修** | TTL 1 小时 / max_uses 100（按握手/配置拉取即铸即用，操作无感） |
| §7.2.3 e2e_required 变更无通知 | **语义确认 + 文档化** | 收敛链已覆盖：C 引擎缓存随 config_version 热更（fail-close 对新增标记即时生效——明文 Open 硬拒是安全且可感知的信号）；上送组内容变化触发扇出自动重连再推，采纳镜像 watcher 跟随；A 侧分流词表下次拉取收敛。残余仅「A 会话中途无理由断流」，语义上 fail-closed 正确，不再单独做通知协议 |
| §7.2.4 注册依赖 push_groups | **已修** | entrust 令牌跳过组名交集（见 §10.1） |
| §7.3.1 kid 32bit | **已修** | kid 扩 12 hex（48bit）；三处查找前缀唯一兼容旧 8 位 kid（DB LIKE 前缀 / B 校验前缀感知 / 引擎 key_entry），歧义 fail-closed |
| §7.3.2 配置拉取失败无通知 | **已覆盖（既有机制）** | 桌面端「分流未生效」徽标（split 已连接但规则仍含 0.0.0.0/0 兜底即拉取失败态）已上线；失败回退全量是安全语义，不再加新通知通道 |
| §7.3.3 WASM CSPRNG | **已文档化** | `seal_open` 注释标注（当前无 WASM 客户端） |
| §7.3.4 seq 回卷 | **已修** | `ChannelCipher::seal/open` 返回 Result + u64::MAX 饱和检查（通道死亡优于 nonce 重用） |

### 10.3 §8 令牌生命周期统一设计（全量落地）

- **DB v15 `token_lifecycle`**：`relay_token`/`delegated_token` +`expires_at`/`max_uses`/
  `used_count`，`account` +`tunnel_expires_at`；NULL = 永不过期/不限（存量令牌全兼容）。
- **统一助手**（`db::` 再导出）：`normalize_expiry`（RFC3339/datetime-local → UTC Z 秒级）、
  `expiry_active`（解析失败 fail-closed）、`uses_exhausted`。
- **执法点**：扇入认证 `check_relay_token`（过期/用尽按未知令牌拒 + 命中累 used_count）、
  账号隧道 `validate_client` 查 `tunnel_expires_at`、委托注册同步死令牌跳过（状态
  expired/exhausted）+ `DelegationEngine` `alive()` 门（e2e_unwrap 硬拒、配置通道/管理桥关闭；
  用量热路径内存计数、`refresh_keys` 刷回 DB 保重启连续）。
- **偏差说明**：§8.3 设想的「B 侧注册帧携带过期信息」未做——C 侧注册同步已保证死令牌
  不上送，B 无需协议扩展；一次性 ticket 的完整语义仍属 P3.5（列已备）。
- **API/UI**：委托签发/扇入令牌/账号三处创建可选过期+用量（三态更新），列表统一
  `lifecycle` 状态徽标（active/expiring<72h/expired/exhausted）。
- **未做**：CLI `--expires` 标志、TUI 生命周期列、connector token 轮换（§8.4 低优先级）。
