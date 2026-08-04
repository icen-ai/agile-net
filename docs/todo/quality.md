# 全项目质量审查（死代码 / 重复 / 不优雅 / 性能）

> 审计范围：`crates/core` + `crates/node` + `crates/client` + `apps/desktop`  
> 审计时点：功能开发基本完成后的极速迭代收尾  
> 原则：按**置信度 × 收益**排序；不改业务语义的清理优先于大重构

---

## 0. 总览

| 类别 | 高 | 中 | 低 | 说明 |
|------|----|----|----|------|
| 死代码 / 近死代码 | 2 | 3 | 2 | 含 `#[allow(dead_code)]` 与无调用封装 |
| 重复代码 | 4 | 5 | 3 | 跨 crate 工具函数、双份校验/限流、两端 UI 助手 |
| 不优雅 / 可维护性 | 3 | 6 | 4 | 巨型文件、API 分层、参数链、图标双份 |
| 性能 / 资源 | 2 | 4 | 3 | 主窗轮询、`sysinfo` 热路径、签名对比 |

**安全债对照**（`docs/todo/attacks.md`）：ATK-001/002/003/005/006/008/010/012/013/014 主路径已修；本审查不再展开已关闭项，仅列残留不一致。

---

## 1. P0 — 建议本轮就清（小改动、高收益或语义风险）

### 1.1 管理密码策略分叉（安全一致性）

| 位置 | 策略 |
|------|------|
| `node/api/handlers/auth.rs` `validate_admin_credentials` | ≥10 + 大小写 + 数字 |
| `node/api/handlers/admins.rs` **本地同名私有函数** | 同上（**字面复制**） |
| `client/api.rs` `init_password` | ≥10 + 大小写 + 数字 |
| `apps/desktop/src/roles.rs` `set_web_password` | **仅 ≥10，无复杂度** |

**问题**：桌面「Web 远程面」改密可设弱口令；与 client Web API 首设密码策略不一致。  
**建议**：抽出单一 `password_policy::validate_admin_password`（或复用 auth 版），`roles::set_web_password` 与 `init_password` 共用；`admins.rs` 删除私有副本，统一 `use` auth 的 `pub(crate)` 实现。

### 1.2 双份 `LoginRateLimiter`（已修泄漏但仍双实现）

- `crates/node/src/api/mod.rs`：可配置阈值 + 惰性 retain(>1024)
- `crates/client/src/api.rs`：硬编码 5/5/15 + **同一套** retain 逻辑（~90 行拷贝）

**建议**：抽到 `agile_net_core` 或极薄 `agile_net_auth_util` 公共模块；client 用固定默认，node 保留 `with_config`。避免以后一边修一边漏。

### 1.3 死封装：`Database::create_relay_token`（无任何调用方）

```text
crates/node/src/db/accounts.rs
  create_relay_token          ← 全仓库零引用（除定义）
  → create_relay_token_full
  → create_relay_token_with_group
  → create_relay_token_with_quota  ← 真实入口
```

生产路径一律走 `*_with_quota` / `*_with_group` / `*_full`。  
**建议**：删除最外层 `create_relay_token`；评估是否合并为「一个 builder / 一个带默认参数的入口」，消灭四级转发 + 多处 `#[allow(clippy::too_many_arguments)]`。

### 1.4 `sha256_hex` 五处私有实现

| 位置 | 可见性 | 用途 |
|------|--------|------|
| `node/db/mod.rs` | `pub` | 权威（token/jti 哈希） |
| `core/relay/listener.rs` | 私有 | 监听侧 token 哈希（与 node 语义重叠） |
| `desktop/download.rs` | 私有 | 制品钉值 |
| `desktop/sync.rs` | 私有（旁路还有 `hex()`） | S3 签名 |
| `node/tool/doctor.rs` | 私有 | wintun 钉值校验 |

**建议**：

- 数据面/控制面哈希：`core` 导出 `util::sha256_hex`（或 `crypto::sha256_hex`），node/db 与 listener 共用。  
- 桌面 download/doctor/sync 可继续本地 3 行实现（依赖边界清晰），但 doctor 与 download 的 **WINTUN 钉值常量**必须单源（注释已写「与 subscription 同步」，仍是双份字符串风险）。

### 1.5 主窗轮询无 `visibilitychange` 暂停（性能）

| 面 | 行为 |
|----|------|
| `tray.js` / `float.js` | 已有 hidden → `stopLoops` |
| `apps/desktop/ui/app.js` | **10s / 2s / 30s 永久 setInterval**，后台仍刷节点/代理/订阅/系统代理/TUN/规则/Hero |

**建议**：与 tray 对齐——`document.hidden` 时 clear，visible 时立即 tick + 重启 interval。日志页 `app-logs.js` 的 1s timer 已有 `stop()`，确认切页/隐藏时调用链完整。

---

## 2. P1 — 重复与不优雅（1–2 次迭代内）

### 2.1 `default_control_scope` / `default_scope` ×4

四处均为 `|| "full".into()`：

- `core/proto/message.rs`
- `node/db/models.rs`
- `node/auth/jwt.rs`
- `node/api/handlers/relay_tokens.rs`

serde 默认函数不能跨 crate 直接当 `default =` 路径共用时，至少在 **node 内**抽 `crate::defaults::control_scope()`，proto 侧保留一份并注释「默认值契约 = full」。

### 2.2 `default_true` 双份（desktop）

- `apps/desktop/src/roles.rs`
- `apps/desktop/src/custom_rules.rs`（**已被引用**，非死代码）

可接受为 serde 惯用写法；若 desktop 再增加第三处，再抽 `serde_defaults` 小模块。

### 2.3 UI 助手双份（管理端 vs 桌面）

| 符号 | 桌面 | 管理端 |
|------|------|--------|
| `esc` / `ahelp` / `fmtBytes` / `toast` | `app-core.js` | `node/ui/app.js` |
| `agSelectEnhance` / `agTabsBind` | `app-core.js` | `node/ui/app.js` 内嵌拷贝 |
| 图标表 | `icons.js` + `AgIcon` | `app.js` 顶部 `ICONS` + `ic()` |

**样式/图表**已按 AGENTS.md 共享（`tokens.css` / `components.css` / `agchart.js`）。  
**JS 行为层尚未沉淀**：`agSelect*` / `agTabsBind` / `esc`/`ahelp` 与 icons 仍双维护。

**建议沉淀顺序**（第二次需要才抽的规则已满足）：

1. `apps/desktop/ui/shared-ui.js`（或拆 `agsel.js` + `icons.js` 管理端 `include_str!`）  
2. 管理端 `mod.rs` 增加 `/ui/shared-ui.js`、`/ui/icons.js`  
3. `node/ui/app.js` 删内嵌副本，只留页面逻辑  

注意：管理端 HTML 仍有 `onclick="switchView(...)"`（桌面 CSP 禁止内联）。管理端无 Tauri CSP 故可跑，但与「事件委托统一」规范不一致——中长期改为与桌面相同的显式绑定。

### 2.4 巨型文件（可维护性）

| 文件 | 约行数 | 建议 |
|------|--------|------|
| `node/tool/doctor.rs` | ~2112 | 按节拆 `doctor/ports.rs` `sysproxy.rs` `tun.rs` … + `mod.rs` 编排 |
| `client/src/lib.rs` | ~1911 | 连接/隧道/规则/hosts/轮询分模块（hosts 已部分内聚） |
| `node/src/cli.rs` | ~1561 | 按子命令文件拆（rule/group/account/…） |
| `node/ui/app.js` | ~1385 | 视图拆分对齐桌面 `app-*.js` |
| `desktop/ui/app-views.js` | ~1053 | 可再按 connect/nodes/routes 切 |
| `desktop/ui/app-subscription.js` | ~1006 | 可接受，注意签名对比勿回退 |

### 2.5 `#[allow(clippy::too_many_arguments)]` 簇

- `db/accounts.rs` / `db/connectors.rs`：创建 API 参数膨胀  
- `core/relay/connector.rs` / `listener.rs`：会话装配参数  

**建议**：引入轻量 config 结构体（`CreateRelayToken` / `ConnectorSpawn`），从根上消 allow，而不是继续叠 `with_*` 包装层。

### 2.6 `system_stats()` 每次 status 新建 `System`

`node/api/handlers/node.rs`：`status` → `system_stats()` → `System::new()` + `refresh_memory` + `refresh_processes`。  
管理端概览 **15s 轮询**会打这条路径。

**建议**：进程级 `Lazy`/`Mutex<System>` 复用，或降低字段刷新频率；CPU 需两次 refresh 才有意义时注明语义，避免「看起来有 CPU% 实际恒 0」的假指标。

### 2.7 近死 / 豁免 dead_code

| 符号 | 说明 |
|------|------|
| `roles::verify_web_password` | 仅 `DesktopWebAuth` trait 调用；`#[allow(dead_code)]` 可改为 `pub(crate)` 或内联到 trait impl |
| `SystemHosts::with_path` | 仅 `#[cfg(test)]` 使用；应用 `#[cfg(test)]` 而非 `allow(dead_code)` |
| `DoctorStatus::Unsupported` 路径 / `SysProxy::Unsupported` | 平台 cfg 需要；allow 合理，可加注释保留 |

### 2.8 `create_account` vs `create_account_with_admin`

薄包装仍被测试与少数路径使用，**保留合理**；不必强行删除。与 relay token 四级链不同。

---

## 3. P2 — 性能与前端体验

### 3.1 变更检测（已做 vs 缺口）

**已做**：`agchart` sig、Hero 功率/清单、`SubTraffic` 总量、`node/ui` 多处 `dataset.sig`。  
**缺口**：

- 部分列表仍整表 `innerHTML = map(...).join('')`（`app-logs` 连接表、管理端 accounts 等）——高频 1s 路径优先做签名短路。  
- `JSON.stringify` 大对象作 sig（管理端 connector 列表等）：列表变长时 CPU 可见；可改为「id|updated_at|status」拼接或长度+hash。

### 3.2 日志页 1s 轮询

`app-logs.js`：连接/日志/命中均 1s。内核未运行时仍 invoke 失败吞掉——建议失败退避（2s→5s）或依赖事件推送，减少空转 IPC。

### 3.3 `client/lib.rs` clone 密度

约 78 处 `clone()`、36 处 `to_string`/`to_owned`（单文件）。多数为 Arc/String 跨 await 必要拷贝；拆模块时顺带：

- 热路径优先 `Arc<str>` / 共享 `Arc<ClientState>`  
- 避免在 5s 心跳闭包内重复克隆大 `params`

### 3.4 服务端固定 interval

- connector 状态 2s、流量 2s、清理 60s、证书 24h——合理。  
- 与前端轮询叠加时注意：前端 5–15s 拉 status 已含 connector 快照，无需再加密度。

---

## 4. P3 — 风格与长期债

1. **图标双表**：桌面 `icons.js` vs 管理端 `ICONS`——漏同步会导致一侧空 SVG。  
2. **管理端内联 onclick**：与桌面 CSP 哲学不一致。  
3. **tray `fmtRate` vs 主窗速率展示**：单位逻辑可共用。  
4. **`extractors.rs` `result_large_err`**：axum Rejection 体积问题，可接受；长期用自定义小错误枚举。  
5. **attacks.md 文档滞后**：部分「未修」描述与代码不符（如 WS 已 scope 校验、refresh 已 limiter）——审查关闭时同步文档状态，避免假警报。

---

## 5. 推荐落地顺序（可执行 backlog）

| 序 | 项 | 预估 | 风险 |
|----|----|------|------|
| 1 | 统一密码策略 + 删 admins 副本 + 修 `set_web_password` | S | 低（收紧校验） |
| 2 | 主窗 `visibilitychange` 停轮询 | S | 低 |
| 3 | 删 `create_relay_token` 死封装；`with_path` 改 `cfg(test)` | S | 低 |
| 4 | `sha256_hex` 提升到 core；WINTUN 钉值单源 | M | 中（依赖方向） |
| 5 | 合并 `LoginRateLimiter` | M | 中 |
| 6 | 沉淀 shared JS（agsel/tabs/esc/icons）到管理端 | M | 中（回归 UI） |
| 7 | `system_stats` 复用 System | S | 低 |
| 8 | doctor / client lib / cli 拆分 | L | 中（纯移动，测全量） |
| 9 | 列表 sig 优化 + 日志退避 | M | 低 |
| 10 | 同步 `attacks.md` 修复状态 | S | 无 |

---

## 6. 明确「暂不动」

- **业务正确的重复**：`constant_time_eq` 单源在 `core/relay`（好）；测试里重复 mock validator 可接受。  
- **平台 cfg 分支**的 `allow(dead_code)`（`SysProxy::Unsupported`）。  
- **serde `default_true`** 两处小函数（直至第三处）。  
- **为拆而拆**超过 1.5k 行的稳定模块若无近期改动需求，可排在功能冻结后。

---

## 7. 验证清单（清理后）

```bash
rtk cargo test --workspace
# 演示进程占用 exe 时：
CARGO_TARGET_DIR=target/ci rtk cargo test --workspace
cargo check --manifest-path apps/desktop/Cargo.toml
```

手动：管理端改密 / 桌面 Web 远程面设密 / 弱口令应一致拒绝；主窗切后台 CPU/IPC 下降；tray/float 行为不变。
