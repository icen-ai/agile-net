# 阶段 2 安全性审计发现（按协议阶段 × STRIDE）

> 逐格执行说明：矩阵（`interaction-matrix.md` §3）每一格至少经过以下一种方法的检查：
> 精读触发路径源码 / 直接引用现有对抗性集成测试 / 构造推理链落至代码行。
> 未发现问题的格子在本文件 §9 显式标注「已检查，未发现问题」及方法，不留空默认安全。
> 严重度口径：Critical=直接拿权/解密；High=绕过核心安全承诺或单包可触发资源失控；
> Medium=有边界条件的执法缺口/资源放大；Low=文档化取舍或影响受限。

## 发现索引

| ID | 严重度 | 一句话 | STRIDE | 状态 |
|---|---|---|---|---|
| F1 | **High** | E2E Open 信封可跨信道重放，攻破「重放不得产生应用层重复变更」纪律 | 重放/篡改 | **已修复+测试**（chan_salt 一次性消费） |
| F2 | **High** | connector 侧入站 Open 无并发上限（listener 有 256，不对称） | DoS | **已修复+测试**（对称信号量） |
| F3 | **Medium** | Open 转发无跳数上限：互指路由（0.0.0.0/0 转售合法存在）可成环放大 | DoS | **已修复+测试**（hops+MAX_OPEN_HOPS=8） |
| F4 | **Medium** | listener `auth_attempts` 表无过期清理，IPv6 轮换源可缓慢膨胀内存 | DoS | **已修复**（均摊清扫） |
| F15 | **Medium** | direct 入口 × E2E 组签发不拒绝但数据路径断裂（信封终结于扇出会话） | 可用性/签发校验 | **已修复+测试**（issue_token 拒绝该组合） |
| F5 | Low | mux WindowUpdate 无界加许可（仅自害） | — | 文档化 |
| F6 | Low | 同会话恶意 peer 可伪造 Close/OpenFail 杀本地信道（等同 RST） | DoS | 接受 |
| F7 | Low | 带宽诊断在 PeerAcl 前拦截（设计如此，无路由能力，1GiB/请求封顶） | 信息泄露面 | 接受+文档化 |
| F8 | Low | 恶意中继可向签发者面板喂伪造 ConsumerSessionReport（仅显示层） | 仿冒 | 接受+文档化 |
| F9 | Low/取舍 | 明文档（transparent）中继可见明文与元数据——设计取舍，需人类拍板 | 信息泄露 | 决策项 |
| F10 | Low | QR/图片解码面（rqrr+image，20MB 封顶，纯 Rust） | 攻击面 | 接受 |
| F11 | Info | device.key Windows 侧未显式设 ACL（依赖 profile ACL，代码已注明） | — | 接受 |
| F12 | Low | 委托哈希占位 squat（会话域、fail-closed 空_acl，代码已文档化） | DoS | 接受 |
| F13 | Low | 持令牌的恶意中继可在 transparent 档冒充消费者（bearer 语义+设备门控兜底）；Single 档可踢真消费者 | 仿冒 | 决策项 |
| F14 | Info | kid 48-bit 前缀（仍需 32B 密钥才能解封，无实际 brute-force 面） | — | 接受 |

---

## F1 [High] E2E Open 信封跨信道重放

**组合**：D3/D5（消费者→中继→签发者 / E2E / 中继恶意）
**触发路径**：
- `crates/core/src/relay/connector.rs:846` `hooks.e2e_unwrap(env)` →
- `crates/core/src/relay/e2e.rs:193 open_open()`：解封成功即接受，**无任何「该信封已被使用」的记忆** →
- `e2e.rs:220` `derive_chan_key(e2e_key, chan_salt)`：同一信封恒得同一 `chan_salt` →
- `e2e.rs:234 ChannelCipher::new`：每条信道的收发序列号**各自从 0 起**。

**攻击链**（恶意中继 R，无需任何密钥）：
1. R 正常转发消费者 C 的 E2E Open（含密封 blob）与后续数据记录（密文块），完整录下；
2. 信道结束后，R 向签发者 I **重放同一 Open 帧**（channel_id 换新）——blob 是真实密封的，I 解封成功；
3. 两条信道派生**相同 chan_key**，R 再把录下的密文记录按序重放到新信道——序列号从 0 重新对齐，
   AEAD 校验全部通过；
4. I 的本地目标连接收到**原始请求流的完整重放**（如未鉴权指令、非幂等写入）。

**与设计纪律的冲突**：`e2e.rs:22-24` 明文写着「the relay cannot forge new ciphertexts but can replay
old ones, which **must never surface as duplicated application-level mutations**」——信道内防重放
（严格序列）达成了，但**跨信道**场景违反该承诺。现有测试 `replayed_record_rejected`（e2e.rs:531）
仅覆盖信道内重放。
**可利用性**：需要位置合适的中继（正是本产品威胁模型的一等公民）；对幂等流量无害，
对指令型/写型协议是真实完整性攻击。
**现状是否已缓解**：否（审计时）。
**修复**（函数级）：签发端记住「已见 chan_salt」——`DelegationEngine` 的 `KeyEntry` 增加每令牌
salt 去重集（上限 fail-closed），`e2e_unwrap` 解封后登记，重复盐直接拒绝；128-bit 随机盐使
合法碰撞概率为零，去重集语义即「一信封一次性」。
**回归测试**：同一信封二次 unwrap 必须失败；不同信封（新盐）正常。

## F2 [High] connector 侧入站 Open 洪泛无上限

**组合**：N8（上行→扇出反向 Open / 上行被攻破或持令牌恶意节点）
**触发路径**：`crates/core/src/relay/connector.rs:637-652`——维护循环 `open_rx.recv()` 每帧直接
`tokio::spawn(handle_open…)`，无信号量；`handle_open` 内 `accept_channel`（mux.rs:544，无上限插入）
+ 无界 TCP 拨出。对照 listener 侧同一威胁有
`MAX_INBOUND_OPENS_PER_SESSION=256`（listener.rs:1436、1866）。
**威胁**：持有效 relay token 的恶意/被攻破上行可并发泵入上万 Open——每 个 spawn 任务 + 每信道
128 深度 mpsc + 每任务一个出站 TCP 连接尝试 → 任务/FD/内存耗尽，整进程数据面瘫痪（影响该节点
**所有**角色，含其它 connector 与本地代理）。
**现状是否已缓解**：否（listener 有、connector 无——实现不对称）。
**修复**：connector 维护循环加同款 `Semaphore(MAX_INBOUND_OPENS_PER_SESSION)`，超限回 OpenFail。
**回归测试**：伪上游灌 300 个并发 Open，断言并发桥接任务数被限、超限信道收到 OpenFail。

## F3 [Medium] Open 转发无跳数上限（多跳环路放大）

**组合**：N6/N7（恶意/误配下行虚假 advertise；客户端隧道 0.0.0.0/0 转售）→ 与 multihop 报告 MH-1 双重标注
**触发路径**：`proto/message.rs:176 OpenChannel` 无 hop 字段；转发点三处逐字透传：
listener.rs:2159 `open_channel_full`、connector.rs:1032（peer_router 链式）、connector.rs:1069（客户端隧道 opener）。
**威胁**：A、B 互 advertise 覆盖对方目标（含合法存在的全量路由转售 0.0.0.0/0），一个 Open 在
A↔B 间逐跳嵌套转发。每跳消耗 1 permit（256/会话封顶）+1 信道 +1 任务，`open_channel` 10s 超时
级联回卷；攻击者可持续保持两节点各 256 permit / 512 信道满载并制造帧风暴。有界但真实的双节点
DoS，且随环上节点数放大。
**现状是否已缓解**：部分（per-session 上限兜住了无界增长，但没有协议级环阻）。
**修复**：`OpenChannel` 增加 `hops` 字段（serde default，pre-launch 无兼容包袱），每转发点 +1，
超过 `MAX_OPEN_HOPS=8` 回 OpenFail。
**回归测试**：构造 A→B→C→A 三节点互指环（真实多跳拓扑），断言首 Open 在 8 跳内收到 OpenFail
而非嵌套增长。

## F4 [Medium] listener 认证失败表无过期清理

**组合**：M 面/数据面入口（任意 IP）
**触发路径**：`listener.rs:1085 record_auth_failure`：`DashMap<IpAddr,(u32,Instant)>` 只在
该 IP **再次失败**时翻窗口、在**成功**时删除；永不后台清理。`delegated_tombstones` 有 retain
清理（listener.rs:1512），此表没有。
**威胁**：IPv6 海量源轮换（每条目需完成一次 TLS 握手，攻击成本存在但可持续）→ 长运行期内存
单调增长（每条目 ~100B，百万级 ≈ 100MB）。
**修复**：`record_auth_failure` 内偶发（如每 1024 次插入）`retain` 清掉窗口外条目，均摊 O(1)。

## F15 [Medium] direct 入口 × E2E 组：签发不拒绝、数据路径断裂（可用性/签发校验）

**组合**：D1/D2 交叉格（direct 入口 × E2E/admin 档）
**触发路径**：`api/handlers/delegation.rs` 校验 split/admin 要求 E2E 组，但**未拒绝** direct 入口
引用 e2e_required 组；`service::delegation::issue_token` 生成 entrust 词（hint_map 非空）；
客户端 `DelegatedOpener`（client.rs:274-299）见 `en` 词即**全部** Open 以 E2E 信封+en 词为目标——
而 direct 入口的信封终结点（DelegationHooks）挂在**扇出会话 connector** 上，签发者自身 listener
无解封能力：`route_open` 将 en_xxx 解析为本地终结（`resolve_delegated_route → Some(None)`）后落入
对 `en_xxx:0` 的本地 TCP 拨号（DNS 必然失败 → OpenFail）。配置拉取通道（`DELEGATION_CONFIG_TARGET`）
同样经 en 词信封，同样断裂——direct+E2E/admin 档令牌**全量流量不可用**。
**安全影响**：fail-closed（无明文泄露），但签发面板允许构造出完全不可用的令牌（校验缺失）。
**现状是否已缓解**：审计时无；**已修复**：`issue_token` 拒绝 `direct` 入口 × 含 e2e_required 组
的组合（提示改用 relay 入口）。
**回归测试**：`issue_rejects_direct_entry_with_e2e_group`（direct+e2e 组拒、direct+admin 拒、
direct+透明组放行）。

---

## F5-F14 概要（低危/文档化/决策项）

- **F5**：mux.rs:413 `add_permits(n)` 无上限——恶意 peer 可把自己的发送信用膨胀到无限，
  后果仅是放弃自己的流控保护（自害），不影响接收侧内存（对端发送信用才受本端约束）。
  不修，记录。
- **F6**：恶意 peer 可发 Close/OpenFail 于任意 channel_id 杀死本地信道（mux.rs:447/422）。
  影响范围=该恶意 peer 自己的会话，等同其直接断 TCP，无跨会话影响。接受。
- **F7**：`bandwidth::intercept` 在 PeerAcl 前（listener.rs:2101 / connector.rs:838）——设计文档化：
  echo/sink/source 无路由能力；source 1GiB/请求封顶（bandwidth.rs:38），会话级令牌桶仍适用。
  接受，但注意：**受限节点**可借诊断平面持续拉流（受其会话限速约束），运营上可按需关闭。
- **F8**：`ConsumerSessionReport` 由中继单方面上送（listener.rs:809），签发者面板照单全收
  （delegation.rs:472 仅缓存展示）。恶意中继可伪造「谁在线」——仅管理显示层欺骗，
  不影响执法（执法全部基于解封/组规则）。接受+文档化；后续可加中继会话签名归属。
- **F9**：**决策项**（需人类拍板）：transparent 档中继可见明文+全部目标元数据（timing/大小）。
  现有缓解：`e2e_required` 组强制 E2E + 明文 fail-close（delegation.rs:538）；
  E2E 档中继盲转（本审计 D3 格验证通过）。是否接受 transparent 档的存在本身 → REPORT §决策项。
- **F10**：`node::qr` 用 image+rqrr 解析不可信图片（≤20MB）。纯 Rust、无 unsafe 解析链，
  内存上限存在；分辨率解码炸弹风险低（20MB 封顶）。接受。
- **F11**：device.key Unix 0600（device.rs:171），Windows 侧未显式设 ACL（注释已声明依赖
  用户 profile ACL）。与 `~/.anet` 其余文件一致。接受。
- **F12**：委托哈希 squat：第二个签发者抢注他人 token_hash 被拒（listener.rs:1671），
  但「先占者」可以是攻击者（会话域，断连即释放；squat 条目空 ACL fail-closed）。
  代码注释已论证影响=该单令牌临时 DoS。接受。
- **F13**：**决策项**：bearer 令牌语义下，中继在认证时刻即持有消费者令牌明文——
  它可（a）以自身设备开消费者会话（transparent 档内冒充，签发侧设备门控是唯一区分；
  默认 block 策略下被拦）；（b）Single 档下直接踢掉真消费者（并发执法被武器化）。
  设备证明让「冒充」可归因但不阻止。是否引入「中继不可见令牌」（如 HMAC 挑战-响应）
  属架构决策 → REPORT §决策项。
- **F14**：kid 48-bit：仅是签发端查表键，解开信封仍需 32B e2e_key；碰撞= 服务端拒绝服务
  单令牌（概率 2^-48 且需先通过会话认证）。接受。

---

## 9. 已检查未发现问题清单（逐协议阶段）

| 阶段 | 检查方法 | 结论 |
|---|---|---|
| 节点身份与配对 | 精读 `device.rs` 全文 + `verify_device_proof`（TLS exporter 挑战绑定会话，零重放窗口）+ 测试 `missing_or_forged_proof_is_rejected`/`proof_binds_listener_derived_device_fp` | 无问题：fp 本地派生、不可信线值不采信、损坏密钥 fail-hard 不静默重生成 |
| 二维码配对 | 精读 `qr.rs`（纯解码，无执行语义）；链接解析 `link.rs` 纯函数、拒绝非 anet:// scheme | 无问题（解析器无副作用；导入确认在 UI 层） |
| 鉴权 | 精读 listener 认证路径 + `relay_auth.rs`（kind 强制区分；Client kind 永不进 node 表）；常数时间比较；吊销踢会话+断连即撤销注册 | 无问题；「建组无鉴权」不存在（组操作走 AdminAuth，测试 `authorization_enforced`） |
| 证书与传输 | 精读 `tunnel/tls.rs`：钉值>钉证书>CA>insecure>系统CA 优先级实现正确；`PinnedFingerprintVerifier` 哈希比对+rustls 原生 CertificateVerify；TLS1.3 强制（`tls12_rejected`）；ACME 私钥 0600、挑战证书 RFC8737 | 无问题；ACME 无集中协调单点（每节点独立向 CA 申请，2.5.1-7 项引用） |
| 协议编解码 | 精读 `frame.rs`（长度上限按类型、未知类型拒、len<5 拒）+ `fuzz_frame_decoder_never_panics` + JSON 结构无递归 | 无问题；**版本协商不可降级**：PROTOCOL_VERSION 仅声明，v4 行为无条件（无版本门槛分支） |
| 连接建立 | 精读 `serve()`：连接数 1024/pending 256/认证限流 20/min/IP/10s 握手超时 + 测试 `slowloris_pending_auth_capped`/`auth_rate_limit_drops_flood` | 无问题；打洞不存在（架构为显式 fan-out 直连，无第三方打洞面；advertise 只送给**已认证**上行，不泄内网拓扑给不可信方） |
| 隧道数据面（E2E） | 精读 `e2e.rs` 全文 + F1 修复验证；跨隧道串流：信道注册表按 channel_id 隔离，DashMap 键空间奇偶分侧 | 除 F1 外无问题；流量放大：无（Data 帧无反射语义，echo 仅回给请求者本人） |
| 隧道数据面（明文/transit） | 精读 route_open/handle_open/bridge 三臂 + PeerAcl 组集并集语义（`peer_acl_test`） | 除 F3/F9 外无问题；组标在非签发跳被清除（listener.rs:2153），下游不产生越权放行（仅可能意外拒绝，见 MH 报告注） |
| 中继盲转保证 | e2e_key 与认证令牌解耦验证（`issue_stores_hash_and_recoverable_e2e_key`：key 随机、非令牌派生）+ kid/hint 双重绑定 + blob 对中继不透明 | 无问题（这是 4e4724b 安全提交的主旨，复核成立） |
| 管理面 | 引用对抗测试矩阵：`login_oracle_prevented`、`login_bruteforce_lockout`、`jwt_forgery_rejected`、`refresh_token_rotation_and_revocation`、`sql_injection_safe`、`xss_payload_stored_safely`、`oversized_body_rejected`、`mass_assignment_ignored`、`audit_log_no_credential_leak`、`scope_enforcement_three_tiers`、`admin_ui_security_headers`、`unauthenticated_and_role_enforcement` | 无新发现；可逆存储仅两处且 AES-256-GCM（db 层复核 `encrypt_secret` 调用点=connector token/e2e_key） |
| 依赖供应链 | `cargo tree` 关键链人工核对（见下方附录）；`cargo audit`/`cargo deny` 本机未安装（error: no such command），无法离线跑 RLSA 扫描 | 无已知高危；**建议 CI 常态化**（附录 A 给出补跑方案） |

### 附录 A：关键依赖快照（审计时点）

核心加密/传输链：`ring 0.17.14`、`rustls 0.23.43`、`tokio-rustls 0.26.4`、
`rustls-pemfile 2.2.0`、`webpki-roots 0.26.11`、`rcgen 0.13.2`、`sha2 0.10.9`。
运行时：`tokio 1.53.1`、`serde 1.0.229`/`serde_json 1.0.151`、`dashmap 6.2.1`、
`arc-swap 1.9.2`、`bytes 1.12.1`、`chrono 0.4.45`、`rand 0.9.5`、`ip_network 0.4.1`、
`ip_network_table 0.2.0`、`toml 0.8.23`、`tracing 0.1.44`、`anyhow 1.0.104`。
供应链扫描补跑：`cargo install cargo-audit cargo-deny && cargo audit && cargo deny check`
（或接入 GitHub Actions 的 `rustsec/audit-check`；建议随 CI 每周跑一次）。
