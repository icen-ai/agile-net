# AgileNet 全组合攻击面 / 安全性 / 性能审计总报告

- **分支**：`audit/full-attack-surface`（自 master `482b77e` 起）
- **范围**：crates/core（relay/proto/tunnel/proxy/device/link）、crates/node（认证/ACME/QR/service/api/db）、
  crates/client（引擎/凭据）、三 crate 全部 436 项集成测试盘点 + 对抗性复验
- **方法**：阶段 1 侦察建模（`interaction-matrix.md`）→ 阶段 2 逐格 STRIDE + 协议阶段审计
  （`findings.md`）→ 阶段 2.5 多跳/规模化专项（`multihop-scale-report.md`，含 release 实测）
  → 修复与回归（全部落测试）
- **任务书事实纠正**：`relay/transit.rs` 是流量记账模块而非明文转发路径；真正的明文路径在
  `listener::route_open`+`bridge`，E2E 路径在 `relay/e2e.rs`——两条路径已分别审计，未混用结论。

## 执行摘要

审计覆盖 4 个正交维度（角色×连接方式×加密档×信任状态）×跳数区间的全部组合格，
**未发现 Critical 级问题**；发现并**已修复** 2 个 High、3 个 Medium 问题（含多跳专项 2 项），
其余 10 项低危/信息项均已文档化或列为决策项。核心安全承诺逐项复验成立：

1. **E2E 盲转承诺成立**：e2e_key 与认证令牌解耦、kid/hint 双绑定、中继不可解密、
   明文降级 fail-close——但「重放不得产生应用层重复变更」的纪律存在**跨信道缺口**（F1），
   已以信封一次性（chan_salt 消费）修复。
2. **数据面资源执法在修复后双侧对称**：listener 与 connector 均有 256 入站 Open 上限（F2），
   多跳环路有 8 跳预算 O(1) 拒绝（F3）。
3. **多跳性能健康**：RTT 近线性（回环 +26µs/跳）、吞吐 ×~0.8/跳、E2E 端点开销 0.4ns/字节
   （中继纯字节转发，无实现劣化）、mux 在饱和信道下无队头阻塞（探针膨胀 1.1x）。

## 高危格子总览（矩阵标红）

| 矩阵格 | 组合 | 发现 | 状态 |
|---|---|---|---|
| D3/D5 | 消费者→中继→签发者 / E2E / 中继恶意 | **F1** 跨信道重放（High） | ✅ 已修+测试 |
| N8 | 上行→扇出反向 Open 洪泛 | **F2** connector 无上限（High） | ✅ 已修+测试 |
| N6/N7 | 互指 advertise 环路（含 0.0.0.0/0 转售） | **F3** 无跳数预算（Medium，放大×DoS 双标） | ✅ 已修+测试 |
| M/入口 | 认证失败 IP 表膨胀 | **F4**（Medium） | ✅ 已修 |
| D1×D2 | direct 入口 × E2E/admin 档 | **F15** 签发校验缺失（Medium，fail-closed） | ✅ 已修+测试 |

其余格子（消费者并发/容灾/伪造、扇出认证/收敛、联邦上送采纳、传递认证、管理面全项、
协议编解码、ACME/QR）——已检查未发现问题，逐格方法见 `findings.md §9`。

## 修复清单（commit 0606739 等，全部附回归测试）

| ID | 修复 | 测试 |
|---|---|---|
| F1 | `DelegationEngine::e2e_unwrap` chan_salt 一次性消费（上限 65536 fail-closed） | `engine_e2e_envelope_is_one_shot` |
| F2 | connector 维护循环 `MAX_INBOUND_OPENS_PER_SESSION` 信号量 | `connector_open_flood_capped` |
| F3 | `OpenChannel.hops` + `MAX_OPEN_HOPS=8`（listener route_open / connector handle_open 双点） | `open_hop_budget_kills_routing_loop`（真实互指环拓扑）、`open_channel_extension_roundtrip` |
| F4 | `record_auth_failure` 每 1024 次插入均摊 retain 清扫 | 既有认证限流测试回归 |
| F15 | `issue_token` 拒绝 direct × e2e_required 组 | `issue_rejects_direct_entry_with_e2e_group` |

全量回归：`cargo test --workspace` **436 passed / 0 failed**（含新增 5 项回归）。

## 多跳/规模化专项摘要（详见 `multihop-scale-report.md`）

- **信任传递**：逐跳验证（设备证明绑 TLS 会话）+ E2E 端到端密钥解耦——无链式放大缺陷；
  明文档中间跳可见性为设计取舍。
- **降级混用**：无跳级降级面（信封对过境跳不透明，明文命中 e2e_required 组 fail-close）。
- **路径操纵**：advertise 完全自报、无交叉验证（**架构决策项 ③**）；本项目无指标择路面，
  故无「虚报指标诱导选路」类别。
- **共谋**：明文档全可见；E2E 档留时序/长度元数据（抗关联需恒速整形，**决策项 ②**）。
- **重放/环路/跳数**：F1/F3 修复后全部有界或 O(1) 拒绝。
- **规模化**：无集中信任单点（逐节点 ACME/自签 + 设备密钥签名记录）；路由查找无 O(n²) 面；
  限速单点计费无双跳压缩；资源放大点清单（修复后均线性有界）见 MH-P5 表。

## 性能基线与建议

实测（release/回环/`multihop_bench_test`，方法与数据见 MH 报告）：

- RTT：1/2/3/5 跳 = 93/129/140/197µs（avg）→ **+26µs/跳**，近线性；
- 吞吐：上行 1491→548 Mbps（1→5 跳），×~0.8/跳；下行同量级；
- E2E 端点开销 0.4ns/B（密封 8.4 vs 裸 13.6 Gbps）；中继 E2E 模式零额外 CPU（纯转发）；
- mux 公平性：饱和上传下探针信道 1.1x（无队头阻塞）。

优化建议（按收益排序）：① 万级 direct 令牌时 `resolve_delegated_route` 的 O(N) 线性扫改
hint 索引（当前量级无感，量级预研时再做）；② 真实广域多跳衰减需 netem/Docker 环境验证
（搭建步骤已写明，本机无法执行 tc）；③ 供应链扫描（cargo-audit/deny）入 CI 周任务。

## 未覆盖 / 需人工判断项

**需真实环境验证**（方法已给出）：
1. 广域 RTT/丢包下的多跳衰减（`tc netem` + `.docker/docker-compose.chain.yaml` 扩 N 级，步骤见 MH-P6）；
2. 30-50 节点 mesh 互借中继的聚合吞吐与 p99（compose 脚本化，步骤见 MH-P6）；
3. DPI/主动探测下的 TLS 拟态有效性（黑盒环境，发布前人工一轮）。

**架构性问题（代码不可修，需人类决策）**：
- **① transparent 档存废**：明文中转下中继可见全部明文+元数据；多跳+恶意下行虚假 advertise
  会把明文直接喂给攻击者（MH-S3）。若保留，建议管理端显著标注「明文档勿跨不受信中继」；
  若收紧，可将 e2e_required 设为默认或强制唯一档位。
- **② E2E 档抗关联**：当前承诺是「不可解密」，非「不可关联」（长度/时序元数据跨跳保真）。
  抗关联需填充/恒速整形，性能代价需产品拍板。
- **③ advertise 无验证**：bearer relay token 即路由声明权。可考虑「advertise 需管理端审批/
  与钉值绑定」，代价是联邦开通摩擦。
- **④ 中继持令牌冒充（F13）**：bearer 语义下中继在认证时刻即见消费者令牌明文，transparent
  档可冒充（设备门控是区分器）、Single 档可踢真消费者。彻底解法是挑战-响应式令牌，属协议演进。

## 交付物索引

| 文件 | 内容 |
|---|---|
| `docs/audit/interaction-matrix.md` | 阶段 1：组件清单/拓扑/组合矩阵（基准表，含测试覆盖列） |
| `docs/audit/findings.md` | 阶段 2：F1-F15 逐项发现 + 已检查未发现问题清单 + 依赖附录 |
| `docs/audit/multihop-scale-report.md` | 阶段 2.5：安全 7 项 + 性能 6 项 + 实测基线 + 真实环境搭建方案 |
| `crates/core/tests/multihop_bench_test.rs` | 多跳基准（`--ignored` 显式跑） |
| 新增回归测试 5 项 | F1/F2/F3/F15 见修复清单；全部随 `cargo test --workspace` 运行 |
