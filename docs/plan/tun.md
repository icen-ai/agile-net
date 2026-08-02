# 计划：anet-gui TUN 模式（anet 在前、FlClash 在后）

> 状态：方向已确认（2026-08-01 讨论收敛），待实施。本文档为实施依据。
> 目标：**TUN 开启时，本机全部流量（含浏览器系统代理流量）先走 anet，
> 命中 AgileNet 规则走隧道，未命中放行给 FlClash 出口**——代理接管从"抢注册表"
> 升级为网卡层接管，根除与 FlClash 等系统代理派软件的互相抢占。
> 范围：**P1 仅 Windows x64 桌面 GUI**。macOS（utun + root）与 Android（VpnService）另议。
> 本文档取代 `subscription.md` §5 中"不实现 TUN"的旧结论。

## 0. 实施进度

- **P1 已实施**（2026-08-02，Windows x64 桌面 GUI）：
  - §2.1 wintun.dll 钉版本下发：官方源 wintun-0.14.1.zip + SHA-256 内置校验
    （哈希与 wintun.net 官网 / wireguard-windows 构建脚本多源交叉验证），校验失败拒落盘
    + 审计 `gui.wintun_tamper`；落盘 `~/.agile-net/mihomo/wintun.dll`（卸载清理随内核目录覆盖）。
  - §2.2 管理员提权：`CheckTokenMembership` 检测；非管理员 → 对话框 + runas 拉起自身
    （tun_mode 先持久化，重启后自动恢复开启）；审计 `gui.tun_elevation`（granted/declined）。
  - §2.3 TUN 配置骨架：`render_config` 分 TUN/非 TUN 双路径；骨架逐字段按计划
    （无 mixed-port / tun mixed+auto-route+dns-hijack / fake-ip / ANET-IN socks5→57890 /
    QUIC 压制+UDP DIRECT+MATCH→ANET-IN；proxy-providers 保留）。
    既定决策：TUN 配置不经过覆写脚本链（脚本作用于订阅代理配置语义，防环约束必须完整保留）。
  - §2.4 回落外部上游：`gui-settings.json` 新增 `tun_mode` / `external_upstream`
    （默认 127.0.0.1:7890，serde default）；TUN 开启 → `set_proxy_fallback(外部上游)`
    + TCP 拨测一次（不通仅灵动岛告警不阻断）；审计 `gui.fallback_change`（记地址不记凭据）。
  - §2.5 互斥与防环：TUN 开 → 统一出口强制关 + UI 置灰（反向亦拒绝开启；
    2026-08-03 起已改为派生行为无开关，见 §2.5 正文）；
    回落目标校验（仅回环、严禁 57890/57892/59292）；`check_no_loop` 扩展
    （TUN 无 mixed-port / 57890 仅以 proxies 出站出现一次 / rules 必须 MATCH→ANET-IN），
    落盘前强制检查，违规拒绝启动内核。另：TUN 下出站模式固定 rule（global/direct 绕过 anet 分流）。
  - §2.6 系统代理策略：TUN 开 → 自动 engage 57890；30s 巡检升级为自动收回
    （被抢即重写 + 审计 `gui.sysproxy_conflict` 记来源值）；关 TUN/退出 → 快照还原，
    退出时停内核（mihomo 自动清理 TUN 适配器与路由）。
  - §2.7 GUI：订阅页「TUN 模式」分区（开关 / 外部上游 agedit 行内编辑 /
    状态行：运行中·权限不足·上游不可达）+ FlClash 系统代理提示文案；
    审计 `gui.tun_enable` / `gui.tun_disable`。
  - §2.8 测试：TUN/非 TUN 配置快照、`check_no_loop` 全分支、回落目标校验、
    权限检测 mock 注入、TCP 拨测；E2E `tun_e2e`（--ignored，需管理员本机手动，
    自动断言 wintun 落盘 + 控制面 tun.enable，curl/浏览器步骤手动）。
- **P1.5 已实施**（2026-08-02，订阅出口优先，无 FlClash 也可用 TUN）：
  - 背景：实机发现原「回落=外部上游（默认 FlClash 7890）」在无 FlClash 环境全部未命中
    流量静默失败（谷歌不可达）；且 TUN 互斥把统一出口偏好写死后不恢复，关 TUN 仍断网。
  - 订阅出口：TUN 配置新增 `socks-port: 57893` + 规则 `IN-TYPE,socks,AGILE-SUB`（先于
    MATCH），anet 未命中流量回落到 TUN mihomo 的 socks 入站直达订阅组出口（mihomo 自身
    出站不被 TUN 捕获，不成环）；`check_no_loop` 同步断言两项各出现且仅一次。
  - 回落优先级（`effective_fallback`）：TUN 且有激活订阅 → 57893 订阅出口；无激活订阅
    → 外部上游（默认 7890，校验同步禁指 57893）；拨测目标改为生效回落地址。
  - 统一出口语义迭代：先改运行时排除（不写死偏好），**2026-08-03 起进一步移除用户开关
    改为派生行为**（订阅内核开 = 未命中走订阅出口 57892；TUN 开 = 自动接管 57893；
    开关/互斥守卫/`set_subscription_unified` 命令全部移除，`subscription_unified` 字段删除）。
  - 优雅降级补强（abandon_tun 统一兜底）：UAC 取消/权限丢失/wintun 不可用/内核 TUN 启动
    失败/副作用失败 → 自动关 TUN 并以普通模式重启内核，审计 `gui.tun_abandon` + 一次性
    灵动岛提示（`tun_status.notice` 读取即清除）。
- **P2 未实施**（规则下沉 TUN 层，性能优化）。

## 1. 背景与选型

### 1.1 为什么需要 TUN

现状（subscription P2）的流量接管依赖系统代理托管（HKCU `ProxyEnable/ProxyServer`），
与 FlClash 等软件抢同一个全局开关：谁后写谁生效，靠 30s 巡检 + 手动收回兜底。
且系统代理只对"读系统代理的应用"生效，硬编码直连的应用完全绕过。

TUN（虚拟网卡，L3 接管）不碰注册表，接管面覆盖全部 TCP/UDP 流量。

### 1.2 为什么 TUN 由 mihomo sidecar 承担

- 我们已托管 mihomo 内核（subscription P1），其 TUN 实现（wintun、auto-route、
  DNS 劫持、fake-ip）是生产级现成的；Rust 自研 TUN + 用户态 TCP 栈是数量级更大的工程。
- 许可证边界不变：sidecar 独立进程，严禁 gomobile 链接（subscription.md §1）。
- mihomo TUN 在 Windows 需 **wintun.dll + 管理员权限**，这是本计划的主要新成本。

### 1.3 总体链路（目标态）

```
浏览器/读系统代理应用 ──系统代理(anet 托管→57890)──┐
                                                ├─▶ ProxyRouter 127.0.0.1:57890
不读系统代理的应用 ──TUN(mihomo)──MATCH→SOCKS5────┘        │
        (fake-ip 保域名)                                    ├─ 命中 AgileNet 规则 → AgileNet 隧道
                                                            └─ 未命中 → 回落外部上游 127.0.0.1:7890(FlClash)
```

- 系统代理仍由 anet 托管（指向 57890）：浏览器流量 thus 也"先走 anet"。
- TUN 兜底不读系统代理的应用：mihomo 捕获后经 SOCKS5 全量转交 57890，同一路由器分流。
- 未命中流量回落 FlClash（7890，mixed 入站天然支持 SOCKS5，
  复用 subscription P2 已完成的 `Outbound::Forward` + `Socks5ForwardOutbound`）。

## 2. P1：TUN 接管 + anet 在前 FlClash 在后

### 2.1 wintun.dll 钉版本下发

- 官方源 `https://download.wireguard.com/wintun/wintun-0.14.1.zip`，
  **钉版本 + SHA-256 内置校验**（与内核同策略，校验失败拒绝落盘并审计 `gui.wintun_tamper`）。
- 落盘 `~/.agile-net/mihomo/wintun.dll`（与 mihomo.exe 同目录，wintun 按 exe 相邻加载）。
- 卸载清理项同步覆盖。

### 2.2 管理员提权

- TUN 需管理员。开启 TUN 时检测当前进程权限
  （`windows-sys` CheckTokenMembership / TokenElevation）：
  - 已是管理员：直接开启。
  - 非管理员：对话框说明 + 「以管理员身份重启」按钮
    （ShellExecuteW `runas` 拉起自身 exe，当前实例退出；
    TUN 开关状态持久化，重启后自动恢复开启）。拒绝则停留现状，审计 `gui.tun_elevation`。
- mihomo 子进程继承 GUI 权限，无需单独提权。

### 2.3 mihomo TUN 配置生成（`subscription.rs` render_config 分模式）

TUN 模式配置骨架（全量重写原则不变）：

```yaml
# TUN 模式：移除 mixed-port（关闭 57892，防环关键，见 2.5）
external-controller: 127.0.0.1:59292
secret: "..."
socks-port: 57893               # P1.5：anet 未命中流量的回落入站（直达订阅出口）
tun:
  enable: true
  stack: mixed              # TCP 系统栈 / UDP gVisor；异常时降级 gvisor
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
dns:
  enable: true
  enhanced-mode: fake-ip    # 关键：fake-ip 保域名，SOCKS5 CONNECT 以域名形式到达 57890，
  fake-ip-range: 198.18.0.1/16  # AgileNet 域名规则（add_host_suffix/exact）方可匹配
  nameserver: [223.5.5.5, 119.29.29.29]
proxies:
  - name: ANET-IN
    type: socks5
    server: 127.0.0.1
    port: 57890
proxy-providers:            # 保留：代理页测速/切换仍走控制面，与数据面解耦
  main: ...
proxy-groups:
  - name: AGILE-SUB
    type: select
    use: [main]
rules:
  - AND,(NETWORK,udp),(DST-PORT,443),REJECT   # 压制 QUIC：anet 入站不支持 UDP，强制回退 TCP
  - NETWORK,udp,DIRECT                        # 其余 UDP（STUN 等）直连，P1 不接管
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IN-TYPE,socks,AGILE-SUB                   # P1.5：anet 回落（socks 入站）直达订阅出口
  - MATCH,ANET-IN                             # 全部 TCP 转交 anet 路由器
```

### 2.4 anet 侧回落（P1.5 修订：订阅出口优先，外部上游兜底）

- **回落优先级**：有激活订阅 → 回落 `127.0.0.1:57893`（TUN mihomo 的 socks 入站，经
  `IN-TYPE,socks,AGILE-SUB` 规则直达订阅组出口；mihomo 自身出站不被 TUN 捕获，不成环）。
  无激活订阅 → 回落「外部上游」地址（默认 `127.0.0.1:7890`，如 FlClash mixed 入站，可改）。
- 效果：**不依赖 FlClash 也能用 TUN**——未命中 AgileNet 规则的流量默认走订阅节点出网；
  与 FlClash 共存时外部上游作为无订阅场景的兜底。
- `crates/client` `set_proxy_fallback` 已支持任意地址，无需改动核心。
- GUI 设置 `gui-settings.json`（`tun_mode: bool` / `external_upstream: String`，serde default）。
- TUN 开启/切换时 TCP 拨测**生效回落目标**一次，不通则灵动岛 warn（不阻断开启）。
- 未命中转发复用 `Socks5ForwardOutbound`。

### 2.5 互斥与防环（硬约束）

- **统一出口与 TUN 语义互斥**（2026-08-03 起统一出口为派生行为，无用户开关）：
  非 TUN 且订阅内核运行 → 回落 57892；TUN 开启 → 回落自动切换 57893（TUN 分支优先），
  关 TUN 自动回落 57892——57890→57892→MATCH→57890 死环从配置上杜绝，无需用户操作。
- 回落目标合法性单测：TUN 模式下回落严禁指向 57890/57892/57893/59292 及 loopback 外的未配置地址。
- `assert_no_loop` 扩展：TUN 配置不得含 `mixed-port`；非 TUN 配置维持原断言。
- mihomo TUN 配置中 57890 仅以 `proxies` 出站形式出现，rules 严禁回指 57892。

### 2.6 系统代理策略（TUN 模式）

- TUN 开启 → anet 自动托管系统代理指向 57890（复用 `sysproxy.rs` engage/快照/还原）。
- 冲突巡检在 TUN 模式下从"提醒手动收回"升级为**自动收回**（30s 巡检发现被抢即重写，
  审计 `gui.sysproxy_conflict` 记录每次抢夺来源值）。
- UI 提示文案：建议关闭 FlClash 的「系统代理」开关（FlClash 只需保持内核监听 7890），
  避免两软件周期性互抢注册表（虽不致命，但产生无效写入与审计噪音）。
- 关闭 TUN / 退出 GUI：还原系统代理快照；mihomo 退出自动清理 TUN 适配器与路由。

### 2.7 GUI 与审计

- 订阅页新增「TUN 模式」分区：开关、外部上游地址输入、状态（运行中/权限不足/上游不可达）。
- 审计事件：`gui.tun_enable` / `gui.tun_disable` / `gui.tun_elevation`（granted/declined）/
  `gui.wintun_download` / `gui.wintun_tamper` / `gui.fallback_change`（记地址不记凭据）/
  `gui.tun_abandon`（权限不足/启动失败安静放弃并回退普通模式，附一次性 UI 提示；TUN 为可选附加，绝不影响其它功能）。
- 前端约束沿用既有约定（无内联事件、变更检测、灵动岛通知）。

### 2.8 P1 测试

- 配置生成器：TUN / 非 TUN 双模式快照；防环断言全量覆盖（2.5 各条）。
- 回落目标校验单测；权限检测抽象层注入 mock。
- E2E（`--ignored`，需管理员本机手动）：
  开 TUN → `curl http://ip.sb`（不带 -x，模拟不读系统代理应用）出口 = FlClash 节点 IP；
  AgileNet 内网域名走隧道通；浏览器系统代理=57890 访问谷歌经 anet→FlClash 通；
  关 FlClash → 未命中失败 + 灵动岛上报告警；退出 GUI → 系统代理与路由表还原。

## 3. P2：AgileNet 规则下沉 TUN 层（性能优化，可选）

P1 全部 TCP 都经 anet 用户态转发一跳。P2 把 AgileNet 规则同步进 mihomo 配置：

- 规则生成：AgileNet 域名/IP 规则（含管理面隐式路由）→ mihomo rules 前置项
  （`DOMAIN-SUFFIX,xxx,ANET-IN` 等），`MATCH` 改为直接出站外部上游
  （mihomo `http`/`socks5` 类型代理节点指向 7890）。
- 效果：仅内网流量到达 57890，普通流量在 mihomo 内直接转发 FlClash，少一跳用户态转发。
- 动态同步：AgileNet 规则变更（节点上下线）时重生成配置 + `PUT /configs?force=true` 热加载。
- 防环约束同 2.5（ANET-IN 只出现在 AgileNet 规则项，MATCH 永不指向 57890）。

## 4. 安全与边界（Non-goals）

- 不解决"FlClash 也开 TUN"的双 TUN 冲突（两 TUN 抢默认路由无正解）：
  检测到其他 wintun/utun 适配器或路由冲突时仅诊断提示，请用户只保留一个。
- 不接管 UDP（QUIC 压制回退 TCP；其余 UDP 直连），UDP 代理属于远期议题。
- 不提供「自定义 wintun/内核路径」入口（防供应链注入，同内核策略）。
- TUN 模式为本机专属能力，不进 Web 远程面（同订阅命令策略）。
- anet-svc 不涉及；macOS utun + root、Android VpnService 另立计划。

## 5. 分期验收

- **P1 完成**：非管理员开 TUN → 提权重启后 TUN 接管生效；
  不读系统代理的应用流量经 anet 分流（内网走隧道、其余走 FlClash）；
  浏览器系统代理流量同路径；FlClash 抢系统代理 30s 内被自动收回并落审计；
  关 TUN/退出后系统代理与路由表完整还原。
- **P2 完成**：AgileNet 规则变更 1s 内热加载进 mihomo；普通流量不再经 57890 转发；
  内网匹配准确率与 P1 一致（规则同步 diff 单测）。
