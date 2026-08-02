# 计划：anet-gui 订阅代理（mihomo sidecar）

> 状态：方向已确认（2026-07-31 讨论收敛）。本文档为实施依据。
> 定位：**anet-gui 桌面端独享的附加服务**——导入 Clash 系订阅后无需 FlClash 等第三方客户端；
> 借统一本地出口顺带收敛系统代理冲突，把「被谁抢占了代理」变成可诊断的一等事件。
> 范围：**仅桌面 GUI（Windows / macOS）**。Android 明确排除（Play 禁止运行时下载可执行文件，
> 需构建期内核打包 + VpnService 形态，另立计划）。anet-svc 不涉及。

## 0. 实施进度

- **P1 + P2（已完成，2026-07-31）**：
  - `apps/desktop/src/subscription.rs`：内核管理器——v1.19.29 钉版本下载
    （官方 Release + 镜像回退，SHA-256 内置校验/篡改拒绝落盘并审计；win x64 + macOS arm64/x64）、
    supervisor 任务独占子进程 + mpsc 停止信号（**槽位作存活标记由 supervisor 收尾清除，
    stop 用 clone 发送端——take 会让等待循环秒退、运行时直接停机产生孤儿进程**）、
    启动就绪检查（控制面 10s 未就绪即回收并报端口占用）、崩溃指数退避重启（上限 5 次审计放弃）、
    config.yaml 全量生成（proxy-providers 零解析）、external-controller REST 客户端（loopback:59292 + secret 持久化）。
  - `crates/core`：`Outbound::Forward` + `Socks5ForwardOutbound`（入站已解析目标，
    作 SOCKS5 客户端二次握手转交上游；SOCKS5/HTTP 两种入站全覆盖，含 mock 服务端单测）。
  - `crates/client`：`set_proxy_fallback`——回落地址写入合并路由默认出站
    （命中规则走隧道，未命中回落 127.0.0.1:57892；关闭回落即直连）。
  - `apps/desktop/src/sysproxy.rs`：系统代理托管（Windows 注册表 + InternetSetOption 即时生效 /
    macOS networksetup 逐服务），开启前快照、关闭还原；30s 巡检冲突审计；
    设置页横幅 + 一键收回；代理端口变更自动重写期望值。
  - GUI：侧栏「订阅」页（内核状态/订阅卡片/代理组测速切换）、角色开关 D、
    系统代理托管开关（统一出口初为开关、2026-08-03 起改派生行为无开关）；
    卸载清理项覆盖 subscriptions.json 与内核目录；订阅命令不进 Web 远程面（本机专属）。
  - 测试：配置生成/转义/URL 脱敏单测、SOCKS5 转发握手与失败应答单测、
    内核 E2E（下载→启动→REST 握手→停止，`--ignored` 手动运行）。

（实际端口落地为 mixed `57892`（57891 开发机已占用，文档各处同步））

## 1. 技术选型：mihomo sidecar，不 Rust 重写

**结论：进程级 sidecar，永不自研协议栈。**

- Clash 订阅生态 = 8+ 种代理协议（SS/SSR/VMess/VLESS+Reality/Trojan/Hysteria2/TUIC/WireGuard）
  + 规则引擎（GEOSITE/GEOIP/rule-providers/proxy-groups）+ 多种订阅格式。
  Rust 生态无完整对标物（shadowsocks-rust 仅覆盖 SS），自研是数月到年级工程且需永久追逐协议演进，
  抗检测代码（uTLS 指纹、Brutal 拥塞控制）自研正确性风险不可接受。
- 关键省力点：**mihomo 自带 proxy-providers**——订阅 URL 写进配置即可，
  拉取 / 解析 / 定时更新全部由内核完成，本项目零订阅解析代码。
- 许可证边界：mihomo 为 GPL-3.0。sidecar 是独立进程（stdin/HTTP 通信），
  社区共识不构成衍生作品；**严禁** gomobile 链接进 anet-gui（MIT 主体会被传染）。
- 信任链：内核二进制只从 mihomo 官方 GitHub Release 下载，
  **钉版本 + SHA-256 校验**（校验值随 anet-gui 版本内置，升级内核 = 升级 anet-gui）。

## 2. 总体架构

```
┌──────────────────────────── anet-gui ────────────────────────────┐
│  设置/订阅页 (ui/) ──IPC──▶ subscription 模块 (apps/desktop/src) │
│                                 │ 生成 config.yaml / 启停 / 巡检  │
│                                 ▼                                 │
│   ProxyRouter ◀── 回落上游 ── mihomo 进程 (sidecar)               │
│   57890 本地代理                  ├─ mixed 入站  127.0.0.1:57892  │
│   AgileNet 规则→隧道              └─ REST 控制  127.0.0.1:59292   │
│   其余流量→mihomo                       (external-controller)     │
└──────────────────────────────────────────────────────────────────┘
```

- **端口规范**（对齐 AGENTS.md 5 万段、规避 Clash 系常用端口）：
  mihomo mixed 入站 `127.0.0.1:57892`（避让 7890/7897），
  external-controller `127.0.0.1:59292`（避让 9090），均仅 loopback。
- **数据布局**（全部在 `~/.agile-net/` 下，卸载清理项同步覆盖）：
  - `mihomo/mihomo[.exe]`：内核二进制（钉版本）
  - `mihomo/config.yaml`：由本模块生成（**严禁手改**，启动时全量重写）
  - `mihomo/cache/`：内核缓存（GeoIP/GeoSite 数据库等）
  - `subscriptions.json`：订阅清单（URL 常含 token，视为敏感凭据，0600；
    卸载「配置与偏好」项一并清理）

## 3. P1：sidecar + 订阅导入 + 内核管理面

目标：订阅能导入、内核能跑、GUI 能看节点/测速/切换；流量出口暂为 mihomo 独立端口。

### 3.1 内核管理 `apps/desktop/src/subscription.rs`

- `KernelManager`：下载（按 `target_os/arch` 选 Release 资产 → SHA-256 校验 → 原子替换落盘）、
  启动 / 停止 / 崩溃退避重启（指数退避，上限 5 次后记审计并灵动岛告警）、版本查询。
- 首次启用时惰性下载；下载进度经灵动岛通知反馈（不新增 UI 体系）。
- 配置生成器：订阅清单 → `config.yaml`
  （proxy-providers 逐订阅一项、`mixed-port: 57892`、`external-controller: 127.0.0.1:59292`、
  `secret` 首启随机生成并持久化于 `subscriptions.json`、`log-level: warning`、
  默认 GROUP 聚合全部 provider）。
- 内核 REST 客户端：`GET /proxies` / `GET /group/{group}/delay`（provider 节点不在全局
  /proxies 注册表，单节点 `/proxies/{name}/delay` 恒 404，必须整组并发测）/ `PUT /proxies/{group}`
  / `GET /providers/proxies` + `PUT`（手动更新订阅）；全部经 loopback + secret 鉴权。

### 3.2 Tauri 命令与 GUI

- 命令（沿用现有 `#[tauri::command]` + 审计风格）：
  `list_subscriptions` / `add_subscription` / `remove_subscription` / `update_subscription`（手动刷新）、
  `subscription_status`（内核运行态/版本/各订阅节点数与最近更新）、
  `proxy_groups` / `select_proxy` / `test_delay`、
  `set_subscription_role`（总开关，持久化进 `gui-settings.json`，类比三路开关）。
- UI：侧栏新增「订阅」分区（Lucide `satellite-dish` 图标，收录进 icons.js）：
  订阅卡片列表（名称/URL 脱敏/节点数/最近更新/手动刷新/删除）+ 添加订阅弹窗（URL + 备注名）；
  代理组与节点列表（延迟着色徽标、点击切换），复用现有卡片/表格/搜索折叠组件。
- 交互约束：无 Node 构建链、CSP 禁内联事件（事件委托/显式绑定）、轮询变更检测、
  深浅主题均走 CSS 变量——全部沿用既有约定。
- 审计：`gui.subscription_add/remove/update`、`gui.kernel_start/stop/crash`，
  严禁记录订阅 URL 明文全文（记脱敏前缀 + 备注名）。

### 3.3 P1 出口形态

mihomo mixed `127.0.0.1:57892` 独立可用（用户可手动指应用过去）；
设置页明示「AgileNet 代理 57890 / 订阅代理 57892」两个入口。**此阶段不动 ProxyRouter。**

### 3.4 P1 测试

- 配置生成器：多订阅/空清单/特殊字符转义快照测试。
- REST 客户端：mock axum server 验证信封/鉴权/错误翻译。
- 状态机：崩溃重启退避、下载校验失败拒绝落盘（篡改哈希用例）。

## 4. P2：统一出口 + 系统代理托管与冲突诊断

目标：用户只需 57890 一个端口；系统代理被抢占成为可诊断事件。

### 4.1 ProxyRouter 回落上游

- `crates/core` `ProxyRouter` 增加可选回落上游（`127.0.0.1:57892`）：
  AgileNet 规则命中的走隧道；未命中的转发至 mihomo；订阅角色关闭时回落 = 直连（现状不变）。
- 客户端引擎装配处注入回落地址；GUI 侧原提供「订阅流量经统一出口」开关（默认开；
  **2026-08-03 起移除开关改为派生行为**：订阅内核开即未命中走订阅出口，无需用户决策）。
- 防环：mihomo 配置 `rules` 首条 `IP-CIDR,127.0.0.0/8,DIRECT` 且回落只认 57892 入站；
  mihomo 自身出站不得再指回 57890（配置生成器静态保证 + 启动断言）。

### 4.2 系统代理托管（诊断核心）

- 设置页「系统代理」开关：开启后把系统代理指向 `127.0.0.1:57890`
  （Windows：注册表 `ProxyEnable/ProxyServer`；macOS：`networksetup` 逐项服务设置；
  关闭时还原为开启前的快照值）。
- **冲突巡检**：每 30s 读系统代理实际值，与我们设置的期望值比对——
  被第三方改动（其他代理软件抢占）时灵动岛 warn 通知
  「系统代理已被外部修改，当前不经过 AgileNet」+ 可展开详情（当前值 vs 期望值）+
  单击「收回」一键重写。该事件落审计 `gui.sysproxy_conflict`。
- 与现有 Clash 共存文档（`apps/README.md`）同步更新：托管模式下的预期行为。

### 4.3 P2 测试

- 回落路由：mock 上游断言命中/未命中分流、订阅关闭时回落直连。
- 系统代理：设置/还原快照往返、外部篡改检出与收回（Windows 注册表用临时 hive/抽象层注入）。
- 防环断言：生成配置静态检查无回指规则。

## 5. 安全与边界（Non-goals）

- 不实现 TUN/增强模式（桌面端需驱动/提权，复杂度高收益低）；VPN 形态属于未来 Android 计划。
  （2026-08-01 更新：桌面 Windows TUN 已立项，见 `docs/plan/tun.md`，本条款仅对订阅 P1/P2 当期有效。）
- 不解析订阅内容（全交 mihomo proxy-providers）；不支持导入本地 yaml 文件（P1 仅 URL）。
- 内核只从官方 Release 下载且钉版本校验，不提供「自定义内核路径」入口（防供应链注入）。
- external-controller 仅 loopback + secret；严禁随 Web 远程面暴露（Web 远程面不映射订阅命令，
  订阅管理是本机专属能力，与卸载入口同策略）。
- 订阅 URL 为敏感凭据：存储 0600、日志/审计脱敏、导出功能不提供。

## 6. 分期验收

- **P1 完成**：添加订阅 → 内核自动下载启动 → 订阅页可见节点组与延迟 →
  切换节点生效 → curl 经 57892 出口 IP 变化；崩溃内核自动拉起并告警。
- **P2 完成**：57890 单端口同时承载 AgileNet 隧道流量与订阅流量（规则命中分流正确）；
  系统代理托管开启后被第三方篡改 → 30s 内灵动岛告警并可一键收回，事件落审计。
