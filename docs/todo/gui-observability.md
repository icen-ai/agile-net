# GUI 可观测性与桌面组件强化 · 实施记录

状态：已实施（2026-08，commit `45a3eec` 起）。本文档记录本轮 GUI 大版本强化的设计与落点，供后续维护对照。

## 范围总览

1. TUN 出口探测修复
2. 日志菜单（实时连接 / 实时日志 / 命中追踪）
3. 侧栏底部状态区 + 托盘增强 + 桌面悬浮球
4. 拖拽导入订阅 + 系统代理锁定
5. `anet doctor` 自我诊断（CLI + GUI + 文档站）
6. 设计系统升级（macOS 级质感）

## 1. TUN 出口探测

- 根因：`fetch_exit_ip` 以 `http://` 代理协议连 mihomo 纯 SOCKS5 口（57893），协议不匹配；且 reqwest 未启用 `socks` feature。
- 修复：`apps/desktop/Cargo.toml` reqwest 加 `socks`；`lib.rs fetch_exit_ip` 按模式分派 scheme——TUN `socks5h://127.0.0.1:57893`（域名交内核解析，避开 fake-ip），非 TUN 保持 `http://…:57892`（mixed 口支持 CONNECT）。

## 2. 日志菜单（view-logs）

- 采集（`apps/desktop/src/subscription.rs`）：WS 客户端握手路径参数化（`ws_session_on`）；`KernelManager::start_collectors` 随内核启停挂 `/connections`、`/logs?level=info` 两个采集任务（指数退避重连，复用 traffic 模式）。
- 内存态 `ConnTracker`：活跃连接 map + 已关闭环 300 + 日志环 500 + 命中聚合 top 100。
- 命令：`sub_connections` / `sub_logs` / `sub_rule_hits` / `sub_close_connection` / `sub_clear_logs` / `sub_add_rule_for_host(host, direct|subscription)`（映射 custom_rules 放行规则，`normalize_host` 校验去噪）。
- 前端（`app.js LogsView`）：仅视图打开时轮询（连接/日志 1s、命中 2s）；连接表签名对比整表重绘（活跃置顶 inset accent 条）；日志增量追加（游标丢失/缓冲轮换自动全量重绘，DOM 上限 500）；右键 `.ctx-menu`：强制打断 / 直连该域名 / 走订阅该域名。

## 3. 桌面组件

- 侧栏底部 `.side-foot`：↑↓ 实时速率 + 代理状态，折叠态只留速率、≤720px 隐藏。
- 托盘：`tray_speed_watch`（lib.rs）1s 刷新 tooltip 网速；弹窗 tray.html 重做（网速大字 / 60s 双序列 sparkline / 代理组速切 / 连接摘要 / 主题跟随 ag-theme），修复了原页缺 tokens.css 引用的旧 bug；窗口 292×420。
- 悬浮球 float.html（label `float-ball`，72×72 透明 always-on-top）：拖拽（>4px 阈值 + `tauri://move` 静默判停 + 边缘吸附）、单击菜单 / 双击主面板 / 右键菜单、气泡通知（`ag-float-notify`，≤3 条堆叠 4s 淡出）；菜单/气泡超出 72px 由前端扩容管理器 setSize/setPosition 解决（capabilities 已配齐）。`RoleSettings.float_ball` 持久化，设置页开关；仅桌面端。
- 桥接的气泡事件：内核启动失败、系统代理冲突/收回（`float_ball_notify` → emit_to float-ball）。

## 4. 交互润滑剂

- 拖拽导入：主窗 `tauri://drag-drop` → `import_local_subscription(path)`（≤5MB yaml/yml，落盘 `mihomo/local-<id>.yaml`，provider `type: file`，删除订阅级联清理）。
- 系统代理锁定：`RoleSettings.sysproxy_lock`，`sysproxy_watch` 自动收回条件扩为 `tun_mode || lock`（审计 detail 含 `lock:true`）；设置页开关。

## 5. anet doctor 自我诊断

- 核心 `crates/node/src/tool/doctor.rs`：`DoctorReport{sections, summary, duration_ms}`，五态 `ok/info/warn/err/fixed`；`run` / `run_streaming`（逐节回调）/ `render` / `exit_code`（err>0→1）；`SECTION_PLAN` 七节计划。
- 七节：ports（含 GUI 内嵌节点 59293/54431、孤儿 mihomo sweep 自动修复）/ sysproxy（残留还原自动修复）/ tun（wintun 钉值、管理员）/ kernel（mihomo 版本钉、控制面可达）/ network（DNS/HTTPS/网关 ping）/ config（JSON 损坏备份重置、磁盘余量）/ rules（pattern 重复/非法/hosts 托管块漂移/DB CIDR 包含冲突）。
- CLI `anet doctor`（`--json`，免登录）；GUI `run_doctor`（emit `ag-doctor-begin` + `ag-doctor-section` 流式，前端骨架逐节原位替换，无事件通路时整体渲染兜底）。
- 文档站：`wiki/content/guides/doctor.md`（每项「检查什么/正常表现/常见异常/自动修复/手动处理」+ FAQ 排查链）。

## 6. 设计系统

- tokens.css 新增 24 token（深浅两套）：阴影三级 `--shadow-1/2/3`、玻璃 `--glass-bg/--glass-border`、info 语义、表格 `--tbl-*`、日志 `--log-*`、`--accent-grad`、`--mask`、`--toggle-knob`、`--dur-fast/--dur-slow`（原 `--shadow` 兼容别名已随管理端改 `--shadow-3` 后移除）。
- components.css 新增共享组件：`.ctx-menu`（毛玻璃右键菜单）、`.tbl`（粘性表头表格）、`.logv`（日志流 + 级别色条 + `mark.logv-hl`）、`.pill`、`.side-foot`；全部含深色适配与 `prefers-reduced-motion` 降级。
- style.css 全局质感：卡片 hover 抬升、模态模糊弹入、6px 纤细滚动条、focus-visible 环、视图入场动画、移动端 ≥40px 触摸目标。

## 跨平台说明

- Windows / macOS：全量功能（TUN 仅 Windows x64；macOS 系统代理走 networksetup；托盘模板图标已适配）。
- 国产 Linux（统信/麒麟等 WebKitGTK 环境）：桌面端功能可用；毛玻璃依赖 `backdrop-filter`（已带 `-webkit-` 前缀），旧 WebView 自动退化为半透明底色。
- Android：同一份前端；悬浮球/托盘/卸载等桌面专属项按 UA/平台隐藏（`set_float_ball` 移动端返回不支持）；响应式 ≤720px 布局已覆盖新组件。
- iOS：暂不在构建矩阵；前端不依赖任何桌面专属 Web API，后续接入无前端改造成本。

## 遗留与后续

- `client_tunnel_test` 偶发网络型 flake（core 未改动，复跑即过）。
- 悬浮球气泡桥接点目前 2 处（内核启动失败、系统代理冲突）；脚本错误告警链路无 AppHandle，后续可在 KernelManager 加事件槽。
- Android 真机构建未在本机验证（需 NDK 环境）。

## 二期：留存型中控台（竞品调研驱动）

标杆调研（Clash Verge Rev/FlClash/Stash/v2rayN/Surge/iStat/Tailscale 等）结论：留存 = 状态可见性 + 每日仪式感 + 零打扰。二期落地：

- **首页中控台**（hero-card）：`.power-btn` 大总开关（`proxy_power`/`proxy_power_toggle`，TUN 互斥守卫）+ 实时速率双序列曲线（--chart-up/down token）+ 三枚 dstat 摘要（odoSet 数字滚动，仅 hero 区克制使用）+ 新手检查单（四步首次成功路径，localStorage 持久/可关闭）。
- **节点页「每日选妃」**：组级/全部批量测速（`sub_test_group`，前端 30ms 阶梯流式写 `.lat` 徽标，防阻塞禁用）、按延迟排序（localStorage 每组记忆）、<500ms 最低延迟「推荐」徽标（Tailscale 式替用户决策）、双层签名对比防 10s 轮询打断流式。
- **事件中心**：日志视图第四页签，`recent_events`（gui-audit.jsonl 尾部倒读 + kind 白名单 + detail 人读化、敏感字段绝不回显），Surge Event Center 式「不打断但可回顾」。
- **连接详情展开**：chains 全链/规则/起止/累计流量实时刷新 + 纯 HTML 链路迷你拓扑（本机→中继→出口→目标，语义色圆点）。
- **偏好**：`notify_float_ball`（气泡开关，emit 收口门控）、`reduce_effects`（性能模式：`html.no-blur` 关玻璃动画，低配/国产 Linux，首帧 localStorage 预应用）。
- **窄屏底部导航 .bnav**（≤720px：首页/扇入/日志/设置；侧栏整体隐藏联动；管理端/HTTP_MODE 隐藏；z-index 90 低于模态）。
- 设计系统二期 token/组件：--chart-*/--lat-*/--power-*/--skel-*/--glass-hi；.odo/.skel/.empty-state/.power-btn/.lat/.ev-list/.bnav；玻璃组件全部 no-blur 兜底；agchart.js 主题色实色解析。
