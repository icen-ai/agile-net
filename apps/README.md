# AgileNet 客户端应用（桌面 & Android）

`apps/desktop` 是基于 **Tauri 2** 的跨平台客户端，前端为原生 HTML/JS（无 Node 构建链），
后端直接复用 `agile-net-client` 引擎（与 `anet-svc client` 同一数据面）：

- **Windows** 桌面应用（`.exe` / `.msi`，内嵌 WebView2 Bootstrapper）
- **Android** 应用（`.apk` / `.aab`，Tauri 2 Mobile）
- macOS / Linux 亦可构建（未实测）

## 功能

- **一体化应用外壳**：无边框窗口 + 自定义标题栏（拖拽区/窗口控制），Cindy 风格设计 token
- **灵动岛通知**：标题栏中央状态岛（代理/网络摘要），通知瞬时弹出自动收回；
  部分网络不可达时点击展开异常节点明细
- **空状态引导**：未连接节点时展示三步接入引导，粘贴框自动聚焦
- **剪贴板识别**：一键识别剪贴板中的 `anet://`（兼容旧 `agilenet://`）接入链接并导入
- 快速接入：粘贴 `anet://connect?...` 链接一键导入连接（含 sk- 强密码）
- 手动添加：地址 / 账号 / 密码 / 证书固定 PEM / insecure 开关 / hosts 管理（折叠面板）
- 节点管理：多节点连接、实时状态徽标（连接中/重连中脉冲动画）、断开、凭据保存与自动重连
- **已保存节点管理**：状态区分（已连接/未连接…）、删除（二次确认）、导出为接入链接
- **路由自由组合**：合并视图逐条启停，暂停立即生效并本地记忆，暂停不占冲突位次
- **列表搜索**：节点/凭据/路由列表均为图标展开的折叠式筛选
- 本地代理：127.0.0.1 端口启停（SOCKS5 / HTTP 自动识别），可配置连接节点后自动启动
- **系统托盘**：关闭窗口最小化到托盘，右键菜单（显示主窗口 / 代理开关 / 退出），双击唤起
- **开机自启**：设置中一键开启/关闭（Windows 注册表 Run 项 / macOS LaunchAgent）
- 错误翻译：底层网络错误自动转为用户友好的中文提示
- **订阅代理（mihomo sidecar）**：Clash 系订阅导入即用，内核钉版本下载（SHA-256 校验）、
  崩溃自愈、代理组/测速/切换全 GUI 管理；未命中 AgileNet 规则的流量可统一经订阅出口（57890 单端口）
- **系统代理托管**：一键指向本地代理端口，关闭自动还原快照；被第三方抢占时横幅 + 灵动岛提醒并可一键收回

## 订阅代理（Clash 订阅导入）

「订阅」页添加 Clash 系订阅地址即可，无需 FlClash 等第三方客户端：

- 内核为 mihomo sidecar（独立进程，GPL 边界清晰），首次开启角色时自动下载
  （钉版本 + SHA-256 内置校验，镜像仅作 CDN 加速，篡改可检出并拒绝落盘）
- 端口规范：mixed 入站 `127.0.0.1:57892`、控制面 `127.0.0.1:59292`（避让 Clash 7890/9090 系）
- 统一出口为派生行为（无开关）：订阅内核开启时，本地代理 57890 同时承载 AgileNet
  隧道流量与订阅流量——命中内网规则走隧道，其余流量回落订阅出口（57892）
- 订阅 URL 视为凭据：0600 存储、审计脱敏、不提供导出；卸载时可随清理项一并删除

## 与 Clash / FlClash 等代理工具共存

AgileNet 本地代理默认监听 `127.0.0.1:57890`（5 万段端口，刻意避开 Clash 系常用的 7890/7897/9090），
两种工具可以同时运行，互不影响。推荐组合方式：

### 方案 A（推荐）：FlClash 为主入口，AgileNet 作为其代理节点

系统代理保持 FlClash 不变，把 AgileNet 加为 Clash 的一个代理节点，只把内网网段分流进来。
在 FlClash 的「覆写 / Mixin」配置中加入：

```yaml
proxies:
  - name: AgileNet
    type: socks5
    server: 127.0.0.1
    port: 57890
rules:
  # 把管理员分配给你的内网网段指向 AgileNet，注意放在 rules 最前面
  - IP-CIDR,10.140.0.0/16,AgileNet,no-resolve
```

效果：访问内网网段 → AgileNet 隧道；其余流量 → 原 Clash 节点，互不影响。

### 方案 B：AgileNet 在前，Clash 兜底（限 FlClash TUN 模式）

系统代理指向 AgileNet `127.0.0.1:57890`：命中规则的流量进入隧道，未命中流量 DIRECT 直连。
此时若 FlClash 开着 TUN（虚拟网卡），直连流量仍会被 Clash 接管出口，两者自动叠加；
若 FlClash 仅是系统代理模式，未命中流量不会经过 Clash（Clash 被旁路），该场景请用方案 A。

### TUN 模式补充

FlClash 开 TUN 时，10.140.0.0/16 这类内网地址也会被虚拟网卡接管——按方案 A 配置规则即可
（TUN 同样按 Clash 规则分流）。AgileNet 的隧道端点是 127.0.0.1（loopback 默认不进 TUN），不受影响。

> 注意：如果浏览器访问内网目标时返回代理错误，先确认请求进的是 AgileNet 的端口（57890）
> 而不是 Clash 的 7890——Clash 没有内网路由时会直接失败，表现为截断的空响应。

## Windows 安装包

```bash
cd apps/desktop
cargo tauri build
# 产物：
#   target/release/bundle/msi/AgileNet_<version>_x64_en-US.msi
#   target/release/bundle/nsis/AgileNet_<version>_x64-setup.exe
```

安装包已内嵌 WebView2 Bootstrapper（无 WebView2 的机器自动引导安装）。

## 构建前置

| 平台 | 依赖 |
|------|------|
| 通用 | Rust stable（≥1.77）、`cargo install tauri-cli --version "^2"` |
| Windows | Visual Studio Build Tools（C++  workload）、WebView2（Win10+ 通常自带；打包配置已内嵌 Bootstrapper 兜底） |
| Android | Android Studio + SDK Platform 34 + NDK r26+，并设置 `ANDROID_HOME`、`NDK_HOME` |

## Windows 桌面

```bash
cd apps/desktop
cargo tauri dev        # 开发调试（热重载）
cargo tauri build      # 产出 release 安装包：src-tauri/target/release/bundle/{nsis,msi}
```

## Android

```bash
cd apps/desktop
cargo tauri android init          # 一次性生成 gen/android 工程
cargo tauri android dev           # 真机/模拟器调试
cargo tauri android build --apk   # 产出 APK（debug；发布需配置签名 keystore）
```

签名发布包：在 `gen/android/app/build.gradle.kts` 配置 `signingConfigs` 后执行
`cargo tauri android build --apk --aab`。

## 图标

`tauri.conf.json` 的 `bundle.icon` 当前为空（开发态）。正式发布前请生成：

```bash
cargo tauri icon path/to/source-icon.png   # 自动生成全平台图标到 icons/
```

## 架构说明

```
ui/ (HTML+JS)  ──IPC──>  src/lib.rs (Tauri commands)
                              │
                              ├─ connect_node / disconnect_node / list_nodes
                              ├─ start_proxy / stop_proxy / proxy_status
                              ├─ list_credentials（密码存 OS keyring，credentials.json 只留元数据，0600 文件回退）
                              └─ parse_connect_url（anet:// 接入链接解析，兼容 agilenet://）
                              │
                        agile-net-client 引擎（anet-svc client 同源）
                              │
                        agile-net-core（TLS 1.3 / mux / relay / proxy）
```
