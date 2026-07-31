# AgileNet 客户端应用（桌面 & Android）

`apps/desktop` 是基于 **Tauri 2** 的跨平台客户端，前端为原生 HTML/JS（无 Node 构建链），
后端直接复用 `agile-net-client` 引擎（与 CLI/daemon 同一数据面）：

- **Windows** 桌面应用（`.exe` / `.msi`，内嵌 WebView2 Bootstrapper）
- **Android** 应用（`.apk` / `.aab`，Tauri 2 Mobile）
- macOS / Linux 亦可构建（未实测）

## 功能

- **空状态引导**：未连接节点时展示三步接入引导，粘贴框自动聚焦
- **剪贴板识别**：一键识别剪贴板中的 `agilenet://` 接入链接并导入
- 快速接入：粘贴 `agilenet://connect?...` 链接一键导入连接（含 sk- 强密码）
- 手动添加：地址 / 账号 / 密码 / 证书固定 PEM / insecure 开关 / hosts 管理
- 节点管理：多节点连接、实时状态徽标（连接中/重连中脉冲动画）、断开、凭据保存与自动重连
- 本地代理：127.0.0.1 端口启停（SOCKS5 / HTTP 自动识别），可配置连接节点后自动启动
- **系统托盘**：关闭窗口最小化到托盘，右键菜单（显示主窗口 / 代理开关 / 退出），双击唤起
- **开机自启**：设置中一键开启/关闭（Windows 注册表 Run 项 / macOS LaunchAgent）
- 合并路由视图：全部已连接节点规则的实时汇总
- 错误翻译：底层网络错误自动转为用户友好的中文提示

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
                              ├─ list_credentials（~/.agile-net/credentials.json, 0600）
                              └─ parse_connect_url（agilenet:// 接入链接解析）
                              │
                        agile-net-client（引擎）
                              │
                        agile-net-core（TLS 1.3 / mux / relay / proxy）
```
