# 安装

AgileNet 有两个产物：**anet-svc**（服务器）与 **anet-gui**（图形客户端）。全部安装包在
[GitHub Releases](https://github.com/icen-ai/agile-net/releases) 发布，每个文件附带 SHA-256 校验。

## anet-svc（服务器 / 中继 / 网关）

| 文件 | 平台 | 说明 |
| --- | --- | --- |
| `anet-svc-windows-x64.exe` | Windows 10/11 x64 | 直接运行 |
| `anet-svc-linux-x64` | Ubuntu / Debian 等现代 glibc 发行版 | `chmod +x` 后运行 |
| `anet-svc-linux-x64-musl` | **麒麟 V10 / 统信 UOS 等老 glibc 发行版** | musl 静态链接，无 glibc 版本要求 |
| `anet-svc-linux-arm64` | ARM64 服务器（鲲鹏、树莓派、云 ARM） | |
| `anet-svc-macos-x64` / `anet-svc-macos-arm64` | Intel / Apple Silicon Mac | |

校验与启动：

```bash
sha256sum -c anet-svc-linux-x64.sha256
chmod +x anet-svc-linux-x64
./anet-svc --version          # anet-svc 0.1.0
./anet-svc serve              # 默认子命令，读取 ./agile-net.toml（缺省配置自动可用）
```

### systemd（Linux 常驻）

```ini
# /etc/systemd/system/anet-svc.service
[Unit]
Description=AgileNet anet-svc
After=network.target

[Service]
WorkingDirectory=/opt/agile-net
ExecStart=/opt/agile-net/anet-svc serve /opt/agile-net/agile-net.toml
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now anet-svc
```

### 源码构建

```bash
git clone https://github.com/icen-ai/agile-net
cd agile-net
cargo build --release -p agile-net-node    # 产物：target/release/anet-svc
```

## anet-gui（图形客户端）

| 文件 | 平台 | 说明 |
| --- | --- | --- |
| `anet-gui_<ver>_x64-setup.exe` | Windows x64 | NSIS 安装器，支持静默安装 `/S` |
| `anet-gui_<ver>_x64_en-US.msi` | Windows x64 | MSI，企业 GPO 分发友好 |
| `anet-gui_<ver>_x64.dmg` / `_aarch64.dmg` | macOS Intel / Apple Silicon | 未签名：首次「右键 → 打开」 |
| `anet-gui_<ver>_amd64.deb` | Ubuntu / Debian | `sudo dpkg -i` |
| `anet-gui_<ver>_amd64.AppImage` | 通用 Linux（麒麟/统信优先验证此包） | `chmod +x` 免安装 |
| `app-*-debug.apk` | Android 8.0+ (API 26) | debug 签名，可侧载 |

> **签名现状**：Windows 未签名（SmartScreen 提示属预期，「仍要运行」即可）；
> macOS 未签名未公证（右键打开）；Android 为 debug 签名侧载包。
> 各平台正式签名所需的证书与 secrets 配置见「开发 → 构建、测试与发布」。

## 端口约定

默认端口统一在 5 万段，规避 Clash 系常用端口：

| 用途 | 默认端口 |
| --- | --- |
| 管理 API / Web 后台 | `59090` |
| Relay listener（数据面） | `54430` |
| 客户端本地代理 | `57890` |
| anet-gui 内嵌节点 API | `59290`（避让本地独立节点） |
| anet-gui 内嵌节点 Relay | `54431` |
| anet-gui Web 远程面 | `59291`（仅 127.0.0.1） |
