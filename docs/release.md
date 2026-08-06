# 发布与分发指南

## 发布流程（全自动，无需本地构建）

```bash
git tag v0.2.0 && git push origin v0.2.0
```

推送 tag 后，`.github/workflows/release.yml` 在 GitHub runner 上并行构建全平台产物，
自动创建 GitHub Release 并挂载全部资产。也可在 Actions 页面手动触发（draft 草稿预检）。

构建全程在云 runner 完成；本地构建上传（`gh release create`）仅为备选，不是必须。

## 产物矩阵

### anet-svc（服务器二进制，start/stop/init/client/tui/doctor 子命令）

| 文件 | 平台 |
| --- | --- |
| `anet-svc-windows-x64.exe` | Windows 10/11 x64 |
| `anet-svc-linux-x64` | Ubuntu/Debian 等现代 glibc 发行版 |
| `anet-svc-linux-x64-musl` | **musl 静态链接：麒麟 V10 / 统信 UOS 等老 glibc 发行版首选** |
| `anet-svc-linux-arm64` | ARM64 服务器（鲲鹏、树莓派、云 ARM） |
| `anet-svc-macos-x64` | Intel Mac |
| `anet-svc-macos-arm64` | Apple Silicon Mac |

每个文件附带 `.sha256` 校验文件。龙芯（LoongArch）为 Rust tier-2 目标，暂未纳入流水线，
需要的场景请提 issue。

### anet-gui（图形客户端）

| 文件 | 平台 | 说明 |
| --- | --- | --- |
| `anet-gui_<ver>_x64-setup.exe` | Windows x64 | NSIS 安装器（支持静默安装 `/S`） |
| `anet-gui_<ver>_x64_en-US.msi` | Windows x64 | MSI（企业 GPO 分发友好） |
| `anet-gui_<ver>_x64.dmg` | macOS Intel | 未签名：首次打开需「右键 → 打开」绕过 Gatekeeper |
| `anet-gui_<ver>_aarch64.dmg` | macOS Apple Silicon | 同上 |
| `anet-gui_<ver>_amd64.deb` | Ubuntu/Debian | `sudo dpkg -i` 安装 |
| `anet-gui_<ver>_amd64.AppImage` | 通用 Linux | 免安装；麒麟/统信 GUI 场景优先验证此包 |
| `app-*-debug.apk` | Android 8.0+ (API 26) | debug 签名，可侧载；正式签名需配置 keystore secrets（见下） |

Windows 安装包附带 `SHA256SUMS.txt`；macOS/Ubuntu 包在各自 bundle 目录附带同名校验文件。

## 签名现状与后续

- **Windows**：未签名，SmartScreen 会提示「未知发布者」→ 「仍要运行」。消除需 EV 代码签名证书（`signtool` + secrets）。
- **macOS**：未签名未公证，Gatekeeper 拦截 → 右键打开即可。消除需 Apple 开发者账号（$99/年）
  并在 CI 配置证书与公证 secrets（`APPLE_CERTIFICATE` / `APPLE_SIGNING_IDENTITY` / `APPLE_ID` 等）。
- **Android**：debug 签名可侧载。正式发布需在仓库 secrets 配置 keystore
  （`KEYSTORE_BASE64` / `KEYSTORE_PASSWORD` / `KEY_ALIAS` / `KEY_PASSWORD`），
  并切换 `cargo tauri android build --apk`（release 签名）+ aab 上架 Play。
- **iOS**：未纳入流水线——需要 macOS + Xcode + Apple 开发者账号 + App Store 审核流程，
  属于独立工程（Tauri iOS 支持已就绪，crate-type 已含 staticlib）。

## 麒麟 / 统信说明

- **svc**：用 `anet-svc-linux-x64-musl`（静态链接，无 glibc 版本要求）；systemd unit 与
  Ubuntu 完全相同。龙芯版本需 loongarch64 工具链，未覆盖。
- **gui**：未出原生包。麒麟 V10 / 统信 UOS 自带 webkit2gtk，可先验证 AppImage；
  原生 deb 需在该发行版上执行 `cargo tauri build`（Tauri Linux 构建不宜交叉）。

## 验证安装包（用户侧）

```powershell
# Windows (PowerShell)
Get-FileHash .\anet-gui_0.2.0_x64-setup.exe
# 与 Release 页面 SHA256SUMS.txt 中的值比对
```

```bash
# Linux / macOS
sha256sum -c anet-svc-linux-x64.sha256
```
