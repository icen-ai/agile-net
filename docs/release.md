# 发布与分发指南

## 安装包产出

CI（tag `v*` 推送）自动构建并发布到 GitHub Release：

| 产物 | 说明 |
|------|------|
| `AgileNet_<ver>_x64-setup.exe` | NSIS 安装器（推荐，支持静默安装 `/S`） |
| `AgileNet_<ver>_x64_en-US.msi` | MSI（企业 GPO 分发友好） |
| `SHA256SUMS.txt` | 全部产物的 SHA-256 校验和 |

本地构建：`cd apps/desktop && cargo tauri build`，校验和生成：

```powershell
# Windows (PowerShell)
Get-FileHash .\target\release\bundle\nsis\AgileNet_*-setup.exe -Algorithm SHA256
# Linux/macOS
sha256sum target/release/bundle/{msi,nsis}/*
```

## 验证安装包（用户侧）

```powershell
Get-FileHash .\AgileNet_0.1.0_x64-setup.exe
# 与 Release 页面 SHA256SUMS.txt 中的值比对
```

## 关于 Windows SmartScreen

未签名安装包会触发 SmartScreen 提示「未知发布者」。企业级消除方式：

1. **代码签名证书**（推荐）：OV/EV 证书（DigiCert/Sectigo 等），然后：
   ```powershell
   signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 `
     AgileNet_0.1.0_x64-setup.exe
   ```
   EV 证书可立即获得 SmartScreen 信誉；OV 需要积累。
2. **企业内分发**：通过 GPO/MDM 推送 MSI，不经过 SmartScreen。
3. 临时方案：用户点击「更多信息 → 仍要运行」，并核对 SHA256SUMS。

## 自动更新（tauri updater）

Tauri 2 updater 需要：签名密钥对 + 静态更新清单（latest.json）+ 客户端插件。
启用路径（需要长期维护的更新服务器或静态托管）：

```bash
cargo tauri signer generate -w ~/.tauri/agilenet.key
```

- 私钥放 CI Secrets（`TAURI_SIGNING_PRIVATE_KEY` + `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`）
- 公钥写入 `tauri.conf.json` 的 `plugins.updater.pubkey`
- `endpoints` 指向 `https://<host>/agilenet/latest.json`（由 release job 生成）

未启用 updater 前，以 Release 页面 + SHA256SUMS 手动分发为准。

## 版本号

- 工作区版本：`Cargo.toml` `[workspace.package] version`
- 安装包版本：`apps/desktop/tauri.conf.json` `version`（发布时保持一致）
