# Installation

AgileNet ships two artifacts: **anet-svc** (server) and **anet-gui** (graphical client). All packages are published on
[GitHub Releases](https://github.com/icen-ai/agile-net/releases), each with a SHA-256 checksum.

## anet-svc (Server / Relay / Gateway)

| File | Platform | Notes |
| --- | --- | --- |
| `anet-svc-windows-x64.exe` | Windows 10/11 x64 | Run directly |
| `anet-svc-linux-x64` | Ubuntu / Debian and other modern glibc distros | `chmod +x`, then run |
| `anet-svc-linux-x64-musl` | **Kylin V10 / UOS and other older-glibc distros** | Statically linked with musl, no glibc version requirement |
| `anet-svc-linux-arm64` | ARM64 servers (Kunpeng, Raspberry Pi, cloud ARM) | |
| `anet-svc-macos-x64` / `anet-svc-macos-arm64` | Intel / Apple Silicon Mac | |

Verify and start:

```bash
sha256sum -c anet-svc-linux-x64.sha256
chmod +x anet-svc-linux-x64
./anet-svc --version          # anet-svc 0.1.0
./anet-svc start              # 读取 ./agile-net.toml（缺省配置自动可用）
```

### systemd (Linux, persistent)

```ini
# /etc/systemd/system/anet-svc.service
[Unit]
Description=AgileNet anet-svc
After=network.target

[Service]
WorkingDirectory=/opt/agile-net
ExecStart=/opt/agile-net/anet-svc start /opt/agile-net/agile-net.toml
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now anet-svc
```

### Build from Source

```bash
git clone https://github.com/icen-ai/agile-net
cd agile-net
cargo build --release -p agile-net-node    # 产物：target/release/anet-svc
```

## anet-gui (Graphical Client)

| File | Platform | Notes |
| --- | --- | --- |
| `anet-gui_<ver>_x64-setup.exe` | Windows x64 | NSIS installer, supports silent install with `/S` |
| `anet-gui_<ver>_x64_en-US.msi` | Windows x64 | MSI, friendly for enterprise GPO distribution |
| `anet-gui_<ver>_x64.dmg` / `_aarch64.dmg` | macOS Intel / Apple Silicon | Unsigned: right-click → Open on first launch |
| `anet-gui_<ver>_amd64.deb` | Ubuntu / Debian | `sudo dpkg -i` |
| `anet-gui_<ver>_amd64.AppImage` | Generic Linux (preferred for Kylin/UOS verification) | `chmod +x`, no install needed |
| `app-*-debug.apk` | Android 8.0+ (API 26) | Debug-signed, sideloadable |

> **Signing status**: Windows builds are unsigned (a SmartScreen prompt is expected — choose "Run anyway");
> macOS builds are unsigned and not notarized (right-click → Open); Android builds are debug-signed sideload packages.
> See "Development → Build, Test & Release" for the certificates and secrets required for production signing on each platform.

## Port Conventions

Default ports all live in the 50k range to avoid ports commonly used by Clash-family tools:

| Purpose | Default Port |
| --- | --- |
| Management API / Web dashboard | `59090` |
| Relay listener (data plane) | `54430` |
| Client local proxy | `57890` |
| anet-gui embedded node API | `59293` (avoids a standalone local node and the Docker demo chain mapping on 59290) |
| anet-gui embedded node Relay | `54431` |
| anet-gui Web remote panel | `59291` (127.0.0.1 only) |
