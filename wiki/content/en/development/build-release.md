# Build, Test, and Release

## Build

```bash
# anet-svc（workspace 成员 agile-net-node）
cargo build --release -p agile-net-node        # target/release/anet-svc

# anet-gui（独立 workspace）
cd apps/desktop && cargo tauri build           # 安装包于 target/release/bundle/
```

Rust stable (edition 2024); Tauri 2 + system webkit dependencies (Linux: `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`).

## Test

```bash
cargo test --workspace          # 单元 + 集成（含双节点握手、票据链、scope 强制）
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check

# Docker 四级链断言 T1-T7
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up --abort-on-container-exit --exit-code-from tester
```

> Windows: before running tests, make sure no project exe is running (file locks); if demo processes are up, use
> `CARGO_TARGET_DIR=target/ci cargo test --workspace` to switch the target directory.

## CI Gates (.github/workflows/ci.yml)

- check & clippy (`-D warnings`), fmt, full workspace tests
- Docker four-level chain assertions T1-T7
- desktop-check (cargo check of apps/desktop on Ubuntu)

## Release (Fully Automated)

```bash
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/release.yml` builds in parallel and attaches the artifacts to a GitHub Release:

- **anet-svc**: windows-x64 / linux-x64 / linux-x64-musl (static linking for Kylin / UOS) / linux-arm64 / macOS dual-arch (each with a .sha256)
- **anet-gui**: Windows (msi+nsis+SHA256SUMS) / macOS dual-arch dmg / Ubuntu (deb+AppImage) / Android (debug-signed apk)

Manual triggering from the Actions page is also supported (draft pre-flight check).

## Production Signing (Follow-up, Requires Secrets)

| Platform | Required |
| --- | --- |
| Windows | EV code-signing certificate (signtool + secrets) |
| macOS | Apple Developer account: certificate and notarization secrets |
| Android | keystore secrets (`KEYSTORE_BASE64` etc.), switch to release signing + aab |
| iOS | Apple Developer account + a separate project (not yet in the pipeline) |

## Documentation Site (wiki/)

The source of this documentation site lives in the repo under `wiki/`; it has no build chain (vanilla JS + locally embedded marked) and deploys to Cloudflare Pages:

```bash
wrangler pages deploy wiki --project-name anet
```
