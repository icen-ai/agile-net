# 构建、测试与发布

## 构建

```bash
# anet-svc（workspace 成员 agile-net-node）
cargo build --release -p agile-net-node        # target/release/anet-svc

# anet-gui（独立 workspace）
cd apps/desktop && cargo tauri build           # 安装包于 target/release/bundle/
```

Rust stable（edition 2024）；Tauri 2 + 系统 webkit 依赖（Linux：`libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`）。

## 测试

```bash
cargo test --workspace          # 单元 + 集成（含双节点握手、票据链、scope 强制）
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check

# Docker 四级链断言 T1-T7
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up --abort-on-container-exit --exit-code-from tester
```

> Windows：测试前确认没有正在运行的本项目 exe（文件锁），演示进程在跑时用
> `CARGO_TARGET_DIR=target/ci cargo test --workspace` 换目录。

## CI 门禁（.github/workflows/ci.yml）

- check & clippy（`-D warnings`）、fmt、workspace 全量测试
- Docker 四级链断言 T1-T7
- desktop-check（Ubuntu 上 cargo check apps/desktop）

## 发布（全自动）

```bash
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/release.yml` 并行构建并挂载 GitHub Release：

- **anet-svc**：windows-x64 / linux-x64 / linux-x64-musl（麒麟·统信静态链接）/ linux-arm64 / macos 双架构（各附 .sha256）
- **anet-gui**：Windows（msi+nsis+SHA256SUMS）/ macOS 双架构 dmg / Ubuntu（deb+AppImage）/ Android（debug 签名 apk）

也支持 Actions 页面手动触发（draft 草稿预检）。

## 正式签名（后续项，需 secrets）

| 平台 | 需要 |
| --- | --- |
| Windows | EV 代码签名证书（signtool + secrets） |
| macOS | Apple 开发者账号：证书与公证 secrets |
| Android | keystore secrets（`KEYSTORE_BASE64` 等），切 release 签名 + aab |
| iOS | Apple 开发者账号 + 独立工程（未纳入流水线） |

## 文档站（wiki/）

本文档站源码在仓库 `wiki/`，无构建链（原生 JS + 本地内嵌 marked），部署 Cloudflare Pages：

```bash
wrangler pages deploy wiki --project-name anet
```
