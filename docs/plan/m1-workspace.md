# M1：Workspace 骨架

## 目标

Cargo workspace 编译通过，三个 crate 建好，CI 流水线跑通，项目规范确立。

## 产出

1. `crates/core` — 空库 crate，导出占位模块（relay / proxy / tunnel / proto / config / error）
2. `crates/node` — 空二进制 crate，依赖 core，`main.rs` 打印版本号退出
3. `crates/client` — Tauri 项目骨架，空窗口可启动
4. `Cargo.toml` workspace 配置 + workspace.dependencies
5. `.github/workflows/ci.yml` — cargo check / clippy / test / fmt
6. `rustfmt.toml` + `clippy.toml` 项目规范
7. `.gitignore`

## 任务清单

- [ ] `cargo init --lib crates/core`
- [ ] `cargo init --bin crates/node`
- [ ] `cargo create-tauri-app crates/client`（或手动）
- [ ] 根 `Cargo.toml` workspace 配置
- [ ] core/src/lib.rs 导出空模块
- [ ] node/src/main.rs 读版本号打印
- [ ] client Tauri 空窗口
- [ ] CI 配置
- [ ] 代码规范配置

## 验收测试

### AT-M1-01：workspace 编译

```bash
cargo build --workspace
# 退出码 0，无 error
```

### AT-M1-02：Node 可运行

```bash
cargo run -p agile-net-node -- --version
# 输出: agile-net-node 0.1.0
```

### AT-M1-03：clippy 零警告

```bash
cargo clippy --workspace -- -D warnings
# 退出码 0
```

### AT-M1-04：格式化通过

```bash
cargo fmt --all -- --check
# 退出码 0
```

### AT-M1-05：CI 流水线绿色

```
GitHub Actions CI 全部 job pass
```

## 回归要求

无前序里程碑，本轮建立基线。后续所有里程碑的 CI 必须包含 M1 的 AT-M1-01 ~ AT-M1-04。
