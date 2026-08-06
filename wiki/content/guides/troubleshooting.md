# 故障排查与诊断

本指南整理了 AgileNet 在部署与运行过程中常见的故障场景、诊断方法与解决步骤。

本机环境类问题（端口占用、系统代理残留、TUN、订阅内核等）请先用 [自我诊断](#/guides/doctor) 一键巡检，多数项可当场自动修复；本页聚焦链路、证书、登录等跨端场景。

## 常用诊断方法与日志路径

### 日志定位

1. **anet-svc 节点日志**：
   - 默认标准输出（`stdout`）。
   - 配置文件或环境变量设置 `[log] dir = "logs"`（或 `AGILE_LOG_DIR=logs`）后，按天生成日志文件。
2. **anet-gui 审计日志**：
   - 角色切换与暴露操作审计落盘于 `~/.anet/gui/gui-audit.jsonl`（Windows 下为 `%USERPROFILE%\.anet\gui\gui-audit.jsonl`）。
3. **节点数据库审计**：
   - SQLite `audit_log` 表记录全量管理操作与登录事件，可通过 Web 后台、`anet audit list` 或 `anet tui` 查看。

---

## 常见问题排查

### 1. 证书固定不匹配 (Pinning Mismatch)

**现象**：客户端/下游节点无法连接上游，报 `certificate fingerprint mismatch` 或 `TLS handshake failed`。

**原因**：
- 上游节点重新生成了自签证书，但客户端保存的 `fp`（证书指纹）未同步更新。

**排查与解决**：
- **查看当前指纹**：登录上游节点 Web 后台在控制台概览中获取最新指纹，或执行：
  ```bash
  openssl x509 -in certs/relay-cert.pem -noout -fingerprint -sha256
  ```
- **更新客户端配置**：
  - `anet-gui`：重新导入最新的 `anet://connect?...` 接入链接。
  - `anet-svc client`：替换 `client.toml` 中 `nodes` 里对应的接入链接（指纹钉值内嵌于链接 `fp`/`entryfp` 参数）。

---

### 2. 域名解析与系统 Hosts 维护失败

**现象**：配置了 `resolve: true` 类型的 `host` 规则，但浏览器无法访问目标域名。

**原因**：
- 客户端维护系统 hosts 需要更高权限（Windows 下需要管理员身份，Linux/macOS 下需要 `sudo` / `root`）。

**排查与解决**：
- 确认以管理员权限运行 `anet-gui` 或 `anet-svc client`。
- 若无法提供 root/管理员权限，可关闭 `manage_hosts` 选项，改为仅使用 SOCKS5/HTTP 自动识别代理（`127.0.0.1:57890`）访问。

---

### 3. 端口冲突与被占用

**现象**：节点启动失败，报错 `Address already in use (os error 98 / 10048)`。

**默认端口一览**：
- 管理 API / Web 后台：`59090`
- Relay listener：`54430`
- 客户端本地代理：`57890`
- GUI 内嵌节点 API / Relay：`59293` / `54431`

**排查与解决**：
- 使用命令查找占用进程：
  ```bash
  # Linux / macOS
  lsof -i :59090
  # Windows
  netstat -ano | findstr 59090
  ```
- 在 `agile-net.toml` / `client.toml` 中将冲突端口修改为其他未被占用的端口（建议保持在 5 万段以规避 Clash 等其他软件）。

---

### 4. 登录锁定 (HTTP 429)

**现象**：Web 后台或 CLI 提示 `42900 Too Many Requests`，无法登录。

**原因**：
- 触发了防爆破安全机制（默认 1 分钟内失败超过 5 次，该 IP 被锁定 15 分钟）。

**解决**：
- 等待 15 分钟解锁倒计时结束。
- 忘记管理员密码：`anet admin reset-password admin --offline` 数据库直沉重置（本机操作，无需登录，会话一并吊销）。
