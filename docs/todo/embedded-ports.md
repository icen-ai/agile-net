# GUI 内嵌端口动态化 / 可配置（待办）

> 来源：用户实测反馈（2026-08-04）——Windows 测试机 Hyper-V 动态保留段（59280-59379）覆盖内嵌 API 端口
> 59293，绑定报 os error 10013（WSAEACCES），管理员权限无效；同机 54431 又被残留实例占用。
> 相关修复（已完成）：绑定失败带地址上下文 + GUI 自查引导、relay 绑定失败不再被吞、启动中途失败清场（StartupGuard）。

---

## 问题

内嵌节点端口为写死常量（`apps/desktop/src/roles.rs:15-16`）：

- `EMBEDDED_API_ADDR = 127.0.0.1:59293`（管理 API，进程内部自用）
- `EMBEDDED_RELAY_ADDR = 0.0.0.0:54431`（relay 扇入监听，对外）

Hyper-V/WSL2/Docker 的 winnat 动态保留段是**随机的**（每次保留连续 100 端口，范围落在动态端口段内），
落在 5 万段是常态。碰撞时内嵌节点完全起不来，目前只能靠用户手搓
`net stop winnat` + `netsh int ipv4 add excludedportrange` 恢复，普通用户无法自助。

## 方案

### P1 — 内嵌 API 端口动态化

管理 API 是进程内部自用（GUI 内嵌控制台 iframe、热操作），没有任何对外稳定性的必要：

- `NodeServerOptions.api_listen` 传 `127.0.0.1:0`，启动后读回 `server.api_addr()`（动态端口回填已支持，
  见 `service/mod.rs` 注释 "supports port 0 dynamic allocation"）；
- 所有引用 `EMBEDDED_API_ADDR` 的地方（控制台入口 `console_url`、热操作、状态展示）改为从运行中的
  server 句柄读回实际地址；未运行时的展示文案降级为「-」；
- 彻底免疫保留段碰撞。

### P2 — relay 端口设置项可改

relay 是对外地址（扇入端要连它），需要稳定，但必须给用户换端口的出路：

- 设置（或扇出监听卡片）加「Relay 监听端口」项，默认 54431，保存写库/设置文件，下次启动服务端角色生效；
- 绑定失败时按已落地的引导（10013/10048 中文提示）引导用户改端口；
- `public_host` 已支持（node_config.public_host 热生效，2026-08-04 落地）；端口与之一并构成完整的对外端点配置。

## 注意

- 改端口后需同步提醒：防火墙入站放行、对端 connect_url/扇出配置里的地址同步更新。
- winnat 保留段规避的另一思路是端口挑 5 万段以外（如 4 万段），但只是降低概率，不如动态化彻底。
