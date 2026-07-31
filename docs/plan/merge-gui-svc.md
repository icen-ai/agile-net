# 计划：anet-gui / anet-svc 双产物统一与分布式管理面

> 状态：方向已确认（2026-07-31 多轮讨论收敛）。本文档为实施依据。
> 核心思想：**消灭 frps/frpc 式分裂**——上下游本就是同一个程序，最终只有两个产物。

## 0. 实施进度

- **P1 节点可嵌入化（已完成，2026-07-31）**：`crates/node` 装配根抽为 `service::NodeServer::start/stop`
  （main.rs 薄壳化；API 支持端口 0 动态分配回填；优雅停机）；`apps/desktop` 三路独立开关
  （客户端默认开 / 服务端默认关 / Web 远程面默认关，状态持久化 + `gui.role_toggle` /
  `web.exposure_change` 审计 JSONL）；服务端角色首开强制设管理密码（argon2id），
  内嵌实例默认端口避让（API 127.0.0.1:59290 / Relay 54431，数据于 `~/.agile-net/embedded-node/`）；
  控制台独立 Tauri 窗口复用内嵌节点 SPA；Web 远程面的密码基础设施就位，
  HTTP 服务本身随 P1.5 落地。测试：`crates/node/tests/service_test.rs`（start/serve/stop + 同库重启）。
- **P1.5 客户端管理面 Web 化（已完成，2026-07-31）**：`crates/client` 新增 `api` 模块——
  现有 ~15 个管理命令完整映射为 REST（统一 `{code,data}` 信封与错误码段）；
  管理鉴权与服务端同强度（argon2id 密码哈希 + HS256 JWT 12h + 登录按 IP 限流 5 次/分钟、
  连续失败锁 15 分钟 + 登录/导出审计回调）；凭据导出强制 `confirm=true` 二次确认；
  SPA 静态资产由宿主 include_str! 内嵌并附带 CSP 安全头。
  桌面端 `invoke` 桥双传输：Tauri 窗口内走 IPC，浏览器（Web 远程面）走 HTTP fetch
  （命令→REST 映射表 + 401 自动回登录框）；浏览器模式隐藏本机专属 UI（窗口控制/自启/角色卡）。
  开关C 启停即启停 Web API（默认 127.0.0.1:59291，LAN 暴露为显式配置并告警）。
  `parse_connect_url` / `connect_url_of` 上移至 agile-net-client 供 IPC 与 REST 共用。
  测试：`crates/client/tests/web_api_test.rs`（鉴权信封/限流锁定/导出二次确认+审计/规则暂停/SPA）。
- **P1.6 管理版接入链接（已完成，2026-07-31）**：
  - 服务端：DB 迁移 v2（`account.admin_console` + `admin_ticket` 表）；
    创建/更新账号可授予「管理此节点」权限（控制台勾选 + 强警示 + `account.issue_admin_link` 签发审计），
    管理版 `connect_url` 带 `&admin=1` 变体；配置响应带 `admin_console` 标记；
    新增 `POST /api/v1/client/console-ticket`（10 分钟一次性票据，库中只存哈希）与
    `POST /api/v1/auth/admin-bootstrap`（票据换管理会话，原子计次防重放）；
    JWT 增加 `scope` 声明（ro/rules/full 三档，AdminAuth 强制、未知档位 fail-closed）；
    `admin_console` 账号数据面隐式放开节点 loopback API（收回即失管理通路）。
  - 客户端/GUI：引擎保存节点级 access token（watcher 轮换同步）+ `console_ticket()`/`opener()`；
    桌面 `open_node_console`——loopback 转发器（本地环回端口 → 客户端隧道 → 节点 API）+
    独立 Tauri 窗口 `#boot=ticket` 自举管理会话；节点卡片「管理此节点」入口与「可管理」徽标；
    管理链接导入警示；审计 `admin.console_access`（operator 以 `link:`/`relay:` 前缀区分令牌级会话）。
  - 测试：`crates/node/tests/admin_link_test.rs`（全链路/未授权拒绝/scope 三档/授予与收回）。
- **P2 协议项（已完成，2026-07-31）**：
  - `relay_token.expose_control`：DB 迁移 v3（开关 + `control_scope` 档位）；创建/更新 API
    （`relay_token.expose_control` 审计必落：令牌前缀、on/off、档位、操作人）；
    控制台令牌页勾选「允许该下游中继管理本节点」+ ro/rules/full 档位选择 + 强警示。
  - 握手 v2：AuthOk 载荷向后兼容扩展 `control`（exposed/api_host/api_port/node_name/ticket/scope）；
    旧下游忽略未知字段，版本号保持 2 不割裂。暴露即签发管理引导票据
    （kind=relay，subject=`psk_前缀@下游节点`，7 天/限次，只存哈希；
    安全边界等同中继令牌——吊销+踢会话即全线回收）。
  - 可管理节点自动发现：connector 记录 `control_offer`；下游节点注册表同步 →
    管理版客户端 config 收到 `manageable` 列表（GUI 节点卡片「可管理上游」入口）；
    `admin_console` 账号数据面隐式放开上游端点（host/32 或精确主机）。
  - 控制台通道：`POST /api/v1/client/console-ticket {upstream}` 返回握手当前票据；
    桌面 `open_upstream_console`——loopback 转发器经当前节点隧道直达上游 API + `#boot` 自举；
    换取审计 `admin.session_via_relay`（operator=`relay:psk_前缀@下游`）。
  - 路由再发布：connector 注入客户端引擎合并路由与开启器（`with_client_routes`），
    通告集 = 静态 + 客户端规则值，规则集变化自动重连重新通告（不引入新帧类型）；
    Open 命中再发布规则时经对应客户端隧道转发（via=客户端隧道）。
    GUI 服务端面板可选上游中继配置（保存即热重启内嵌节点）。
  - 测试：`crates/node/tests/control_plane_test.rs`（双节点握手发现 + 票据链 + 档位强制 +
    开关审计 + 迁移幂等）；docker 链路断言新增 T7（管理面穿透 E2E）。
- **P3 改名打包（已完成，2026-07-31）**：
  - `agile-net-node` → **`anet-svc`**：子命令 `serve`（默认）/ `tui` / `client` / `cli`；
    原 `anet` CLI 收编为 `crates/node::cli` 模块（cli crate 删除，消除 cli→node 反向依赖）；
    原 `agile-net-client` daemon 收编为 `agile_net_client::daemon`（client [[bin]] 移除）。
  - `agilenet-desktop` → **`anet-gui`**（package/bin/productName；identifier `ai.icen.agilenet` 保持不变以保证升级兼容）。
  - Dockerfile 单产物（anet-svc）；编排命令全部 `anet-svc serve`；链路测试客户端改用 `anet-svc client`；
    CI 链路门禁标签 T1-T7；README/AGENTS/apps README 同步。
  - crate 包名（agile-net-node/client/core）保留——产物指二进制，包名不动以减少迁移面。
- 状态：**全部分期完成**。
## 1. 终态产物

| 产物 | 内容 | 场景 |
| --- | --- | --- |
| `anet-gui`（exe/msi/dmg/apk） | 客户端引擎 + 内嵌完整节点 + 图形界面 | 办公终端、内网转发机、机房留守机 |
| `anet-svc`（Linux/Win 服务器） | 同一内核无 GUI：`serve`（默认）/ `tui` / `cli` 子命令 | 服务器中继、网关 |

`agile-net-client.exe` / `anet.exe`（CLI）作为独立产物消失，能力收编进 svc 的角色与子命令。

## 2. anet-gui 的三路独立开关

- **开关A 客户端角色**：连上游、本地代理、路由组合（现有能力）
- **开关B 服务端角色**：内嵌完整节点（relay listener/connector、账号/规则/令牌/审计、SQLite）
- **开关C Web 远程面**：把管理 UI 经 HTTP(S) 暴露（监听地址可选 127.0.0.1 / LAN / 仅隧道侧，强制先设管理密码）

组合示例：办公机只开 A；转发机只开 B；机房留守机 A+B+C 全开（替代向日葵远程桌面）。

## 3. 体积与内存结论（实测，2026-07-31）

release 实测：node 13.6MB / client 8.0MB / 现 GUI 16.2MB（安装包 NSIS 5.4MB、MSI 8.4MB）。
合并后 anet-gui ≈ 20~22MB、安装包 ≈ 7~9MB；运行内存 60~68MB（节点增量 ~10MB，大头是 WebView2 与合并无关）。
argon2id 64MB 为登录瞬时尖峰，亚秒释放。结论：可接受，不构成合并障碍。

## 4. 管理面架构：带内管理（穿透）为根基

关键决断（对比见 §5）：**管理流量当普通内网 HTTP 走数据面隧道**，控制台只是内网里的一个 web 站点。

- **控制台通道**：GUI 内置 loopback 转发器（本地环回端口 → 本地代理 → 目标节点 API），
  控制台窗口/浏览器打开 `127.0.0.1:58xxx` 即加载远端节点的管理 SPA，无需配浏览器代理。
- **端到端**：管理 HTTP 可在隧道 TLS 内再套 HTTPS；中继节点只见密文转发。
- **ACL 统一**：能否管理某节点 = 有没有到其 API 地址的规则；收回规则即失去管理通路。
- **审计归因到人/到令牌**：不用 D 的共享会话，每条操作落真实身份。

### 4.1 Relay 链接的「暴露控制面」开关（本设计的核心新增）

- `relay_token` 记录新增 `expose_control` 字段（DB 迁移 + 控制台勾选框
  「允许该下游中继管理本节点」，默认关）。
- Relay 握手 v2：下游 connector 握手时，若其令牌带暴露标记，响应携带
  `control = { exposed: true, api: "<监听地址>" }`。
- 下游节点记录「可管理上游」并随其管理面下发；持管理版接入链接的客户端拉配置时
  收到 `manageable` 列表 → **GUI 设备列表自动发现可管理节点（本机/已连节点/上游链）**。
- 管理身份：psk_ 持有者在数据面已是高信任凭据（可通告网段），暴露开关打开后凭
  中继会话直接换取管理会话（零开通）；审计记为 `via relay-token psk_***（备注）`，
  吊销令牌即全线回收。P2 细化为 只读/可改规则/全权 三档 scoped admin。

### 4.2 管理版接入链接（P1.6）

- 控制台创建客户端账号时可勾选「同时授予管理权限」，生成 `agilenet://connect?...&admin=...`
  变体；生成页强警示 + 审计签发。
- 客户端连接后配置响应带 `admin_console: true` → GUI 节点卡片出现「管理此节点」，
  灵动岛提示「该节点已开放管理权限」。

## 5. 被否决方案存档（D 代理路线）

「C → D 控制台 → D 后端代理转发 → EFG」：D 须存全网 admin 会话（凭据库单点）、
EFG 审计只见 D 不见人、另需一套委托权限。保留为二期「有限委托管理」（转发带真实操作人
身份头）的候选，不作基础路径。

## 6. 场景验证矩阵

| 场景 | 构成 | 状态 |
| --- | --- | --- |
| 四级链穿透（root→mid→leaf→deep→target） | 现有 relay 桥接 | 已验证（docker 断言 T1-T6） |
| EFG(机房 svc) — D(机房 GUI：relay 下游 + 开发者上游 + Web) | A+B+C 全开 | 依赖 P1/P1.5 |
| C(外地开发 GUI) 管理版链接连 D，与坐在 D 前同等体验 | 控制台通道 + 管理链接 | 依赖 P1.6 |
| C 经 D 穿透管理 EFG（D↔EFG 为 relay + 暴露开关） | §4.1 | 依赖 P2 协议项 |
| FlClash 共存（AgileNet 作 Clash 的 socks5 节点按 CIDR 分流） | apps/README 已文档化 | 已完成 |

## 7. 分期

- **P1 节点可嵌入化**：`crates/node` 装配根抽为 `NodeServer::start/stop`；GUI 三路开关；
  控制台独立窗口（SPA 复用）；内嵌实例默认端口与本地节点避让
- **P1.5 客户端管理面 Web 化**：前端 invoke 桥双传输（Tauri IPC / HTTP fetch）+
  REST 映射现有 ~15 个命令 + 管理鉴权
- **P1.6 管理版接入链接**：admin 参数 + `admin_console` 标记 + 节点卡片管理入口
- **P2 协议项**：relay_token.expose_control + 握手 v2 + 可管理上游发现下发；
  scoped admin 三档；路由再发布（客户端收到的规则转售给下游，规则 via=客户端隧道）
- **P3 改名打包**：anet-gui / anet-svc；cli 并入 svc 子命令；CI / docker / 文档

## 8. 安全边界

- Web 面默认 127.0.0.1，暴露 LAN/隧道侧为显式开关，强制管理密码
- 客户端 Web API 与服务端同强度鉴权（argon2id + JWT + 限流 + 审计）
- 凭据导出/接入链接经 Web 暴露需二次确认
- 暴露控制面开关默认关；管理会话审计必带来源（IP + 账号/令牌）

## 9. 审计日志（管理面新增事件）

现有机制：敏感操作（登录/增删改/启停/重置/吊销）经 `record_audit_log` 落 `audit_log` 表
（operator / action / target / detail / 来源 IP，90 天留存自动清理），严禁记录任何
密码/Token 明文。统一与分布式管理面引入的新事件：

| action | 触发 | detail 必含 |
| --- | --- | --- |
| `account.issue_admin_link` | 签发管理版接入链接 | 目标账号、操作人、来源 IP |
| `relay_token.expose_control` | 暴露控制面开关变更 | 令牌前缀、on/off、操作人 |
| `admin.session_via_relay` | 中继令牌换得管理会话 | 令牌前缀、下游节点名、来源（隧道） |
| `admin.console_access` | 经控制台通道访问某节点管理面 | 目标节点、访问者身份（账号或令牌）、路径（本机/隧道层级） |
| `gui.role_toggle` | GUI 三路开关变更 | 角色（client/server/web）、on/off、本机用户 |
| `web.exposure_change` | Web 面监听地址/启停变更 | 新地址、操作人 |

原则：每条管理操作必须能回答「谁、从哪条路径（本机/隧道第几级/经哪个中继）、
对哪台设备、做了什么」；令牌级会话与真人账号在 operator 字段明确区分
（`relay:psk_前缀` vs 用户名）。
