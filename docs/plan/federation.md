# 联邦模型 P1 实施计划（Rendezvous 链接与策略上送）

> 设计蓝本：`docs/todo/federation.md`（§2 关键设计决策为约束，不得偏离）
> 范围：仅 P1（管理面，无新加密）；P2/P3 不在本计划
> 状态：**已落地**（2026-08-04；`cargo test --workspace` 345 全绿 + clippy 双 workspace 零告警；
> 端到端验收 `crates/node/tests/federation_test.rs`、协议/池化 `crates/core/tests/relay_test.rs`）

---

## 1. 链接层：`anet://` 统一格式与解析器（§2.7 落地）

**链接形态（三件套：入口地址 + 凭证 + 入口证书指纹）**：

- 扇入账号：`anet://connect?server=H&port=P&account=U&password=W&fp=FP[&admin=1]`
- 扇出对端：`anet://fanout?server=H&port=P&token=psk_...&sni=SNI&fp=FP`
- `server` 允许 `https://host[:port]` 完整形式（API 反代场景，此时忽略 `port` 参数）
- 生成一律新 scheme；解析器兼容旧 `agilenet://`（平滑迁移，旧链接永久可解析）

**解析器（全部表单共享同一解析器）**：

- 共享 JS：`apps/desktop/ui/aglink.js`（双端唯一实现，桌面 `<script src>`、管理端 `/ui/aglink.js` include_str! 内嵌，同 agchart.js 机制）
  - `AgLink.parse(url)` → `{ role: 'connect'|'fanout', ...fields }` 或 `{ error }`
  - `AgLink.buildConnect(fields)` / `AgLink.buildFanout(fields)`
- Rust：`crates/client/src/connect_url.rs` 双 scheme 兼容 + `ParsedFanout` / `parse_fanout_url` / `fanout_url_of`（桌面深链路由与凭据导出复用）

## 2. DB v9 迁移

```sql
-- 策略上送：扇出时随握手推送的本地权限组（逗号分隔 group ids；空 = 不上送）
ALTER TABLE connector ADD COLUMN push_groups TEXT NOT NULL DEFAULT '';
```

## 3. 协议扩展（向后兼容）

- `AuthRequest.groups: Vec<PushedGroupMsg>`（`#[serde(default)]`，老上游 serde 忽略未知字段）
  - `PushedGroupMsg { name, remark, rules: Vec<String> }`
- 下游：`RelayConnector` 注入 `Arc<ArcSwap<Vec<PushedGroupMsg>>>`，握手时随 Auth 上送；
  ConnectorManager 从 DB（connector.push_groups → 组+规则）装配；config_version 变化热更 slot，
  connector run 循环检测 slot 变化自动重连上送（复用 client_router 再广告模式，无新帧类型）
- 上游：`AuthIdentity::Node` 增加 `groups` 字段；`RelayListener` 新增
  `peer_groups: DashMap<node_id, Vec<PushedGroupMsg>>`（会话建立写入、断开清除）+ getter

## 4. 服务端 API

- `GET /api/v1/admin/federation/offered` → 可授权池：在线下游节点的
  `{ node_id, online, advertise: [...], groups: [{ name, remark, rules: [...] }] }`；
  每组折叠本地采纳状态（`adopted` / `adopted_id` / `adopted_name`——采纳中心的待采纳/跟随中分栏）
- `POST /api/v1/admin/federation/adopt { node_id, group }` → 一键采纳为本地组：
  规则逐条复用（同 type+value 命中既有 rule）或新建；组名 = `组名@节点ID`（命名空间隔离，
  重名追加 `·2` 后缀）；审计 `federation.adopt`。**幂等**：同一上送组重复采纳返回既有镜像
  （`already: true`）。**采纳组为只读活镜像**（DB v12 血缘列 `adopted_node/adopted_name`）：
  同步引擎逐 watcher tick 跟随源的规则与 E2E 标记（仅漂移写；源离线保留最后快照），
  组更新/绑规则写入口拒绝（先复制再编辑）；`POST …/federation/adopted/{id}/copy`
  复制为可编辑本地组（审计 `federation.copy`）
- relay token 创建响应新增 `share_url` + `endpoints`（见 §5）
- `GET /api/v1/admin/node/status` 新增 `endpoints: { public, lan: [...] }` 与 `public_api_url`
- `PUT /api/v1/admin/node/settings` 新增 `public_api_url`（反代端点，见 §6）
- 账号 `connect_url` 生成统一收口：`public_api_url`（scheme+host+port 覆盖）> `public_host` + api_port

## 5. 签发链接化（扇入令牌 + 账号）

**地址来源优先级**（§4-P1）：对外声明（`public_host`，域名或公网 IP）> 本机地址。
「公网会合点」身份即 public_host 的产品化声明，不引入 STUN 类外部探测（保持零外网依赖）。

- 扇入令牌创建成功：返回 `share_url`（anet://fanout 完整链接）+ `endpoints` 数组
  `[{ kind: "public", addr } | { kind: "lan", addr }]`（lan = 本机非回环 IPv4 枚举，
  复用 default-net，anet tool 已有该依赖）
- 账号创建/重置：`connect_url`（默认 public 端点）+ `endpoints`；前端弹窗端点切换即重拼
  （密码仅此一次返回，切换在前端完成，不重新请求）
- 管理端签发弹窗统一为「分享卡片」：端点选择（对外地址 / 内网地址，有多个内网地址时下拉）
  + tab 二选一复制（完整链接 / 仅密钥）+ 下载 .anet 按钮（§7）

## 6. 公网身份产品化 + 反代端点（§4-P1）

- `anet init` 向导：Relay listener 开启后询问「本机是否公网会合点？」→ 是则填对外地址
  （IP 或域名）写入配置 `public_host`
- 管理端设置页「公网会合点」卡片：开关语义 = public_host 非空；对外地址输入；
  反代端点输入（`public_api_url`，如 `https://anet.cns.red`，可选，ahelp 说明 L4/L7 约束）
- 反代约束（文档化于 wiki）：relay 数据面必须 L4 TCP 透传；API 经 HTTPS 反代时用
  `public_api_url` 覆盖 scheme+端口
- 桌面端监听面板 public_host 行已落地，补「反代端点」输入（同 set_server_public_host 机制）

## 7. `.anet` 文件载体（§2.8 落地）

**容器格式**（JSON 信封，人类可读 diff 友好）：

```json
{
  "magic": "ANET1", "version": 1,
  "role": "connect" | "fanout",
  "issuer": "签发节点名", "created_at": "RFC3339", "note": "用途备注",
  "enc": "none" | "aes256gcm", "salt": "b64", "nonce": "b64",
  "payload": { ...技术字段... } | "b64 密文"
}
```

- 加密与设置同步同构：PBKDF2-HMAC-SHA256（100k 迭代，16B 随机 salt）→ AES-256-GCM，
  key input `agile-net-sync:v1:` + 4 位 PIN（格式级兼容，同一 PIN 语义）
- 共享 JS `apps/desktop/ui/aganet.js`（双端唯一实现，同 aglink.js 机制）：
  WebCrypto PBKDF2 + AES-GCM 构建/解析/加解密；`AgAnet.build(envelope, pin)` /
  `AgAnet.parse(text)` → `{ envelope, needPin }` / `AgAnet.decrypt(envelope, pin)`
- 签发处（管理端：扇入令牌 + 账号分享卡片；桌面端：扇入列表导出）提供「下载 .anet」，
  导出对话框可选 PIN（默认推荐）或明文；建议文件名 `<签发方>-<用途>-<日期>.anet`
- 导入三入口：文件选择 / 拖拽入窗 /（桌面）双击文件关联；导入对话框先展示信封元信息
  （签发者/时间/用途/角色），加密文件先输 PIN，确认后按角色落地（connect → 扇入导入并连接；
  fanout → 扇出表单填充）
- 桌面 Rust 侧只做文件系统交互（保存/读取对话框、文件关联事件转发）；加解密全部 JS 层，
  双端行为一致。sync.rs 不动（其 Archive 是同步协议）

## 8. `anet://` 系统协议注册 + 深链路由

- 桌面：`tauri-plugin-deep-link` + `tauri-plugin-single-instance`（深链拉起聚焦既有实例，
  argv URL 转发前端）；`tauri.conf.json` plugins.deep-link desktop schemes = ["anet", "agilenet"]，
  `bundle.fileAssociations` 注册 `.anet`
- Android：deep-link 插件 mobile intent-filter（anet scheme）+ `.anet` mime
- 前端路由：收到 URL → `AgLink.parse` → 按 role 落到导入入口（connect → 扇入快速连接框
  填入并聚焦；fanout → 扇出表单打开并填充技术字段）
- 管理端（浏览器环境）不注册协议，仅粘贴导入

## 9. 策略上送 UI

- 桌面扇出连接表单：新增「上送权限组」多选（本地组 checkbox 列表，存 connector.push_groups）
- 管理端扇出表单：同上加多选
- 管理端扇入页「端点」页签：节点行展开详情（advertise 路由列表 + 上送的组），
  组行「采纳」按钮 → adopt 成功后提示并跳权限组页
- 桌面扇出监听面板「企业联邦对接 · 敬请期待」条目：更新为 P1 已落地能力说明
  （策略上送：扇出连接表单内选择上送组；对端控制台一键采纳授权）

## 10. i18n 与文档

- 新词条先查 common.*/term.* 复用；管理端词条进 `lang/admin.js`，桌面端进 `lang/desktop-*.js`
- 代码注释一律英文；用户可见文案双语文档口吻
- 收尾更新：`docs/todo/federation.md` 状态（P1 落地项打勾）、`AGENTS.md`（链接格式/协议/DB v9/
  共享组件 aglink+aganet、深链与 .anet 约定）、`docs/api/node.md`（新 API）、wiki（反代约束）

## 11. 验收

1. `cargo test --workspace` 全绿（新增：链接解析、v9 迁移、上送协议编解码、adopt 流程、
   endpoints 优先级、.anet 加解密往返）
2. 集成链路（两级节点）：C 配置 push_groups 扇出 B → B 的 federation/offered 可见 C 的组 →
   adopt 成本地组 → 创建账号 A 挂该组 → A 扇入 B 可路由 C 的目标（docker 链测试扩展或
   本地双实例脚本验证）
3. 扇入令牌分享链接在干净桌面端粘贴即导入连接（技术字段零手填）
4. `.anet` PIN 加密文件在双端互导成功；错误 PIN 明确报错
