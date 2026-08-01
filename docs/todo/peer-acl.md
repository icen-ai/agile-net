# 对端收敛（Peer ACL）实施计划

> 状态：已实施（2026-08-01 全部落地；实现与本文的偏差逐条见文末「实施记录」）
> 前置：多扇出 `[[connectors]]` 已落地（见 git 历史 `feat(core): 多扇出`）

## 1. 背景与动机

多扇出落地后，一个节点可以同时扇出到多个对端、扇入多个对端。但权限模型仍停留在
单身份时代：规则收敛只覆盖「账号」这一种流量来源身份（`account.group_id`），
对端身份完全没有收敛能力——

- `relay_token` 表（`crates/node/src/db/mod.rs`）只有 `token_hash/prefix/remark`，
  无 `group_id`：扇入对端拿令牌连入后，其来的流量不按对端收敛。
- 扇出 connector 活在 TOML `[[connectors]]` 里，无组概念：扇出隧道反向来的流量
  同样无收敛；且配置不进库，管理端无法 CRUD、热生效、审计。

真实场景（多公司/多机房互联）：中心端扇出到若干独立运营的端点，每个对端自行
开服务端角色、给自己的用户发账号。中心端**看不见对端的账号体系**，能识别的唯一
身份是「这条隧道来自哪个对端」——收敛只能发生在对端粒度。不同对端挂不同规则
集合，集合之间允许规则交叉；多个对端可共享同一套规则集合（同一体系的不同站点）。

## 2. 立项哲学（主权域原则）

> **节点即主权，权利平等**：只发布规则、选择接受者，不过问对端域内的使用明细——
> 收敛与审计止于端点边界，问责沿组织链传递。

推论（全部硬性）：

- **身份域分离**：节点内身份（账号/密码）与节点间身份（relay token / connector）
  是两个独立主权域，协议**永不**桥接——隧道认证只携带对端节点身份，不携带终端
  用户身份。「身份透传审计」选项明确否决，不进协议。
- **问责靠组织链**：本端审计只能记到「某对端隧道访问了某目标」，定位到人对端
  自查（对端若有审计能力）。各节点日志覆盖各自己的域，串起来才是完整链路。
  这不是缺陷，是设计。
- **对称性**：扇入扇出在收敛上完全对称——对端看本端也用同样模型收敛本端去的
  流量。谁也不比谁多一只眼睛。
- **权力边界**：本端的权力是「给不给、给多少、随时收回」（签发/吊销令牌、调整
  对端所在组的规则、断开隧道，全部实时粗粒度），而不是「看谁在怎么用」。
  控制面与可见性的粒度故意保持一致。

## 3. 领域模型

**所有流量来源身份都挂权限组，`group` 是唯一收敛点。**

| 身份 | 挂载点 | 现状 |
| --- | --- | --- |
| 账号（本端直连用户） | `account.group_id` | 已有，不动 |
| 扇入对端 | `relay_token.group_id` | **新增列** |
| 扇出对端 | `connector.group_id` | **connector 入库时带** |

- 规则交叉复用：`group_rule` 多对多天然支持（同一条规则挂多个组）。
- 多对端共享一套规则：多个 token / connector 挂同一个组，即「对端分组」——
  不需要新建任何「扇出组」实体。
- 收敛语义：对端隧道来的流量，目标命中该对端组的规则集合才放行，否则拒绝。
- 出口选择**不**新增 `rule.egress` 列：隧道 advertise 的路由再发布自动指向
  出口隧道，真实场景没有「同一目标多条平行出口任选」的需求。

### 明确的非目标（本次不做）

- `rule.egress` 出口指定列——砍掉，理由如上。
- 出口容灾/负载均衡组（failover / LB）——出口方向的事，与入口 ACL 正交，缓做。
  注意「多对端共享一组」不是容灾关系（不同流量来源）；真正容灾是「同一对端的
  多条平行连接 failover」，未来需要时单独立项。
- 身份透传审计——永久否决（见 §2）。
- 对端组内主动健康探测——收敛只看隧道连接态，不引入探测。

## 4. 数据模型变更（一次新 migration）

```sql
-- relay_token 加收敛挂载点
ALTER TABLE relay_token ADD COLUMN group_id TEXT REFERENCES "group"(id);

-- 扇出入库（一等资源）
CREATE TABLE connector (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,        -- 对端显示名（管理端列表/审计用）
    upstream_addr TEXT NOT NULL,
    token_enc  TEXT NOT NULL,               -- 加密存储，见 §5
    sni_hostname TEXT NOT NULL DEFAULT '',
    insecure   INTEGER NOT NULL DEFAULT 0,
    advertise  TEXT NOT NULL DEFAULT '',    -- 原 ConnectorConfig.advertise 序列化
    group_id   TEXT REFERENCES "group"(id),
    enabled    INTEGER NOT NULL DEFAULT 1,
    remark     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

- 迁移兼容：现无用户，允许破坏性简化。存量 `relay_token.group_id` 为 NULL 时
  语义 = **不收敛（放行一切）**，与现状一致；新建令牌默认必须选组（UI 强制，
  API 允许显式留空 = 不收敛）。
- TOML `[[connectors]]` 降级为**初始导入**：启动时若 DB 中无同名 connector 则
  导入；运行时以 DB 为准。GUI 本机扇出页改为调本机 API，不再自存配置生成 TOML。
- `connector.name` 用于管理端列表与审计展示；对端 node_name 仅作连接期参考。

## 5. 扇出 token 的加密存储（全库唯一例外）

账号密码 / relay token 均为哈希落库、不可逆；但扇出 token 是对端签发的连接凭据，
**连接时必须使用明文**，只能可逆存储。DB 泄露 = 所有扇出凭据泄露，必须缓解：

- `token_enc` 使用机器密钥对称加密：密钥首启生成，存 `node_config`（与
  `jwt_secret` 同机制），Windows 可后续接 DPAPI 强化（P2）。
- 审计日志**严禁**记录 token 明文与密文；管理端 API 永不回显（与 relay token
  明文只创建时返回一次的口径一致——但扇出 token 是对端给的，创建后亦不回显，
  只允许「重置」）。
- AGENTS.md §3 安全硬化节需补一条该例外及其边界。

## 6. 数据面收敛点

- **扇入**（listener 接受对端 CONNECT/路由请求）：按 `token.group_id → 组规则
  集合` 匹配目标，不命中拒绝并记审计（含对端身份、目标、来源）。
  `group_id IS NULL` = 不收敛（兼容语义）。
- **扇出**（connector 隧道反向来的流量）：按 `connector.group_id → 组规则集合`
  同样收敛。组规则变更 / 令牌吊销 / connector 禁用均实时生效（路由/会话随
  隧道状态机事件刷新）。
- 收敛实现位置：`crates/core` relay listener / connector 的流量入口，复用现有
  `ProxyRouter` 的匹配能力构造「该对端的允许集合」；不改动账号侧匹配引擎。

## 7. 管理端 / CLI / TUI / GUI

- **管理端 SPA**：
  - 令牌页：创建/编辑加「权限组」下拉（留空 = 不收敛）。
  - 扇出页（新菜单）：connector CRUD + 实时状态徽标（connected/connecting/
    reconnecting/disconnected），创建/编辑含「权限组」下拉；token 不回显。
  - 权限组页：组详情展示名下挂的**账号 + 扇入令牌 + 扇出对端**三类身份。
- **CLI（anet）**：
  - `anet token create --group <name>` 等参数补齐。
  - 新增 `anet connector list / add / update / remove`（扇出分组，`--group`）。
- **TUI**：令牌/扇出列表显示所属组；离线模式只读展示同上。
- **GUI（anet-gui）**：本机扇出页从「自存配置生成 TOML」改为调内嵌节点 API；
  扇出表单加「权限组」下拉（本机场景可默认不收敛）。

## 8. 审计口径

- 收敛拒绝事件：记对端身份（token 前缀 / connector name）、目标、时间、来源。
- 对端粒度即为上限：**永不**尝试记录对端域内的终端用户（§2）。
- 敏感操作（令牌/connector/组变更）沿用 `record_audit_log` 现有规范。

## 9. 分期

**P1（本计划全部）**：

1. migration：`relay_token.group_id` + `connector` 表（§4）。
2. 扇出 token 加密存储（§5）+ AGENTS.md §3 补例外说明。
3. 数据面两个收敛点（§6）+ 收敛拒绝审计。
4. 扇出从 TOML 导入切 DB 装配；`NodeServer` 多 connector 装配改读库。
5. 管理端 API + SPA 三处页面（§7）。
6. CLI `connector` 命令组 + token `--group`；TUI 同步。
7. GUI 扇出页改走 API（§7）。
8. `cargo test --workspace` 全绿；wiki/文档同步。

**P2（另立项，不在本计划）**：

- 出口容灾组（同一对端多条平行连接 failover）；DPAPI/系统 keyring 强化
  `token_enc` 密钥保护；管理端对端维度的流量统计页。

## 10. 验收标准

- 建两组 G1{规则 R1}、G2{规则 R2}（R1/R2 网段交叉一条共用规则 R0）：
  对端甲挂 G1、对端乙挂 G2，甲只能访问 R0+R1，乙只能访问 R0+R2。
- 对端丙、丁同挂 G1：行为一致（多对端共享一组）。
- 组规则热更新实时生效；吊销令牌/禁用 connector 即断流。
- 审计日志只出现对端身份，无任何终端用户身份信息、无 token 明文/密文。
- 管理端可对被管端点的令牌/扇出做上述全部操作（带内管理面一致可用）。

---

## 11. 实施记录（2026-08-01）

设计全部落地。实现与上文设计的偏差逐条登记如下（以代码为准）：

- **migration 拆为两步**：v4 `peer_acl_connector`（`relay_token.group_id` + `connector` 表）；v5 补 `connector.ca_cert_path` / `connector.pinned_cert_path` 两列——§4 表结构遗漏，对齐 core `ConnectorConfig` 的证书固定能力（空串 = 不使用，优先级 pinned > ca > insecure，与 TOML 装配逻辑一致）。
- **扇出 token 加密落库格式**定为 `v1:nonce_b64:ct_b64`（AES-256-GCM，ring）；机器密钥 `node_config.connector_token_key` **首用**生成（32 随机字节 hex，与 `jwt_secret` 同机制）。token 创建后不回显，PUT 留空 = 保留原值。
- **HTTP API**：
  - connector 路由：`GET/POST /api/v1/admin/connectors`、`PUT/DELETE /api/v1/admin/connectors/{id}`、`POST /api/v1/admin/connectors/{id}/enable|disable`；PUT 为**全量替换**语义。
  - `advertise` 入参为**字符串数组**（非逗号拼接字符串）。
  - relay-tokens 创建带 `group_id`；PUT 三态 `group_id`（缺省 = 不变 / `null` = 不收敛 / 字符串 = 挂组）。
  - 新增 `GET /api/v1/admin/groups/{id}/detail`：返回组下账号 + 扇入令牌 + 扇出对端三类身份。
- **TOML `[[connectors]]` 启动导入**：`name` 取 `upstream_addr`（TOML 无 name 字段），`advertise` 逗号拼接入库，组为 None（不收敛）；运行时以 DB 为准。
- **core**：收敛实现为 `relay::PeerAcl` + `ProxyRouter::matches` + `AuthIdentity::Node.acl`（`None` = 不收敛）+ `PeerEvent::AclDenied{peer_label, target}`，扇入/扇出数据面钩子各一。
- **node**：装配为 `service::acl::PeerAclRegistry` + `service::connectors::ConnectorManager`；热重载循环同时 rebuild 组路由；收敛拒绝审计按 peer+target 每分钟去重。
- **CLI**：`anet connector list/add/update/remove/enable/disable`（`--group` 接受名称或 id；`remove` 无 `--force` 参数）；`anet token add --group`（`add` 为 `create` 别名）；`--help` 扇出组含 rule/group/account/token/connector。
- **TUI**：令牌页加组列 + 新「扇出」页签（共 7 页签）；离线模式 LEFT JOIN 展示组名。
- **管理端 SPA**：菜单位于 令牌 与 审计 之间；令牌页组下拉 + 组列 + 编辑模态；扇出页 CRUD + 状态徽标（5s 轮询变更检测）+ 启停；权限组详情展示三类身份。
- **GUI（anet-gui）**：扇出页改进程内 DB CRUD + `ConnectorManager` 热操作；删除 `roles.rs` `server_connectors` 自存（旧配置直接丢弃不迁移），`build_embedded_config` 不再输出 connectors；表单无独立名称字段，显示名 = 目标地址（沿用 TOML 导入惯例）；表单「权限组」下拉默认不收敛；新增 Tauri 命令 `list_embedded_groups`。
- **审计口径落实**：收敛拒绝记对端身份（node_id / connector name）+ 目标 + 来源，永不含对端域内终端用户身份；connector / relay-token 敏感操作审计不落 token 明文与密文。
