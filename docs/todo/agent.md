# 内置网络助手（白帽 Agent）设计与实施记录

状态：P1 已落地（2026-08）。路线决策：内置为主、工具层 MCP-ready、P3 暴露 MCP server。

## 1. 定位与红线

- 定位：**住在网络工具里的白帽**——差异化只在「能直接查看和操作本机网络状态」。目标用户是网络小白：标题栏 sparkles 一键唤起，场景卡片代替提问。
- 红线：**不做反攻**（hack back 在各法域均违法，且打到的多是肉鸡）。「反制」= 本机防御：阻断（kill 连接/封域名）、收缩暴露面（关监听/远程面、吊销令牌）、取证打包、上报。
- 模型接入：BYOK（用户自备 Key），零代付零合规负担。

## 2. 架构

- **会话归后端**：对话存于 `src/agent.rs` 的 `AgentState`（内存，会话级）；抽屉关闭/窗口最小化到托盘都不中断执行中的回合；重开经 `agent_get_state` 快照 + `agent-ev` 事件重建视图。**不做历史管理**（功能性工具非对话产品），用户手动清空（`agent_clear`）。
- **工具注册表**（MCP-ready）：`{name, desc, JSON schema, confirm}` 静态表；function calling 白名单制，**严禁自由 shell**。只读工具直通；变更工具（confirm=true） park 在 oneshot 上等待 `agent_confirm`，5 分钟超时=拒绝（fail-closed），请求时 `float_notify` 悬浮球提醒。
- **LLM 薄客户端**（`src/llm.rs`）：OpenAI 兼容协议一家通吃（DeepSeek/Kimi/通义/智谱/OpenAI/自定义含 ollama），reqwest + SSE 行解析 + tool_calls delta 累积，无 vendor SDK。Claude/Gemini 结构不同，需要时 P2 加适配器。
- **网络钉线**（关键纪律）：HTTP 客户端永不读系统/环境代理——防御动作可能停代理/切 TUN，模型对话不能死在半路。路由档挂端点预设：`Direct`（国内厂商默认，`no_proxy()`）/ `Proxy`（海外，显式钉 `127.0.0.1:57890` HTTP CONNECT）。Direct 档保存配置时**自动把 API 域名注入自定义放行规则**（TUN 模式也 DIRECT 出去）。传输失败同历史重试 ×2（断线自愈，事件明示）。
- **Key 存储**：Windows/macOS 进 OS keyring（`ai.icen.agilenet.gui` / `llm-api-key`，与 crates/client 凭据同方案）；其他平台 0600 文件 `~/.anet/gui/agent-key`。配置（不含 Key）落 `agent-config.json`；技能落 `agent-skills.json`。

## 3. 工具清单（P1）

只读：`doctor_run` / `net_ping` / `net_tcping` / `net_dns` / `net_trace` / `net_sockets` / `conlog_recent`（未开记录开关时返回引导文案，不代开）/ `sysproxy_status` / `proxy_overview` / `recent_events`。
变更（确认闸门）：`conlog_kill`（打断可疑外联，验证确认链路）。
结果统一截断 4000 字符；单工具 30s 超时；单消息最多 10 轮工具调用（防循环）。

## 4. 技能/提示词（可插拔，用户可扩展）

- 系统提示词 = 白帽纪律基座（先诊断后动作/禁攻击/小白口吻/引用具体数值）+ Σ 启用技能的 prompt 段。
- 内置 playbook：网络不通排查 / 网速变慢排查 / 疑似被攻击应急 / 代理被劫持检查。内置项**提示词随代码升级**，磁盘只存开关态。
- 用户技能：抽屉技能弹窗里增删/开关（`agent_skill_*`），启用即成为对话流上方的场景芯片。
- MCP 展望：工具表加协议适配器即 MCP server（stdio 或本地 HTTP + 票据），白帽 playbook 以 MCP prompts 随附——P3b。

## 5. UI（v2 仪器风）

标题栏 sparkles → 右侧 400px 抽屉：铭牌头带（标题 + 模型 pill + 技能/清空/关闭）/ 消息流（用户反相气泡、助手迷你 Markdown 直排、流式逐字）/ 工具卡（凹槽一行牌：运行中转圈/完成绿/失败或拒绝红，点开看参数与结果）/ **变更确认卡内联**（warn 色调，允许/拒绝，非模态）/ 场景芯片行 / 自长高输入框（Enter 发送，Shift+Enter 换行）。设置页「AI 助手」卡：服务商/模型/Base URL（自定义档）/API Key（password 输入，不回显，状态仅示已存与否）+ 路由档说明。迷你 Markdown 渲染器手写子集（围栏代码/行内码/加粗/列表/段落），零依赖。

## 6. 实施记录与偏差

- 文件：`src/llm.rs`、`src/agent.rs`（命令 `agent_get_state/send/stop/clear/confirm/config_set/skill_save/toggle/delete`）、`ui/agent.js`、抽屉+设置卡（index.html）、`lang/desktop-agent.js`、icons 增 sparkles/send；keyring 依赖（win/mac 原生后端）+ reqwest `stream` + futures-util。
- 顺手修复：desktop lib 测试 build 的既有broken（custom_rules 测试调用不存在的 `sort_bypass` → 改为生产同款 `sort_by_key(|r| r.sort)`）。
- 测试：llm/agent 单测 5 个（预设表唯一性与 Direct 档 bypass_host 完备、wire 序列化、消息交织、技能开关过滤、url_host 解析）；desktop lib 91 全过。
- 偏差：Anthropic/Gemini 适配器未做（OpenAI 兼容协议覆盖首批全部预设）；P2 待办：更多变更工具（封域名/收缩监听/吊销令牌）、取证包导出、专属隧道档（mux 信道钉线）；P3b：MCP 暴露。
