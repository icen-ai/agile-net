# 内置网络助手（白帽 Agent）后续规划

> **纯规划文档**：P1（白帽 agent 主体）已落地，实施记录随代码可读，本文只保留未实现的未来项。

## 待办

- **P2 — 更多变更工具**：封域名、收缩监听、吊销令牌（均走现有 confirm 确认闸门，fail-closed）。
- **P2 — 取证包导出**：疑似攻击场景一键打包连接记录/事件/审计供上报。
- **P2 — 专属隧道档**：mux 信道钉线，模型流量走隧道出口。
- **P2 — Claude/Gemini 适配器**：当前仅 OpenAI 兼容协议（DeepSeek/Kimi/通义/智谱/OpenAI/ollama 一家通吃），结构不同的厂商需要适配层。
- **P3b — MCP 暴露**：工具注册表加协议适配器即 MCP server（stdio 或本地 HTTP + 票据），白帽 playbook 以 MCP prompts 随附。
