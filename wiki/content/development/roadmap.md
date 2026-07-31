# 路线图

## 已完成

- **双产物统一（P1→P3）**：`NodeServer` 装配根抽取；anet-gui 三路独立开关（客户端/服务端/Web 远程面）；
  客户端管理面 Web 化（REST + 双传输桥 + 同强度鉴权）；管理版接入链接与 scoped admin 三档；
  relay 暴露控制面 + 握手 v2 控制端点下发 + 可管理节点自动发现 + 路由再发布；
  `anet-svc`（serve/tui/client/cli）与 `anet-gui` 双产物收敛，CI/docker/文档同步
- 多层级链式穿透（四级链断言 T1-T7）、断链自愈、长轮询热更新
- 全平台发布流水线（tag 触发，Windows/macOS/Ubuntu/Android/musl 静态）
- 文档站（本站，Cloudflare Pages）

## 进行中 / 规划

| 方向 | 内容 | 出处 |
| --- | --- | --- |
| 移动端系统岛 | Android 前台服务常驻通知 / iOS Live Activities，前后台分工架构 | `docs/todo/island.md` |
| 正式签名 | Windows EV 签名、macOS 公证、Android keystore + Play 上架 | `docs/release.md` |
| 有限委托管理 | 中央控制台代理转发（带真实操作人身份头），D 路线的二期候选 | `docs/plan/merge-gui-svc.md` §5 |
| 龙芯支持 | loongarch64 工具链验证与产物 | — |
| iOS | Tauri iOS 工程化与上架 | — |

## 场景验证矩阵

| 场景 | 状态 |
| --- | --- |
| 四级链穿透（root→mid→leaf→deep→target） | docker 断言 T1-T6（已验证） |
| 机房 svc — 机房 GUI（relay 下游 + 开发者上游 + Web 面） | A+B+C 全开（P1/P1.5，已验证） |
| 外地开发 GUI 管理版链接连机房，与坐在机房前同等体验 | 控制台通道 + 管理链接（P1.6，已验证） |
| 经中继穿透管理更上游（relay + 暴露开关） | 握手 v2 + 自动发现 + 票据链（P2，断言 T7 已验证） |
| FlClash 共存（AgileNet 作 socks5 节点按 CIDR 分流） | 已文档化 |
