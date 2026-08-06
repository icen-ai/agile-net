# 路线图

## 已完成

- **双产物统一**：`NodeServer` 装配根抽取；anet-gui 三路独立开关（客户端/服务端/Web 远程面）；
  anet-svc 单端口统一 Web（`/` 管理端 SPA、`/client` 客户端 SPA、AdminAuth 共享登录）；
  scoped admin 三档；relay 暴露控制面 + 可管理节点自动发现 + 路由再发布
- **统一签发**：账号体系整体删除，delegated_token 升级为唯一消费者身份（入口
  direct/relay × 信任 明文/E2E/E2E+管理档 × 路由 dedicated/split × 并发 single/multi）；
  扇入/扇出页「监听 | 连接 | 签发」三页签；DB 迁移塌缩为基线 v1；协议 v4 唯一行为；
  链接统一 `anet://`；client crate 委托-only（链接式 `nodes` TOML）
- 联邦：策略上送/一键采纳（只读活镜像）、签发委托容灾集合、E2E entrust 零泄露路由
- 多层级链式穿透（四级链断言 T1-T7）、断链自愈、规则热更新
- 全平台发布流水线（tag 触发，Windows/macOS/Ubuntu/Android/musl 静态）
- 文档站（本站，Cloudflare Pages）

## 进行中 / 规划

| 方向 | 内容 | 出处 |
| --- | --- | --- |
| 移动端系统岛 | Android 前台服务常驻通知 / iOS Live Activities，前后台分工架构 | `docs/todo/island.md` |
| 正式签名 | Windows EV 签名、macOS 公证、Android keystore + Play 上架 | `docs/release.md` |
| 有限委托管理 | 中央控制台代理转发（带真实操作人身份头），D 路线的二期候选 | — |
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
