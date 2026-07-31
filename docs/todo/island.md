# TODO: 移动端系统级状态岛（Android 常驻通知 / iOS Live Activities）

> 结论先行：**系统岛只在 App 后台时可用，前台的灵动岛必须自己维护**。
> 分工按生命周期而非能力探测——前台用应用内灵动岛，退后台用系统载体，天然"退化"路径。

## 背景与平台现实

桌面端已实现应用内灵动岛（标题栏内容区上方居中：状态摘要 + 瞬时通知 + 异常详情展开，
见 `apps/desktop/ui/`）。移动端能否直接用手机自带的岛？

| 平台 | 系统载体 | 关键限制 |
| --- | --- | --- |
| iOS | Dynamic Island 仅经 **Live Activities**（ActivityKit, Swift）开放 | **仅 App 退后台后可见**；前台时岛区由系统独占，App 无法渲染 |
| Android | 无统一岛；Android 16+ 有 **Live Updates**（ProgressStyle 通知 chip） | 同样**仅后台可见**；前台状态栏区域 App 不可写 |

因此「完全交给系统岛、不再维护应用内岛」不成立。正确架构：

```
App 前台  → 应用内灵动岛（现有实现，桌面/Android 同一套前端代码）
App 后台  → Android: 前台服务 + 常驻通知（可升级 Live Update）
            iOS:     Live Activities（需先有 iOS 构建目标）
```

## 现状盘点

- `apps/desktop` 仅配置了 Windows + Android 目标；`gen/android` 尚未 init（无原生工程）
- 无 iOS 构建目标；无通知插件；无前台服务
- 应用内灵动岛已完成（含内容区居中定位、动效伸缩、异常展开）

## Android：前台服务 + 常驻状态通知

代理/VPN 类客户端的标准姿势，兼负**后台保活**（国产 ROM 杀进程场景）与状态展示。

实施步骤：

1. `cargo tauri android init` 生成 `gen/android` 原生工程（需 Android Studio + SDK 34 + NDK r26+）
2. Kotlin 侧新增 `ProxyForegroundService`（`foregroundServiceType="specialUse"` 或 `dataSync`），
   常驻通知展示：`代理运行中 127.0.0.1:57890 · 已连 N 节点`
3. 权限与引导：`POST_NOTIFICATIONS`（API 33+ 运行时申请）、电池优化白名单引导
   （`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`，上架注意 Google Play 政策）
4. 状态桥：Rust 侧监听节点/代理状态变化（`agile-net-client` 的 `list_nodes`/`proxy_port`），
   经 Tauri 插件通道通知 Kotlin 更新通知内容
5. Android 16+：通知升级为 `Notification.ProgressStyle` 的 Live Update（状态栏 chip）
6. 前台 UI 不变：应用内灵动岛照常工作，无需能力探测

验收：App 划到后台 30 分钟隧道不断流；通知内容随连接/断开实时更新；点击通知回主界面。

## iOS：Live Activities

前提（未满足时不动工）：

1. 排期 iOS 构建目标（Tauri 2 Mobile iOS，`tauri.conf.json` + Xcode 工程）
2. Swift 侧实现 ActivityKit：`Attributes` 定义（代理状态/在线节点数/降级标记），
   连接成功时 `Activity.request`，状态变化 `update`，断开 `end`
3. Rust→Swift 桥（Tauri plugin 或 UniFFI）把客户端引擎状态推给 Live Activity
4. 注意 Apple 审核：Live Activities 须对应用户可见的进行中任务，代理会话符合语义

## 非目标（明确不做）

- 不追求前台使用系统岛（平台不允许）
- 不做能力探测式降级逻辑（前后台分工即天然退化）
- iOS 无构建目标前不写任何 ActivityKit 代码

## 相关文件

- 应用内灵动岛实现：`apps/desktop/ui/index.html` / `style.css`（`.island`）/ `app.js`（`Island` 对象）
- 设计规范：`docs/architecture/ui-design.md` §3
- Android 工程说明：`apps/README.md`
