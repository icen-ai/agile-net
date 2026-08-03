//! 订阅代理内核（mihomo sidecar）管理：钉版本下载校验 / 配置生成 / 生命周期 / REST 控制面。
//!
//! - 内核只从 mihomo 官方 GitHub Release 下载（镜像仅作 CDN 加速，
//!   完整性由内置 SHA-256 钉死保证，双镜像交叉验证得出）
//! - 数据布局（~/.agile-net/）：mihomo/ 内核与配置缓存；subscriptions.json 订阅清单（0600）
//! - 订阅解析完全交给内核 proxy-providers，本项目不解析订阅内容
//! - external-controller 仅 loopback + secret，严禁对外暴露
//!
//! 实现已按域拆分到 `crate::kernel`（纯搬运，零逻辑变更），本模块仅作门面 re-export，
//! `crate::subscription::xxx` 引用路径全部保持不变。

pub use crate::kernel::*;
