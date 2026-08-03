//! 从 subscription.rs 拆分：mihomo sidecar 内核子模块（纯搬运，零逻辑变更）
//!
//! 子模块划分：api（REST 控制面）/ ws（WS 采集与聚合）/ config（配置生成与防环）/
//! store（订阅清单持久化与 CRUD）/ manager（内核进程生命周期）/ wintun（wintun.dll 下发）。
//! 本层只做归拢 re-export，对外路径仍经 `crate::subscription::` 门面透出。

pub(crate) mod api;
pub(crate) mod config;
pub(crate) mod manager;
pub(crate) mod store;
pub(crate) mod wintun;
pub(crate) mod ws;

pub use api::*;
pub use config::*;
pub use manager::*;
pub use store::*;
pub use wintun::*;
pub use ws::*;
