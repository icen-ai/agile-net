//! Split from subscription.rs: mihomo sidecar kernel submodules (pure move, zero logic change)
//!
//! Submodules: api (REST control plane) / ws (WS collection and aggregation) / config (config generation and loop prevention) /
//! store (subscription list persistence and CRUD) / manager (kernel process lifecycle) / wintun (wintun.dll provisioning).
//! This layer only aggregates re-exports; external paths still go through the `crate::subscription::` facade.

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
