//! Tauri 命令模块：从 lib.rs 拆分（纯搬运，零逻辑变更）。
//!
//! 子模块按 lib.rs 原分区注释切分；此处全量 `pub(crate) use` re-export，
//! 配合 lib.rs 的 `pub(crate) use cmd::*;`，使 generate_handler![...] 列表与
//! crate:: 路径引用（如 floatball.rs 的 crate::show_main_window）完全不变。

mod client;
mod doctor;
mod misc;
mod net;
mod proxy;
mod roles;
mod rules;
mod subscription;
mod tray;
mod windows;

pub(crate) use client::*;
pub(crate) use doctor::*;
pub(crate) use misc::*;
pub(crate) use net::*;
pub(crate) use proxy::*;
pub(crate) use roles::*;
pub(crate) use rules::*;
pub(crate) use subscription::*;
pub(crate) use tray::*;
pub(crate) use windows::*;
