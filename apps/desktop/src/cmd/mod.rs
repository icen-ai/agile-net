//! Tauri command modules: split from lib.rs (pure move, zero logic change).
//!
//! Submodules follow lib.rs's original section layout; full `pub(crate) use` re-exports here,
//! together with lib.rs's `pub(crate) use cmd::*;`, keep the generate_handler![...] list and
//! crate:: path references (e.g. floatball.rs's crate::show_main_window) completely unchanged.

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
