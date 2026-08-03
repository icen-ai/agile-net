//! Subscription proxy kernel (mihomo sidecar) management: pinned download verification / config generation / lifecycle / REST control plane.
//!
//! - Kernel is downloaded only from mihomo's official GitHub Releases (mirrors act as CDN only;
//!   integrity is enforced by a built-in SHA-256 pin, cross-verified across both mirrors)
//! - Data layout (~/.agile-net/): mihomo/ holds kernel and config cache; subscriptions.json is the subscription list (0600)
//! - Subscription parsing is fully delegated to kernel proxy-providers; this project never parses subscription content
//! - external-controller is loopback + secret only; never expose it externally
//!
//! Implementation was split by domain into `crate::kernel` (pure move, zero logic change); this module is only a facade re-export,
//! so all `crate::subscription::xxx` reference paths stay unchanged.

pub use crate::kernel::*;
