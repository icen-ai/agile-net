//! Device gate (node.md M3-T2): certification enforcement for the data plane.
//!
//! The core listener asks two questions through the injected hook:
//! - at auth: `Deny` → reject with `device_revoked` (a revoked device never gets a session);
//! - per Open: `Pending` → OpenFail `pending_approval` (policy "block"), `Allow` passes.
//!
//! State lives in `device_registry`; this cache keeps per-Open lookups off the DB (TTL 2s,
//! explicit invalidation on every certification write — revoke is instant, certify lags ≤2s).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use agile_net_core::relay::listener::DeviceGate;
use dashmap::DashMap;

use crate::db::Database;

/// Cache TTL for open-path gate lookups (auth always reads through).
const GATE_TTL: Duration = Duration::from_secs(2);

pub struct DeviceGateCache {
    db: Database,
    states: DashMap<String, (String, Instant)>,
    /// Pending-device policy: false = block opens until certification (default), true = allow
    /// with a gray flag (the session row is badged, traffic flows)
    allow_pending: AtomicBool,
}

impl DeviceGateCache {
    pub fn new(db: Database) -> Arc<Self> {
        Arc::new(Self {
            db,
            states: DashMap::new(),
            allow_pending: AtomicBool::new(false),
        })
    }

    /// Hot apply the policy from node_config (`device_pending_policy` = 'block'|'allow').
    pub fn load_policy(&self) {
        let allow = self
            .db
            .get_config("device_pending_policy")
            .ok()
            .flatten()
            .map(|v| v == "allow")
            .unwrap_or(false);
        self.allow_pending.store(allow, Ordering::Relaxed);
    }

    pub fn set_allow_pending(&self, allow: bool) {
        self.allow_pending.store(allow, Ordering::Relaxed);
        // policy change applies to live opens immediately
        self.states.clear();
    }

    pub fn is_allow_pending(&self) -> bool {
        self.allow_pending.load(Ordering::Relaxed)
    }

    /// Drop the cached state (call after every certification write: certify/revoke/rebind).
    pub fn invalidate(&self, device_fp: &str) {
        self.states.remove(device_fp);
    }

    fn state_of(&self, device_fp: &str) -> String {
        if let Some(e) = self.states.get(device_fp)
            && e.value().1.elapsed() < GATE_TTL
        {
            return e.value().0.clone();
        }
        let state = self
            .db
            .get_device(device_fp)
            .ok()
            .flatten()
            .map(|d| d.state)
            .unwrap_or_else(|| "pending".to_string());
        self.states
            .insert(device_fp.to_string(), (state.clone(), Instant::now()));
        state
    }

    /// The core-listener hook closure.
    pub fn gate(self: &Arc<Self>) -> agile_net_core::relay::listener::DeviceGateHook {
        let cache = self.clone();
        Arc::new(move |fp: &str| {
            let state = cache.state_of(fp);
            match state.as_str() {
                "certified" => DeviceGate::Allow,
                "revoked" => DeviceGate::Deny,
                // pending (or never seen): policy decides block vs allow-with-flag
                _ if cache.is_allow_pending() => DeviceGate::Allow,
                _ => DeviceGate::Pending,
            }
        })
    }
}
