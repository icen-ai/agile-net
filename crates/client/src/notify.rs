//! Client notification center (node.md M4-T1): the local persistent inbox behind the titlebar
//! bell + sidebar menu. Session notices (kick/revoke/takeover), auth rejections and approval
//! state changes land here; the UI reads the list + unread count and subscribes for live pushes.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// One inbox entry. `kind`: session (kick/notice) | approval (pending/decided) | system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub ts: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    /// M2 reason_code (revoked_by_admin / device_revoked / kicked / pending_approval / ...)
    #[serde(default)]
    pub reason_code: String,
    /// Originating node (engine node_id)
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub read: bool,
}

/// Inbox cap (oldest dropped).
const CAP: usize = 200;

pub struct NotificationCenter {
    items: Mutex<VecDeque<Notification>>,
    path: Option<PathBuf>,
    /// Unread-bump signal (UIs re-pull the list + count)
    events: tokio::sync::broadcast::Sender<()>,
}

impl NotificationCenter {
    /// Persistent center at the given path (load best-effort; write-through on push).
    pub fn open(path: PathBuf) -> std::sync::Arc<Self> {
        let items = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<VecDeque<Notification>>(&s).ok())
            .unwrap_or_default();
        let (events, _) = tokio::sync::broadcast::channel(64);
        std::sync::Arc::new(Self {
            items: Mutex::new(items),
            path: Some(path),
            events,
        })
    }

    /// In-memory center (tests).
    pub fn in_memory() -> std::sync::Arc<Self> {
        let (events, _) = tokio::sync::broadcast::channel(64);
        std::sync::Arc::new(Self {
            items: Mutex::new(VecDeque::new()),
            path: None,
            events,
        })
    }

    /// Default inbox path (~/.anet/notifications.json).
    pub fn open_default() -> std::sync::Arc<Self> {
        Self::open(agile_net_core::util::brand_root().join("notifications.json"))
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.events.subscribe()
    }

    pub fn push(&self, kind: &str, title: String, body: String, reason_code: &str, node_id: &str) {
        let n = Notification {
            id: uuid::Uuid::new_v4().to_string(),
            ts: chrono::Utc::now().to_rfc3339(),
            kind: kind.to_string(),
            title,
            body,
            reason_code: reason_code.to_string(),
            node_id: node_id.to_string(),
            read: false,
        };
        {
            let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
            items.push_front(n);
            while items.len() > CAP {
                items.pop_back();
            }
        }
        self.persist();
        let _ = self.events.send(());
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(json) = serde_json::to_string(&*items) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, json);
        }
    }

    pub fn list(&self) -> Vec<Notification> {
        self.items
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    pub fn unread_count(&self) -> usize {
        self.items
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|n| !n.read)
            .count()
    }

    pub fn mark_all_read(&self) {
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        for n in items.iter_mut() {
            n.read = true;
        }
        drop(items);
        self.persist();
    }

    /// Mark a single entry read (UI taps one notification row).
    pub fn mark_read(&self, id: &str) {
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = items.iter_mut().find(|n| n.id == id) {
            n.read = true;
        }
        drop(items);
        self.persist();
    }

    pub fn clear(&self) {
        self.items.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.persist();
    }
}
