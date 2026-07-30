//! 内存日志环形缓冲（/api/v1/admin/node/logs 数据源）
//!
//! 实现一个 tracing Layer，把最近的日志事件写入有界环形缓冲。

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

const MAX_ENTRIES: usize = 1000;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub time: String,
    pub level: String,
    pub module: String,
    pub message: String,
}

#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_ENTRIES))),
        }
    }

    pub fn push(&self, entry: LogEntry) {
        let mut buf = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() >= MAX_ENTRIES {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// 查询最近日志（新的在前），可选级别/模块过滤。
    pub fn query(&self, limit: usize, level: Option<&str>, module: Option<&str>) -> Vec<LogEntry> {
        let buf = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        buf.iter()
            .rev()
            .filter(|e| level.map(|l| e.level.eq_ignore_ascii_case(l)).unwrap_or(true))
            .filter(|e| module.map(|m| e.module.starts_with(m)).unwrap_or(true))
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// tracing_subscriber Layer 实现。
pub struct LogBufferLayer {
    buffer: LogBuffer,
}

impl LogBufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

impl<S> Layer<S> for LogBufferLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        let metadata = event.metadata();
        self.buffer.push(LogEntry {
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: metadata.level().to_string().to_lowercase(),
            module: metadata.target().to_string(),
            message: visitor.message,
        });
    }
}
