//! 隧道连接池
//!
//! 占位实现，M4 里程碑完善。

/// 隧道连接池。
pub struct TunnelPool {
    _placeholder: (),
}

impl TunnelPool {
    /// 创建空连接池。
    pub fn new() -> Self {
        Self { _placeholder: () }
    }

    /// 当前可用连接数。
    pub fn available(&self) -> usize {
        0
    }
}

impl Default for TunnelPool {
    fn default() -> Self {
        Self::new()
    }
}
