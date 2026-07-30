//! 统一错误类型

use thiserror::Error;

/// AgileNet 核心库统一错误。
#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("auth: {0}")]
    Auth(String),

    #[error("timeout")]
    Timeout,

    #[error("pool exhausted")]
    PoolExhausted,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
