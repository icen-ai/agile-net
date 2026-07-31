//! AgileNet Core — 核心网络库
//!
//! 提供穿透隧道 (relay)、本地代理 (proxy)、TLS 连接池 (tunnel)、
//! 通信协议 (proto) 和配置模型 (config) 五个子模块。

pub mod config;
pub mod error;
pub mod proto;
pub mod proxy;
pub mod relay;
pub mod tunnel;

/// 初始化 rustls 默认 CryptoProvider (使用 ring)
pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
