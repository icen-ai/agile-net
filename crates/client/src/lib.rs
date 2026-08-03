//! AgileNet Client 核心引擎
//!
//! 完整数据面实现：
//! 1. 登录节点 API（access + refresh + tunnel_token）
//! 2. 拉取路由配置并建立 ClientTunnel（TLS 1.3 + tunnel_token 数据面认证）
//! 3. 多节点路由合并 + 本地 SOCKS5/HTTP 代理入站
//! 4. 长轮询配置热更新 + 心跳上报 + 断线自动重连
//! 5. resolve 规则自动维护系统 hosts（可选）
//!
//! 模块划分：
//! - `client`：多节点引擎（连接生命周期/合并路由/后台任务/本地代理入站）
//! - `credential`：凭据存储（OS keyring 优先，0600 文件回退，旧明文自动迁移）
//! - `config_cache`：节点配置离线缓存
//! - `connect_url`：agilenet://connect 接入链接解析与生成
//! - `custom_rules`：自定义规则（GUI 放行 / hosts 映射）
//! - `hosts`：系统 hosts 文件管理

use std::path::PathBuf;

pub mod api;
pub mod daemon;

mod client;
mod config_cache;
mod connect_url;
mod credential;
mod custom_rules;
mod hosts;

pub use client::{
    AgileNetClient, ClientRule, ConnectParams, ManageableNode, NodeState, NodeStatus,
};
pub use config_cache::{CachedNodeConfig, ConfigCache};
pub use connect_url::{ParsedConnect, connect_url_of, parse_connect_url};
pub use credential::{Credential, CredentialStore};
pub use custom_rules::{CustomBypassRule, CustomRules};
pub use hosts::HostsManager;

pub use agile_net_core::proxy::router::wildcard_match;

fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
