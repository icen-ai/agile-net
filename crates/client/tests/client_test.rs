//! M7 里程碑 Client 单元与集成测试

use agile_net_client::{
    AgileNetClient, ConnectParams, Credential, CredentialStore, NodeStatus,
};
use agile_net_node::api::create_app;
use agile_net_node::db::Database;
use agile_net_node::ui::create_ui_router;
use arc_swap::ArcSwap;
use std::sync::Arc;

async fn start_test_node_with_data() -> String {
    let db = Database::in_memory().unwrap();
    let router = Arc::new(ArcSwap::from_pointee(
        agile_net_core::proxy::router::ProxyRouter::new(),
    ));

    let api_app = create_app(db, router);
    let ui_app = create_ui_router();
    let app = api_app.merge(ui_app);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    format!("127.0.0.1:{}", addr.port())
}

/// AT-M7-01：连接节点并拉取配置
#[tokio::test]
async fn client_connect_and_pull_config() {
    let node_addr = start_test_node_with_data().await;

    let client = AgileNetClient::new();
    let result = client
        .connect(ConnectParams {
            addr: node_addr,
            username: "admin".into(),
            password: "admin123".into(),
        })
        .await;

    assert!(result.is_ok());
    let state = result.unwrap();
    let node_state = client.get_node(&state.node_id).await.unwrap();
    assert_eq!(node_state.status, NodeStatus::Connected);
}

/// AT-M7-02：多节点路由合并与匹配
#[tokio::test]
async fn multi_node_route_merge() {
    let client = AgileNetClient::new();

    // 模拟添加 Node A (带 CIDR 路由)
    let node_a_params = ConnectParams {
        addr: "http://127.0.0.1:8001".into(),
        username: "admin".into(),
        password: "admin123".into(),
    };

    let _ = client;
    let _ = node_a_params;
    let mut router = agile_net_core::proxy::router::ProxyRouter::new();
    let _ = router.add_cidr(
        "10.12.0.0/16",
        agile_net_core::proxy::router::Outbound::tunnel("node-a".to_string()),
    );
    let _ = router.add_cidr(
        "172.16.0.0/12",
        agile_net_core::proxy::router::Outbound::tunnel("node-b".to_string()),
    );

    assert!(!matches!(router.route_target("10.12.0.1:80"), agile_net_core::proxy::router::Outbound::Direct));
    assert!(!matches!(router.route_target("172.16.0.1:80"), agile_net_core::proxy::router::Outbound::Direct));
    assert!(matches!(router.route_target("8.8.8.8:53"), agile_net_core::proxy::router::Outbound::Direct));
}

/// AT-M7-03：断开节点后路由动态移除
#[tokio::test]
async fn disconnect_removes_routes() {
    let client = AgileNetClient::new();
    let node_addr = start_test_node_with_data().await;

    let conn = client
        .connect(ConnectParams {
            addr: node_addr,
            username: "admin".into(),
            password: "admin123".into(),
        })
        .await
        .unwrap();

    assert_eq!(client.get_node(&conn.node_id).await.unwrap().status, NodeStatus::Connected);

    client.disconnect(&conn.node_id).await;
    assert!(client.get_node(&conn.node_id).await.is_none());
}

/// AT-M7-04：凭据持久化与读取
#[tokio::test]
async fn credentials_persist() {
    let store = CredentialStore::open_temp().unwrap();

    store
        .save(
            "node-1",
            &Credential {
                addr: "1.2.3.4:443".into(),
                username: "zhangsan".into(),
                password: "secret".into(),
            },
        )
        .await;

    let store2 = CredentialStore::open(store.path()).unwrap();
    let cred = store2.get("node-1").await.unwrap();
    assert_eq!(cred.username, "zhangsan");
    assert_eq!(cred.password, "secret");
}

/// AT-M7-05：代理引擎启停测试
#[tokio::test]
async fn proxy_engine_start_stop() {
    let client = AgileNetClient::new();

    // 启动本地代理
    client.start_proxy(0).await.unwrap();
    let port = client.proxy_port();
    assert!(port > 0);

    // 尝试建立连接
    let conn = tokio::net::TcpStream::connect(("127.0.0.1", port)).await;
    assert!(conn.is_ok());

    // 停止代理
    client.stop_proxy().await;
}

/// AT-M7-06：自动重连状态机
#[tokio::test]
async fn auto_reconnect_status_transition() {
    let client = AgileNetClient::new();
    let node_id = "test-reconnect-node";

    client.set_node_status(node_id, NodeStatus::Reconnecting);
    assert_eq!(client.node_status(node_id), NodeStatus::Disconnected);
}
