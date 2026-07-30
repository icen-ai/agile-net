# agile-net-node 节点服务

## 职责

AgileNet 的服务端 binary。每个 Node 同时具备：
- **Listener 角色**：接受下游 Node / Client 连入（relay listener）
- **Connector 角色**：主动连接上游 Node（relay connector）
- **API Server**：HTTP API + Web Admin UI
- **Proxy**：当自身也是叶子节点时，为客户端的流量做 DIRECT 出站

## 启动流程

```
main()
├── 1. 加载 agile-net.toml
├── 2. 初始化 SQLite（建表 / 迁移）
├── 3. 检查 setup_required（首次启动引导）
├── 4. 启动 RelayListener（如果配置了 listen）
├── 5. 启动 RelayConnector（如果配置了 upstream）
├── 6. 启动 axum HTTP Server（API + Web UI）
├── 7. 启动 ProxyRouter（从 DB 加载规则到内存）
└── 8. 等待 SIGTERM → 优雅关闭
```

## 架构分层

```
┌─────────────────────────────────┐
│         API Layer (axum)         │  ← HTTP 路由 + JWT 中间件
├─────────────────────────────────┤
│       Service Layer              │  ← 业务逻辑、事务、校验
├─────────────────────────────────┤
│         DB Layer (rusqlite)      │  ← SQL 查询、CRUD
├─────────────────────────────────┤
│    Core (relay + proxy + tunnel) │  ← 网络引擎
└─────────────────────────────────┘
```

### API Layer

```rust
pub fn router(state: AppState) -> Router {
    Router::new()
        // Public
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/token/refresh", post(auth::refresh))
        .route("/api/v1/setup", post(auth::setup))
        // Client（tunnel_token）
        .nest("/api/v1/client", client_routes())
        // Admin（admin_token）
        .nest("/api/v1/admin", admin_routes())
        // Web UI（静态文件 fallback）
        .fallback(static_files::handler)
        .with_state(state)
}
```

### Service Layer

```rust
pub struct RuleService {
    db: Arc<Database>,
    router_notifier: watch::Sender<()>, // 通知 proxy 重新加载
}

impl RuleService {
    pub async fn create(&self, input: CreateRule) -> Result<Rule> {
        // 1. 校验 input
        // 2. 插入 DB
        // 3. 写审计日志
        // 4. 通知 proxy 热更新
    }
}
```

### DB Layer

```rust
pub trait Repository<T> {
    async fn find_by_id(&self, id: &str) -> Result<Option<T>>;
    async fn find_all(&self) -> Result<Vec<T>>;
    async fn insert(&self, entity: &T) -> Result<()>;
    async fn update(&self, entity: &T) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
}
```

## AppState

```rust
pub struct AppState {
    pub db: Arc<Database>,
    pub relay_listener: Option<Arc<RelayListener>>,
    pub relay_connector: Option<Arc<RelayConnector>>,
    pub proxy_router: Arc<RwLock<ProxyRouter>>,
    pub jwt_keys: JwtKeys,
    pub config: NodeConfig,
}
```

## 热更新机制

```
API 修改规则 → Service 写 DB → Service 发 watch::send(())
                                        │
                            ProxyRouter 订阅 watch::recv()
                                        │
                            从 DB 重新加载全量规则 → 替换路由表
```

使用 `tokio::sync::watch` 通知，ProxyRouter 在后台 task 监听变更信号。

## 内嵌 Web UI

```rust
#[derive(RustEmbed)]
#[folder = "web/dist"]
struct WebAssets;

async fn static_files(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    match WebAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], file.data).into_response()
        }
        // SPA fallback
        None => {
            let index = WebAssets::get("index.html").unwrap();
            ([(header::CONTENT_TYPE, "text/html")], index.data).into_response()
        }
    }
}
```
