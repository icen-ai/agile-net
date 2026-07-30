# agile-net-client Tauri 客户端

## 职责

用户端桌面应用。连接一个或多个 Node，拉取路由配置，启动本地代理，按规则路由流量。

## 技术栈

| 组件 | 选型 |
|------|------|
| 框架 | Tauri 2 |
| 前端 | React + TailwindCSS |
| Rust 端 | agile-net-core（relay + proxy + tunnel） |
| 持久化 | 加密 JSON（AES-256-GCM） |

## 进程模型

```
agile-net-client.exe (Tauri 主进程)
├── WebView (React UI)
├── Proxy Engine (tokio runtime)
│   ├── SOCKS5/HTTP Inbound (127.0.0.1:PORT)
│   └── ProxyRouter
├── Tunnel Manager
│   ├── TunnelPool → Node-A
│   ├── TunnelPool → Node-B
│   └── ...
└── System Tray
```

所有网络操作在 Rust 端的 tokio runtime 执行，前端仅负责 UI 和 IPC 调用。

## Tauri Commands

```rust
#[tauri::command]
async fn connect_node(addr: String, username: String, password: String) -> Result<NodeInfo, String>;

#[tauri::command]
async fn disconnect_node(node_id: String) -> Result<(), String>;

#[tauri::command]
async fn get_nodes() -> Result<Vec<NodeInfo>, String>;

#[tauri::command]
async fn start_proxy(port: u16) -> Result<u16, String>;

#[tauri::command]
async fn stop_proxy() -> Result<(), String>;

#[tauri::command]
async fn get_traffic_stats() -> Result<TrafficStats, String>;

#[tauri::command]
async fn set_hosts_enabled(enabled: bool) -> Result<(), String>;
```

## 连接流程

```
connect_node(addr, user, pass)
│
├── 1. POST /api/v1/auth/login → 获取 access_token + tunnel_token
├── 2. GET /api/v1/client/config → 获取路由规则
├── 3. 创建 TunnelPool(addr, tunnel_token)
├── 4. 将规则合并到 ProxyRouter
├── 5. 保存凭据到本地加密存储
└── 6. 返回 NodeInfo { id, name, status, rules }
```

## 凭据存储

```rust
pub struct CredentialStore {
    path: PathBuf,
    key: [u8; 32], // 从机器指纹派生
}

impl CredentialStore {
    pub fn open(path: &Path) -> Result<Self>;
    pub fn save(&self, node_id: &str, cred: &Credential) -> Result<()>;
    pub fn get(&self, node_id: &str) -> Result<Option<Credential>>;
    pub fn delete(&self, node_id: &str) -> Result<()>;
    pub fn list(&self) -> Result<Vec<(String, Credential)>>;
}
```

加密方式：AES-256-GCM，密钥从机器标识（Windows: MachineGUID）+ 固定盐派生。

## 多节点路由管理

```rust
pub struct NodeManager {
    nodes: DashMap<NodeId, ManagedNode>,
    router: Arc<RwLock<ProxyRouter>>,
}

struct ManagedNode {
    info: NodeInfo,
    pool: TunnelPool,
    rules: Vec<Rule>,
    status: NodeStatus,
    reconnect_task: Option<JoinHandle<()>>,
}

impl NodeManager {
    pub async fn connect(&self, params: ConnectParams) -> Result<NodeId>;
    pub async fn disconnect(&self, node_id: &NodeId);
    pub fn get_all(&self) -> Vec<NodeInfo>;

    /// 从所有已连接节点的规则重新构建路由表
    fn rebuild_routes(&self) {
        let mut router = ProxyRouter::new();
        for entry in self.nodes.iter() {
            for rule in &entry.rules {
                router.insert(rule, Outbound::Tunnel { node_id: *entry.key() });
            }
        }
        *self.router.write() = router;
    }
}
```

## 系统托盘

```rust
pub fn create_tray(app: &App) -> Result<()> {
    let menu = SystemTrayMenu::new()
        .add_item("显示主窗口", "show")
        .add_separator()
        .add_item("代理：已开启", "toggle_proxy")  // 动态文字
        .add_item("已连 2 个节点", "status")        // 动态文字
        .add_separator()
        .add_item("退出", "quit");

    SystemTray::new()
        .with_menu(menu)
        .with_tooltip("AgileNet")
        .on_event(handle_tray_event)
        .build(app)?;
    Ok(())
}
```

## hosts 文件管理（可选功能）

当规则包含 HOST 类型（如 `git.internal.com → 10.12.0.50`）时，可以选择将映射写入系统 hosts 文件，这样非代理的应用也能访问内网域名。

```rust
pub struct HostsManager {
    /// AgileNet 管理的条目标记
    marker: &'static str, // "# AgileNet Managed - Do Not Edit"
}

impl HostsManager {
    /// 在 hosts 文件中追加/更新 AgileNet 管理的条目
    pub fn update(&self, entries: &[(String, IpAddr)]) -> Result<()>;
    /// 清除所有 AgileNet 管理的条目
    pub fn clear(&self) -> Result<()>;
}
```

注意：修改 hosts 文件需要管理员权限，Tauri 端通过 `runas` 或 UAC 提权。

## 预估体积

| 组件 | 预估 |
|------|------|
| Tauri runtime + WebView | ~5MB（使用系统 WebView2） |
| agile-net-core（Rust） | ~3MB |
| React UI（压缩后） | ~500KB |
| **总安装包** | **~10-15MB** |
