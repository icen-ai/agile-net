# M6：Node Admin UI

## 目标

Node 内嵌 Web 管理界面，Admin 通过浏览器完成所有管理操作：规则、权限组、账号、节点状态监控。

## 依赖

M5 完成（API 全部就绪）。

## 产出

1. React SPA（Vite 构建）
2. 打包为静态资源嵌入 Node binary（rust-embed）
3. 所有 API 对应的管理页面
4. 实时连接状态面板

## 技术选型

| 库 | 用途 |
|----|------|
| React 18 | UI 框架 |
| Vite | 构建工具 |
| TailwindCSS | 样式 |
| React Router | 路由 |
| React Query | API 状态管理 |
| rust-embed | 静态资源嵌入 binary |

## 页面结构

```
/login          → 登录页
/dashboard      → 概览（在线客户端数 / 对等节点 / 规则数）
/rules          → 规则列表 + CRUD
/groups         → 权限组列表 + 规则绑定
/accounts       → 账号列表 + 创建（显示生成的密码）
/peers          → 对等节点列表 + 在线状态
/settings       → 节点配置（端口、TLS 证书路径）
```

## 任务清单

- [ ] `node/web/` 目录初始化：Vite + React + Tailwind
- [ ] 登录页：表单 → POST `/login` → 存 token → 跳 dashboard
- [ ] 布局组件：侧边栏导航 + header（显示节点名、登出）
- [ ] Dashboard 页：GET `/admin/node/status` 展示统计数据
- [ ] Rules 页：表格 + 创建弹窗 + 编辑 + 删除确认
- [ ] Groups 页：表格 + 规则绑定 checklist
- [ ] Accounts 页：表格 + 创建弹窗（显示生成密码，一次性复制）
- [ ] Peers 页：对等节点列表 + 在线/离线状态标识
- [ ] rust-embed 集成：build.rs 编译前端 → 嵌入 binary
- [ ] axum 静态文件服务：`/` 路径 serve 前端，`/api` 路径走 API
- [ ] token 自动刷新：React Query interceptor

## 验收测试

### AT-M6-01：Node 启动后可访问 Web UI

```rust
#[tokio::test]
async fn web_ui_accessible() {
    let node = start_test_node().await;

    // 访问根路径返回 HTML
    let resp = reqwest::get(format!("http://{}/", node.addr())).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<!DOCTYPE html>") || body.contains("<!doctype html>"));
}
```

### AT-M6-02：API 路径不受静态文件影响

```rust
#[tokio::test]
async fn api_and_static_coexist() {
    let node = start_test_node().await;

    // API 正常
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/v1/auth/login", node.addr()))
        .json(&json!({"username": "admin", "password": "admin123"}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 静态资源正常
    let resp = reqwest::get(format!("http://{}/assets/index.js", node.addr())).await;
    // 200 或 304 都可接受
    assert!(resp.unwrap().status().is_success());
}
```

### AT-M6-03：SPA 路由 fallback

```rust
#[tokio::test]
async fn spa_fallback() {
    let node = start_test_node().await;

    // 前端路由路径返回 index.html（不是 404）
    let resp = reqwest::get(format!("http://{}/rules", node.addr())).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("html"));
}
```

### AT-M6-04：未登录重定向（前端行为）

> 此项为 E2E 测试（playwright / cypress），CI 中可标记为 `#[ignore]`，本地手动验证。

```
场景：
1. 打开 http://node:port/dashboard
2. 因无 token，前端自动跳转到 /login
3. 登录后跳回 /dashboard
```

## 回归要求

CI 必须通过：AT-M1-* ~ AT-M5-* + AT-M6-01 ~ AT-M6-03

AT-M6-04 为手动 E2E，不阻塞 CI。
