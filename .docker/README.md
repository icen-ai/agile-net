# AgileNet Docker 部署测试

## 深度链路测试（docker-compose.test.yaml）

四层嵌套网络 + 四级节点链，验证长上下游链路与任意组合接入：

```
tester ──public──► node-root(L1) ──public──► node-mid(L2) ──mid──► node-leaf(L3) ──leaf──► node-deep(L4) ──deep──► target(nginx)
```

- 消费凭据 = **direct 委托令牌**（`POST /api/v1/admin/delegation/tokens`，entry_mode=direct /
  dedicated 全量路由 / multi 并存），客户端 TOML 为链接式 `nodes = ["anet://connect?..."]`
- 透明档多级转发（「盖章择跳」）：签发者 listener 按令牌 ACL 快照执法；组标是会合回传
  专用元数据，直连签发者的下行 Open 清标裸奔——中间跳纯路由，无需同名组
- `tester`（客户端）只能到达 L1/L2 所在 public-net
- `target`（10.140.0.100）/ `target2`（10.150.0.100）只有 L4 可达，构成最深的嵌套目标
- 数据路径：client → root → mid → leaf → deep → target（4 跳转发）

### 运行

```bash
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up \
  --abort-on-container-exit --exit-code-from tester
```

退出码 0 = 全部断言通过。清理：`docker compose -f .docker/docker-compose.test.yaml down -v`

### 断言矩阵（run-chain-test.sh）

| # | 场景 | 验证点 |
|---|------|--------|
| T1 | SOCKS5 经四级链访问最深目标 | 长链路转发正确性 |
| T2 | HTTP CONNECT 经同一链路 | 双协议入站 |
| T3 | 访问规则外目标 | 签发者 listener ACL 快照强制 |
| T4 | 客户端同时接入 root 与 mid | 多节点合并路由、不同深度接入 |
| T5 | root 组新增规则后不重连访问 target2 | 会话 ACL 逐 Open 热解析（注册表 2s watcher 热刷） |
| T6 | kick mid 后链路中断再自愈 | 扇出指数退避重连 |
| T7 | mid 自动发现 root 控制端点 | 握手控制面暴露（manageable_upstreams，rules 档；票据链由 control_plane_test 覆盖） |
| T8 | mid 经扇出隧道测 root | bandwidth 结构化返回（RTT/8MiB 上下行） |

### 节点配置

- `configs/node-*.toml`：listener/connector/advertise/insecure（容器内自签证书互通，测试环境用 `insecure = true`；生产用证书固定）
- Relay token 通过 `AGILE_RELAY_TOKENS` 环境变量幂等预置（见 configs 中 token 值）
- 管理员通过 `AGILE_ADMIN_PASSWORD` 预置（容器自动化用）

## 常驻链路演示（docker-compose.chain.yaml）

同一四级链拓扑的常驻版本（无 tester 断言），供从**宿主机**真实访问最深层网络：

- `node-root` 的 API(59090) 与 Relay(54430) 发布到宿主机（`127.0.0.1:59290` / `127.0.0.1:54430`），
  且 `AGILE_PUBLIC_HOST=127.0.0.1` 保证签发链接的入口地址在宿主机可解析
- `target` 挂载 `tests/deep-index.html` 作为深层网络标识页

```bash
docker compose -f .docker/docker-compose.chain.yaml up -d
# 宿主机连入：在 root 管理面（http://127.0.0.1:59290）签发 direct 委托令牌，
# 把 share_url（anet://connect?...）写进客户端 TOML：
# nodes = ["anet://connect?server=127.0.0.1&port=54430&account=d:<label>&password=psk_...&fp=<指纹>"]
```

经客户端本地代理即可访问 `http://10.140.0.100/`；演示时可在宿主机再架一层
HTTP→CONNECT 转发（如 target/tmp/chain-gateway.js），把 `http://127.0.0.1:58080/`
映射到深层目标，浏览器直接打开即可。
清理：`docker compose -f .docker/docker-compose.chain.yaml down -v`
