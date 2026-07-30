# AgileNet Docker 部署测试

## 深度链路测试（docker-compose.test.yaml）

四层嵌套网络 + 四级节点链，验证长上下游链路与任意组合接入：

```
tester ──public──► node-root(L1) ──public──► node-mid(L2) ──mid──► node-leaf(L3) ──leaf──► node-deep(L4) ──deep──► target(nginx)
```

- `tester`（客户端）只能到达 L1/L2 所在 public-net
- `target`（10.140.0.100）只有 L4 可达，构成最深的嵌套目标
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
| T3 | 访问规则外目标 | 数据面 ACL 强制 |
| T4 | 客户端同时接入 root 与 mid | 多节点合并路由、不同深度接入 |
| T5 | root 新增规则后不重连直连 | 长轮询配置热更新 |

### 节点配置

- `configs/node-*.toml`：listener/connector/advertise/insecure（容器内自签证书互通，测试环境用 `insecure = true`；生产用证书固定）
- Relay token 通过 `AGILE_RELAY_TOKENS` 环境变量幂等预置（见 configs 中 token 值）
- 管理员通过 `AGILE_ADMIN_PASSWORD` 预置（容器自动化用）
