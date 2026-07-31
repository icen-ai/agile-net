# Docker 链路与演示

`.docker/` 提供四级嵌套网络环境：链路断言测试（一次性）与常驻演示（宿主机直连最深层网络）。

## 拓扑

```
tester ──public(172.28)──► node-root ──public──► node-mid ──mid(10.100)──► node-leaf ──leaf(10.120)──► node-deep ──deep(10.140)──► target
```

tester 只能到达 root/mid；target（10.140.0.100）仅 node-deep 可达。
数据路径：client(tester) → root → mid → leaf → deep → target。

## 链路断言测试

```bash
docker build -f .docker/Dockerfile -t anet:dev .
docker compose -f .docker/docker-compose.test.yaml up --abort-on-container-exit --exit-code-from tester
```

断言矩阵（全部通过则退出码 0）：

| 断言 | 内容 |
| --- | --- |
| T1 | 四级链 SOCKS5 穿透 |
| T2 | 同目标经 HTTP CONNECT |
| T3 | ACL 拒绝：规则外目标必须失败 |
| T4 | 多节点接入：同一客户端同时接 root 与 mid |
| T5 | 长轮询配置热更新：新增规则客户端无需重连即生效 |
| T6 | 断链自愈：kick mid → 链路中断 → 自动重连恢复 |
| T7 | 管理面穿透：握手下发控制端点 → 自动发现 → 票据链换取 scoped 管理会话（rules 档位强制） |

> Windows 下若演示链在跑，先 `docker compose -f .docker/docker-compose.chain.yaml down`
> 释放子网，再跑测试。

## 常驻演示

```bash
docker compose -f .docker/docker-compose.chain.yaml up -d
```

宿主机可直接 `anet-svc client` 或 anet-gui 连入 root（`127.0.0.1` 映射端口），
体验经四级链访问 10.140.0.100 的完整路径。

## 自定义链路

编排要点：

- 各节点 `AGILE_RELAY_TOKENS` 预置下游令牌（按哈希幂等）；支持 `psk_xxx|expose:rules` 暴露控制面
- `AGILE_PUBLIC_HOST` 设为容器网络内可解析名，保证 connect_url/隧道端点正确
- 配置文件挂 `/etc/agile-net/node.toml`：`[listener]` 开上游面，`[connector]` 接上游，
  `advertise` 通告本网段（多级时自动含下游链路）
