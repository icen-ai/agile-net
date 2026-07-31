# Clash / FlClash 共存

AgileNet 默认端口统一在 5 万段，规避 Clash 系常用端口（7890/7891/9090 等），
可与 Clash/FlClash 在同一台机器上共存，并把 AgileNet 作为 Clash 的一个 socks5 节点按内网 CIDR 分流。

## 分工

- **AgileNet**：内网网段（公司/机房/嵌套内网）的穿透与精确路由
- **Clash/FlClash**：公网代理与规则分流的总入口

## 组合配置

1. anet-gui（或 `anet-svc client`）启动本地代理：`127.0.0.1:57890`
2. Clash 配置中加入 AgileNet 作为节点：

```yaml
proxies:
  - name: "agilenet"
    type: socks5
    server: 127.0.0.1
    port: 57890

rules:
  # 内网网段走 AgileNet
  - IP-CIDR,10.12.0.0/16,agilenet
  - IP-CIDR,10.100.0.0/16,agilenet
  - DOMAIN-SUFFIX,git.internal,agilenet
  # 其余走原有代理策略
  - MATCH,Proxy
```

3. 需要更细粒度时，AgileNet 侧的规则（CIDR/HOST）与 Clash 侧分流规则保持同源：
   AgileNet 命中规则进隧道，Clash 只负责把对应流量送到 57890。

## 端口约定

| 用途 | AgileNet 默认 | Clash 常用 |
| --- | --- | --- |
| 管理 API | 59090 | 9090（外部控制器） |
| Relay listener | 54430 | — |
| 本地代理 | 57890 | 7890/7891（混合/ socks） |

两者无端口冲突，可长期共存。
