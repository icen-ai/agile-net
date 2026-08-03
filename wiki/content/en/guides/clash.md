# Clash / FlClash Coexistence

All AgileNet default ports live in the 50000 range, deliberately avoiding the ports commonly
used by Clash-family tools (7890/7891/9090, etc.). AgileNet can coexist with Clash/FlClash on
the same machine, registered as a socks5 node in Clash with intranet CIDRs routed to it.

## Division of Labor

- **AgileNet**: penetration and precise routing for intranet segments (corporate networks, server rooms, nested intranets)
- **Clash/FlClash**: the single entry point for public-Internet proxying and rule-based routing

## Combined Configuration

1. Start the local proxy with anet-gui (or `anet-svc client`): `127.0.0.1:57890`
2. Add AgileNet as a node in the Clash configuration:

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

3. For finer-grained control, keep AgileNet's rules (CIDR/HOST) and Clash's routing rules from the
   same source of truth: traffic that matches a rule enters the tunnel in AgileNet, and Clash only
   needs to deliver the corresponding traffic to 57890.

## Port Conventions

| Purpose | AgileNet Default | Clash Typical |
| --- | --- | --- |
| Admin API | 59090 | 9090 (external controller) |
| Relay listener | 54430 | — |
| Local proxy | 57890 | 7890/7891 (mixed / socks) |

The two have no port conflicts and can coexist long-term.
