# The anet CLI

`anet` is the management command entry point (same implementation as `anet-svc`, switching
personas automatically by argv[0]), suited for scripting and remote operations.

- Sessions persist to `~/.anet/session.json` (Unix 0600); expired access tokens refresh automatically
- ID prefix resolution: the first few characters are enough (e.g. `anet rule delete 3f2a`)
- `--json` for machine-readable output; tables by default
- `--api <url>` overrides the endpoint address (defaults to the session value or `http://127.0.0.1:59090`)
- Compatibility: the legacy `anet-svc cli ...` entry still works (deprecated; equivalent to the top-level command of the same name)

## First Install: Setup Wizard

```bash
anet init          # 交互式：配置文件 → 端点名称 → Web 管理/API → Relay → 管理员 → 系统服务 → 启动
anet init -y       # 非交互（自动化）：密码经 AGILE_ADMIN_PASSWORD 提供
```

The system-service step detects the distribution (Ubuntu / Rocky / Kylin / UnionTech UOS and other
systemd-based systems), then registers and starts the service; without root it degrades to printing
sudo instructions; on Windows it registers via sc.exe.

## Service Management

```bash
anet start [config.toml] [-d]   # 启动（默认前台；-d 后台守护）
anet stop                       # 停止（PID 文件 ~/.agile-net/anet-svc.pid）
anet restart [config.toml]      # 重启
anet status                     # 运行状态（进程/配置/API 可达性，无需登录）
```

## Login and Sessions

```bash
anet login -u admin -p 'AdminPass123'   # 缺省密码则安全提示输入
anet logout                              # 清除会话
```

## Node Information

```bash
anet node status        # 端点运行状态总览
anet node rename 机房A  # 端点更名（立即生效并落审计）
```

## Rule Management

```bash
anet rule list [--type ip-cidr] [--json]
anet rule add --type ip-cidr --value 10.12.0.0/16 --remark 办公网
anet rule add --type host --value git.internal --resolve
anet rule update 3f2a --remark 新备注
anet rule delete 3f2a [--force]          # ID 前缀；--force 解除引用
anet rule batch rules.json [--on-conflict skip]
```

## Groups

```bash
anet group add --name office [--rule-ids 3f2a,9f2e]
anet group list / anet group show office
anet group set-rules office 3f2a 9f2e     # 全量设置绑定规则
anet group update office --name 新名称
anet group delete office [--force]
```

## Client Accounts

```bash
anet account add --username zhangsan --group office
# 输出 sk- 密码与 connect_url（仅一次）
anet account add --username ops --group office --admin   # 管理版接入链接（签发记审计）
anet account list [--group office] [--enabled true]
anet account update 8c1d --enabled false / --admin true
anet account reset-password 8c1d
anet account delete 8c1d
```

## Relay Tokens

```bash
anet token add --remark 分公司跳板机
anet token add --remark 机房中继 --group office                    # 收敛到权限组（缺省 = 不收敛）
anet token add --remark 机房中继 --expose-control --scope rules   # 暴露控制面（ro/rules/full）
anet token list                            # 含权限组/暴露面/档位列
anet token delete 9f2e                     # 在线下游立即被踢
```

## Fan-out Peers (connector)

Connectors are first-class database resources (TOML `[[connectors]]` is imported at startup only);
add/update/remove and enable/disable take effect immediately. Attaching a `--group` applies peer
restriction (default = unrestricted).

```bash
anet connector list                        # 含实时状态与所属组
anet connector add --name 机房B --addr relay-b.example.com:54430 --token psk_... \
    [--sni cdn.cloudflare.com] [--fp sha256指纹] [--advertise 10.12.0.0/16,git.internal] [--group office]
anet connector update 3f2a [--group 新组] [--token psk_新]   # 缺省参数保留原值
anet connector enable 3f2a / anet connector disable 3f2a    # 启用起连 / 禁用断开
anet connector remove 3f2a
```

A fan-out token is a credential issued by the peer: stored encrypted in the database and never
displayed again after creation (`update --token` is only for resetting it).
The peer relay cert is a self-signed mimicry cert that system CAs can never verify: pin its
fingerprint with `--fp` (copy it from the peer's node status page) instead of using insecure —
pinning takes priority over every other verification mode.

## Admins and Audit

```bash
anet admin list / anet admin add --username ops2    # 安全提示输入密码
anet admin passwd                                   # 修改自己的密码
anet admin reset-password admin --offline           # Forgot the password: direct DB reset (local operation, no login; sessions revoked)
anet audit list [--action admin.login] [--json]
```

## Network Tools: anet tool

A built-in local network diagnostics toolset (no login, no session validation) that replaces common
commands such as telnet / nc / curl / ping / netstat / lsof, aimed at trimmed-down environments
where packages cannot be installed online. Exit codes: `0` reachable, `1` unreachable, `2` usage/environment error.

```bash
anet tool selfcheck                 # 巡检 PATH 缺失命令 + 替代方案引导
anet tool tcping db.internal 5432   # 别名 telnet / nc；-c 多次 min/avg/max
anet tool curl https://example.com -k
anet tool dns example.com @223.5.5.5 AAAA    # 别名 nslookup
anet tool listen --proto tcp        # 别名 netstat / ports；portof / portsof / lsof -i:<port>
anet tool ping host / anet tool traceroute host   # 无权限自动降级 TCP / 输出授权指引
anet tool diag example.com 443      # DNS → ping → traceroute → tcping，定位卡在哪一层
```

For the full command list, aliases, permission requirements, and fallback chains, see [Network Tools (anet tool)](#/guides/tools).

## TUI

```bash
anet tui               # 默认走 API（需 login），写操作落审计
anet tui --offline     # 直连数据库只读兜底（节点未启动时也能查看）
```
