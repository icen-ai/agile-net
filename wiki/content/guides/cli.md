# 命令行 anet

`anet` 是管理命令入口（与 `anet-svc` 同一实现，按 argv[0] 自动分人格），适合脚本化与远程运维。

- 会话持久化于 `~/.anet/session.json`（Unix 0600），access_token 过期自动刷新
- ID 前缀解析：输入前几位即可（如 `anet rule delete 3f2a`）
- `--json` 机器可读输出，默认表格输出
- `--api <url>` 覆盖端点地址（默认读会话或 `http://127.0.0.1:59090`）

## 首装：初始化向导

```bash
anet init          # 交互式：配置文件 → 端点名称 → Web 管理/API → Relay → 管理员 → 系统服务 → 启动
anet init -y       # 非交互（自动化）：密码经 AGILE_ADMIN_PASSWORD 提供
```

系统服务自动识别发行版（Ubuntu / Rocky / 麒麟 / 统信 UOS 等 systemd 系）注册并启动；
无 root 降级打印 sudo 指引；Windows 经 sc.exe 注册。

## 服务管理

```bash
anet start [config.toml] [-d]   # 启动（默认前台；-d 后台守护）
anet stop                       # 停止（PID 文件 ~/.anet/svc/anet-svc.pid）
anet restart [config.toml]      # 重启
anet status                     # 运行状态（进程/配置/API 可达性，无需登录）
```

## 登录与会话

```bash
anet login -u admin -p 'AdminPass123'   # 缺省密码则安全提示输入
anet logout                              # 清除会话
```

## 节点信息

```bash
anet node status        # 端点运行状态总览
anet node rename 机房A  # 端点更名（立即生效并落审计）
```

## 规则管理

```bash
anet rule list [--type ip-cidr] [--json]
anet rule add --type ip-cidr --value 10.12.0.0/16 --remark 办公网
anet rule add --type host --value git.internal --resolve
anet rule update 3f2a --remark 新备注
anet rule delete 3f2a [--force]          # ID 前缀；--force 解除引用
anet rule batch rules.json [--on-conflict skip]
```

## 权限组

```bash
anet group add --name office [--rule-ids 3f2a,9f2e]
anet group list / anet group show office
anet group set-rules office 3f2a 9f2e     # 全量设置绑定规则
anet group update office --name 新名称
anet group delete office [--force]
```

## 统一签发（消费者接入）

消费者接入无账号层——资源主直接签发委托令牌（令牌即身份）。签发走 Web 后台
扇入页「签发」页签或 API `POST /api/v1/admin/delegation/tokens`（四维度：入口
direct/relay × 信任 明文/E2E/E2E+管理档 × 路由 dedicated/split × 并发 single/multi），
产出 `anet://connect?...` 接入链接（明文仅签发时展示一次）。

## Relay 令牌

```bash
anet token add --remark 分公司跳板机
anet token add --remark 机房中继 --group office                    # 收敛到权限组（缺省 = 不收敛）
anet token add --remark 机房中继 --expose-control --scope rules   # 暴露控制面（ro/rules/full）
anet token list                            # 含权限组/暴露面/档位列
anet token delete 9f2e                     # 在线下游立即被踢
```

## 扇出对端（connector）

connector 为一等入库资源（TOML `[[connectors]]` 仅启动导入），增删改与启停即时生效；
`--group` 挂权限组即对端收敛（缺省 = 不收敛）。

```bash
anet connector list                        # 含实时状态与所属组
anet connector add --name 机房B --addr relay-b.example.com:54430 --token psk_... \
    [--sni cdn.cloudflare.com] [--fp sha256指纹] [--advertise 10.12.0.0/16,git.internal] [--group office]
anet connector update 3f2a [--group 新组] [--token psk_新]   # 缺省参数保留原值
anet connector enable 3f2a / anet connector disable 3f2a    # 启用起连 / 禁用断开
anet connector remove 3f2a
```

扇出 token 为对端签发凭据：加密落库，创建后不回显（`update --token` 仅用于重置）。
对端 relay 证书为自签拟态证书，系统 CA 验不过：`--fp` 钉证书指纹（对端节点状态页可复制）即可免 insecure，优先于一切校验方式。

## 管理员与审计

```bash
anet admin list / anet admin add --username ops2    # 安全提示输入密码
anet admin passwd                                   # 修改自己的密码
anet admin reset-password admin --offline           # 忘记密码：数据库直沉重置（本机操作，无需登录，会话一并吊销）
anet audit list [--action admin.login] [--json]
```

## 网络工具 anet tool

内置本机网络诊断工具集（无需登录、不走会话校验），替代 telnet / nc / curl / ping / netstat / lsof 等常见命令，
面向无法联网装包的裁剪环境。退出码约定：`0` 可达、`1` 不可达、`2` 用法/环境错误。

```bash
anet tool selfcheck                 # 巡检 PATH 缺失命令 + 替代方案引导
anet tool tcping db.internal 5432   # 别名 telnet / nc；-c 多次 min/avg/max
anet tool curl https://example.com -k
anet tool dns example.com @223.5.5.5 AAAA    # 别名 nslookup
anet tool listen --proto tcp        # 别名 netstat / ports；portof / portsof / lsof -i:<port>
anet tool ping host / anet tool traceroute host   # 无权限自动降级 TCP / 输出授权指引
anet tool diag example.com 443      # DNS → ping → traceroute → tcping，定位卡在哪一层
```

完整命令清单、别名、权限需求表与降级链见[网络工具 anet tool](#/guides/tools)。

## TUI

```bash
anet tui               # 默认走 API（需 login），写操作落审计
anet tui --offline     # 直连数据库只读兜底（节点未启动时也能查看）
```
