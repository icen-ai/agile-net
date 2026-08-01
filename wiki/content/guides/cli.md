# 命令行 anet

`anet` 是管理命令入口（与 `anet-svc` 同一实现，按 argv[0] 自动分人格），适合脚本化与远程运维。

- 会话持久化于 `~/.anet/session.json`（Unix 0600），access_token 过期自动刷新
- ID 前缀解析：输入前几位即可（如 `anet rule delete 3f2a`）
- `--json` 机器可读输出，默认表格输出
- `--api <url>` 覆盖端点地址（默认读会话或 `http://127.0.0.1:59090`）
- 兼容：`anet-svc cli ...` 旧式入口仍可用（已废弃，等同顶层同名命令）

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
anet stop                       # 停止（PID 文件 ~/.agile-net/anet-svc.pid）
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

## 客户端账号

```bash
anet account add --username zhangsan --group office
# 输出 sk- 密码与 connect_url（仅一次）
anet account add --username ops --group office --admin   # 管理版接入链接（签发记审计）
anet account list [--group office] [--enabled true]
anet account update 8c1d --enabled false / --admin true
anet account reset-password 8c1d
anet account delete 8c1d
```

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
    [--sni cdn.cloudflare.com] [--advertise 10.12.0.0/16,git.internal] [--group office]
anet connector update 3f2a [--group 新组] [--token psk_新]   # 缺省参数保留原值
anet connector enable 3f2a / anet connector disable 3f2a    # 启用起连 / 禁用断开
anet connector remove 3f2a
```

扇出 token 为对端签发凭据：加密落库，创建后不回显（`update --token` 仅用于重置）。

## 管理员与审计

```bash
anet admin list / anet admin add --username ops2    # 安全提示输入密码
anet admin passwd                                   # 修改自己的密码
anet audit list [--action admin.login] [--json]
```

## TUI

```bash
anet tui               # 默认走 API（需 login），写操作落审计
anet tui --offline     # 直连数据库只读兜底（节点未启动时也能查看）
```
