# 命令行 anet-svc cli

`anet-svc cli` 是命令行管理工具（原 `anet` 收编），适合脚本化与远程运维。

- 会话持久化于 `~/.anet/session.json`（Unix 0600），access_token 过期自动刷新
- ID 前缀解析：输入前几位即可（如 `anet-svc cli rule delete 3f2a`）
- `--json` 机器可读输出，默认表格输出
- `--api <url>` 覆盖节点地址（默认读会话或 `http://127.0.0.1:59090`）

## 登录与会话

```bash
anet-svc cli login -u admin -p 'AdminPass123'     # 缺省密码则安全提示输入
anet-svc cli status                                # 节点运行状态总览
anet-svc cli logout                                # 清除会话
```

## 规则管理

```bash
anet-svc cli rule list [--type ip-cidr] [--json]
anet-svc cli rule add --type ip-cidr --value 10.12.0.0/16 --remark 办公网
anet-svc cli rule add --type host --value git.internal --resolve
anet-svc cli rule delete 3f2a                      # ID 前缀
```

## 权限组

```bash
anet-svc cli group add --name office
anet-svc cli group list
anet-svc cli group bind-rules <group> <rule-id> [<rule-id>...]
```

## 客户端账号

```bash
anet-svc cli account add --username zhangsan --group office
# 输出 sk- 密码与 connect_url（仅一次）
anet-svc cli account add --username ops --group office --admin-console   # 管理版接入链接
anet-svc cli account list [--online]
anet-svc cli account reset-password 8c1d
anet-svc cli account disable 8c1d / anet-svc cli account enable 8c1d
anet-svc cli account delete 8c1d
```

## Relay 令牌

```bash
anet-svc cli token add --remark 分公司跳板机
anet-svc cli token add --remark 机房中继 --expose-control --scope rules   # 暴露控制面
anet-svc cli token list
anet-svc cli token delete 9f2e
```

## 管理员与审计

```bash
anet-svc cli admin add --username ops2            # 安全提示输入密码
anet-svc cli admin passwd                          # 修改自己的密码
anet-svc cli audit list [--action admin.login] [--json]
```

## 子命令 tui

```bash
anet-svc cli tui    # 等价于 anet-svc tui（直连数据库的本地控制台）
```
