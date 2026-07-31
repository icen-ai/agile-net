# 快速上手

五分钟跑通最小可用链路：**起节点 → 建账号 → 客户端接入 → 本地代理**。

## 1. 启动节点（anet-svc）

```bash
anet-svc serve
# anet-svc v0.1.0 starting
# Web Dashboard & API Server started (http://0.0.0.0:59090)
```

无配置文件也能启动（缺省仅 API）。生产建议使用配置文件：

```toml
# agile-net.toml
name = "my-node"
db_path = "agile-net.db"
public_host = "relay.example.com"   # connect_url 与隧道端点对外展示地址

[api]
addr = "0.0.0.0:59090"
# tls_cert_path = "certs/api-cert.pem"   # 生产建议启用 HTTPS
# tls_key_path = "certs/api-key.pem"

[listener]
addr = "0.0.0.0:54430"
cert_path = "certs/relay-cert.pem"
key_path = "certs/relay-key.pem"
sni_hostname = "cdn.cloudflare.com"
```

> 首次启动可用环境变量预置管理员：`AGILE_ADMIN_USERNAME=admin AGILE_ADMIN_PASSWORD='强密码(≥10位)'`；
> 或启动后走 Web 后台初始化（下一步）。

## 2. 初始化管理员并建账号

打开 `http://<节点>:59090`，完成管理员初始化（仅一次）。然后在 Web 后台：

1. **权限组**：新建组（如 `office`）
2. **路由规则**：添加内网网段，如 `ip-cidr 10.12.0.0/16`、`host git.internal`
3. 回到权限组，把规则绑定到组
4. **客户端账号**：新建账号（密码由服务端生成 `sk-` 48 位，仅展示一次）

创建成功即得到接入链接：

```
agilenet://connect?server=relay.example.com&port=59090&account=zhangsan&password=sk-...&tls=1&fp=<证书指纹>
```

> 证书指纹（`fp`）使客户端一键完成证书固定（pinning），无需 insecure。
> 勾选「同时授予管理权限」会生成管理版链接（`&admin=1`），见「核心概念 → 带内管理面」。

## 3. 客户端接入（anet-gui）

安装并打开 anet-gui，把接入链接粘贴到首页输入框 → **一键接入**。连接成功后：

- 「节点」页显示节点卡片与实时状态
- 「路由」页展示合并路由表，可逐条暂停/恢复（立即生效并本地记忆）
- 点击 **启动代理**，本地 `127.0.0.1:57890` 提供 SOCKS5/HTTP 自动识别代理

把系统或应用代理指向 `127.0.0.1:57890`，命中规则的流量进入隧道，其余直连。

## 4. 无 GUI 的终端（anet-svc client）

服务器/容器里的终端角色用 `client` 子命令：

```toml
# client.toml
proxy_port = 57890
manage_hosts = true

[[nodes]]
addr = "https://relay.example.com:59090"
username = "zhangsan"
password = "sk-..."
pinned_fingerprint = "<证书指纹>"
```

```bash
anet-svc client client.toml
# local proxy listening on 127.0.0.1:57890 (SOCKS5/HTTP)
```

## 5. 验证

```bash
# 经代理访问内网目标
curl --socks5-hostname 127.0.0.1:57890 http://10.12.1.10/

# 经代理命中 host 规则
curl -x http://127.0.0.1:57890 http://git.internal/
```

到这里最小链路已通。进阶：

- 多级中继链：`anet-svc serve` 同时配置 `[connector]`（接上游）与 `[listener]`（供下游），见「架构与双产物」
- 图形化管全网：`anet-gui` 开启服务端角色 + 管理版接入链接，见「带内管理面」
- 命令行管理：`anet-svc cli`，见「命令行 anet-svc cli」
