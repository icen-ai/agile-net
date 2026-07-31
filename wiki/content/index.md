<div class="hero">
  <div class="hero-title">AgileNet 文档</div>
  <div class="hero-sub">高安全、轻量级的 Rust 多节点网络穿透与代理链路由系统。<b>上下游同体</b>——没有 frps/frpc 式的分裂，最终只有两个产物：anet-gui 与 anet-svc。</div>
  <div class="hero-actions">
    <a class="btn btn-primary" href="#/getting-started/quickstart">快速上手</a>
    <a class="btn btn-ghost" href="https://github.com/icen-ai/agile-net">GitHub 仓库</a>
    <a class="btn btn-ghost" href="https://github.com/icen-ai/agile-net/releases">下载发布版</a>
  </div>
</div>

## 双产物

| 产物 | 形态 | 典型场景 |
| --- | --- | --- |
| **anet-gui** | 全功能图形客户端（Windows / macOS / Android） | 办公终端、内网转发机、机房留守管理端 |
| **anet-svc** | 服务器二进制（`serve` / `tui` / `client` / `cli` 子命令） | 服务器中继、内网网关 |

<div class="card-grid">
  <a class="card-link" href="#/getting-started/installation">
    <div class="cl-title"><i data-ic="download" data-sz="15"></i>安装</div>
    <div class="cl-desc">各平台安装包与二进制：Windows / macOS / Ubuntu / 麒麟 / 统信 / Android</div>
  </a>
  <a class="card-link" href="#/getting-started/quickstart">
    <div class="cl-title"><i data-ic="rocket" data-sz="15"></i>快速上手</div>
    <div class="cl-desc">五分钟跑通：起节点 → 建账号 → 接入链接 → 本地代理</div>
  </a>
  <a class="card-link" href="#/concepts/architecture">
    <div class="cl-title"><i data-ic="network" data-sz="15"></i>架构与双产物</div>
    <div class="cl-desc">上下游同体、多层级链式穿透、角色由配置决定</div>
  </a>
  <a class="card-link" href="#/concepts/management-plane">
    <div class="cl-title"><i data-ic="monitor" data-sz="15"></i>带内管理面</div>
    <div class="cl-desc">管理流量走数据面隧道；暴露控制面 + 管理可达自动发现</div>
  </a>
  <a class="card-link" href="#/guides/gui">
    <div class="cl-title"><i data-ic="monitor" data-sz="15"></i>anet-gui 指南</div>
    <div class="cl-desc">三路独立开关：客户端 / 服务端 / Web 远程面；控制台窗口</div>
  </a>
  <a class="card-link" href="#/reference/api">
    <div class="cl-title"><i data-ic="globe" data-sz="15"></i>REST API 参考</div>
    <div class="cl-desc">统一 {code,data} 信封、JWT 认证、管理面与客户端端点</div>
  </a>
  <a class="card-link" href="#/reference/protocol">
    <div class="cl-title"><i data-ic="layers" data-sz="15"></i>Mux 帧协议</div>
    <div class="cl-desc">Mux 帧结构、FrameType 规范、握手 v2 与 WindowUpdate 流控</div>
  </a>
  <a class="card-link" href="#/guides/troubleshooting">
    <div class="cl-title"><i data-ic="wrench" data-sz="15"></i>故障排查与诊断</div>
    <div class="cl-desc">Pinning 证书固定、系统 hosts 权限、端口占用与日志定位</div>
  </a>
</div>

## 特性一览

- **多层级链式穿透**：客户端经任意级 relay 链直达最深嵌套网段，断链自动重连自愈
- **聚合中继**：任一节点可同时是上游与下游；一台机器既是终端也是转发机
- **带内管理**：管理面流量走数据面隧道，控制台只是内网里的一个站点；relay 令牌可勾选「暴露控制面」（ro/rules/full 三档），管理可达性沿链路自动发现
- **全功能 GUI**：灵动岛状态通知、凭据管理、路由逐条启停、列表折叠搜索；三路角色开关
- **安全硬化**：argon2id 密码哈希、令牌只存哈希、证书固定 pinning、常数时间比较、登录限流锁定、全量审计、JWT 吊销轮换
- **Clash/FlClash 共存**：5 万段默认端口（API 59090 / Relay 54430 / 代理 57890），可作为 Clash 的 socks5 节点按内网 CIDR 分流

<div class="pill-row">
  <span class="pill">Rust 2024</span>
  <span class="pill">Tauri 2</span>
  <span class="pill">TLS 1.3</span>
  <span class="pill">SQLite WAL</span>
  <span class="pill">Docker 四级链断言</span>
  <span class="pill">Cloudflare Pages 文档站</span>
</div>
