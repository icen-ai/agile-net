<div class="hero">
  <div class="hero-title">AgileNet Docs</div>
  <div class="hero-sub">A high-security, lightweight Rust multi-node network tunneling and proxy-chain routing system. <b>Fan-in and fan-out in one binary</b> — no frps/frpc-style split. In the end there are only two artifacts: anet-gui and anet-svc.</div>
  <div class="hero-actions">
    <a class="btn btn-primary" href="#/getting-started/quickstart">Quick Start</a>
    <a class="btn btn-ghost" href="https://github.com/icen-ai/agile-net">GitHub Repository</a>
    <a class="btn btn-ghost" href="https://github.com/icen-ai/agile-net/releases">Downloads</a>
  </div>
</div>

> **Every node holds sovereignty; all sides are equal**: publish rules and choose their recipients, but never peer into how the other side uses them within its own domain — restriction and auditing stop at the endpoint boundary, and accountability travels along the organizational chain.

## Two Artifacts

| Artifact | Form | Typical Scenarios |
| --- | --- | --- |
| **anet-gui** | Full-featured graphical client (Windows / macOS / Android) | Office terminals, intranet forwarders, lights-out server-room management |
| **anet-svc / anet** | Server binary + management commands (one implementation, two entry points: `start` / `stop` / `status` / `init` / `tui` …) | Server relays, intranet gateways |

<div class="card-grid">
  <a class="card-link" href="#/getting-started/installation">
    <div class="cl-title"><i data-ic="download" data-sz="15"></i>Installation</div>
    <div class="cl-desc">Installers and binaries for every platform: Windows / macOS / Ubuntu / Kylin / UOS / Android</div>
  </a>
  <a class="card-link" href="#/getting-started/quickstart">
    <div class="cl-title"><i data-ic="rocket" data-sz="15"></i>Quick Start</div>
    <div class="cl-desc">Up and running in five minutes: start a node → issue a token → access link → local proxy</div>
  </a>
  <a class="card-link" href="#/concepts/architecture">
    <div class="cl-title"><i data-ic="network" data-sz="15"></i>Architecture</div>
    <div class="cl-desc">Fan-in and fan-out in one binary, multi-level chained tunneling, roles decided by configuration</div>
  </a>
  <a class="card-link" href="#/concepts/management-plane">
    <div class="cl-title"><i data-ic="monitor" data-sz="15"></i>Management Plane</div>
    <div class="cl-desc">Management traffic rides the data-plane tunnel; control-plane exposure + automatic manageability discovery</div>
  </a>
  <a class="card-link" href="#/guides/gui">
    <div class="cl-title"><i data-ic="monitor" data-sz="15"></i>anet-gui Guide</div>
    <div class="cl-desc">Three independent switches: client / server / Web remote panel; console window</div>
  </a>
  <a class="card-link" href="#/reference/api">
    <div class="cl-title"><i data-ic="globe" data-sz="15"></i>REST API Reference</div>
    <div class="cl-desc">Unified {code,data} envelope, JWT auth, management and client endpoints</div>
  </a>
  <a class="card-link" href="#/reference/protocol">
    <div class="cl-title"><i data-ic="layers" data-sz="15"></i>Mux Frame Protocol</div>
    <div class="cl-desc">Mux frame layout, FrameType spec, handshake v2 and WindowUpdate flow control</div>
  </a>
  <a class="card-link" href="#/guides/troubleshooting">
    <div class="cl-title"><i data-ic="wrench" data-sz="15"></i>Troubleshooting</div>
    <div class="cl-desc">Certificate pinning, system hosts permissions, port conflicts and log analysis</div>
  </a>
</div>

## Feature Highlights

- **Multi-level chained tunneling**: clients reach the deepest nested network segment through relay chains of any length, with automatic reconnection and self-healing
- **Aggregated relay**: any node can fan in and fan out at the same time; one machine is both a terminal and a forwarder
- **In-band management**: management traffic rides the data-plane tunnel, so the console is just another site inside the intranet; relay tokens can opt into "expose control plane" (ro/rules/full tiers), and manageability is discovered automatically along the chain
- **Full-featured GUI**: dynamic-island status notifications, credential management, per-rule toggling, list folding and search; three role switches
- **Security hardening**: argon2id password hashing, hash-only token storage, certificate pinning, constant-time comparison, login rate limiting and lockout, full audit trail, JWT revocation and rotation
- **Coexists with Clash/FlClash**: default ports live in the 50k range (API 59090 / Relay 54430 / Proxy 57890), and AgileNet can serve Clash as a socks5 node with intranet CIDR routing

<div class="pill-row">
  <span class="pill">Rust 2024</span>
  <span class="pill">Tauri 2</span>
  <span class="pill">TLS 1.3</span>
  <span class="pill">SQLite WAL</span>
  <span class="pill">Docker four-level chain assertions</span>
  <span class="pill">Cloudflare Pages docs site</span>
</div>
