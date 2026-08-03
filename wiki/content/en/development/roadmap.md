# Roadmap

## Completed

- **Dual-artifact unification (P1→P3)**: `NodeServer` assembly-root extraction; anet-gui's three independent switches (client role / server role / Web remote plane);
  web-based client management plane (REST + dual-transport bridge + equal-strength authentication); management-grade connect URLs and the three scoped-admin tiers;
  relay-exposed Control Plane + handshake v2 control-endpoint delivery + manageable-node auto-discovery + route re-advertisement;
  convergence of the `anet-svc` (serve/tui/client/cli) and `anet-gui` artifacts, with CI/docker/docs kept in sync
- Multi-level chained traversal (four-level chain assertions T1-T7), broken-link self-healing, long-polling hot updates
- All-platform release pipeline (tag-triggered; Windows/macOS/Ubuntu/Android/musl static)
- Documentation site (this site, Cloudflare Pages)

## In Progress / Planned

| Direction | Content | Source |
| --- | --- | --- |
| Mobile system island | Android foreground-service persistent notification / iOS Live Activities, with a foreground/background split architecture | `docs/todo/island.md` |
| Production signing | Windows EV signing, macOS notarization, Android keystore + Play Store release | `docs/release.md` |
| Limited delegated management | Central console proxy forwarding (carrying the real operator identity header), the phase-two candidate of the D route | `docs/plan/merge-gui-svc.md` §5 |
| LoongArch support | loongarch64 toolchain verification and artifacts | — |
| iOS | Tauri iOS productization and App Store release | — |

## Scenario Validation Matrix

| Scenario | Status |
| --- | --- |
| Four-level chain traversal (root→mid→leaf→deep→target) | docker assertions T1-T6 (verified) |
| Server-room svc — server-room GUI (relay downstream + developer upstream + Web plane) | A+B+C all on (P1/P1.5, verified) |
| Off-site developer GUI connecting to the server room via a management-grade link, with the same experience as sitting in the server room | console channel + management link (P1.6, verified) |
| Managing nodes further upstream through relay traversal (relay + expose switch) | handshake v2 + auto-discovery + ticket chain (P2, assertion T7 verified) |
| FlClash coexistence (AgileNet as a socks5 node with CIDR-based traffic splitting) | documented |
