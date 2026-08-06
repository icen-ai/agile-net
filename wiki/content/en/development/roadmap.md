# Roadmap

## Completed

- **Dual-artifact unification**: `NodeServer` assembly-root extraction; anet-gui's three independent switches (client role / server role / Web remote plane);
  anet-svc's single-port unified Web (`/` admin SPA, `/client` client SPA, shared AdminAuth login);
  the three scoped-admin tiers; relay-exposed control plane + manageable-node auto-discovery + route re-advertisement
- **Unified issuance**: the account system was removed wholesale; delegated_token became the sole consumer identity (entry direct/relay × trust plaintext/E2E/E2E+management × routing dedicated/split × concurrency single/multi);
  the fan-in/fan-out pages carry three tabs "Watch | Connect | Issue"; DB migrations collapsed into baseline v1; protocol v4 as the only behavior;
  links unified on `anet://`; the client crate is delegation-only (link-style `nodes` TOML)
- Federation: policy push / one-click adoption (read-only live mirrors), delegated-issuance disaster sets, E2E entrust zero-disclosure routing
- Multi-level chained traversal (four-level chain assertions T1-T7), broken-link self-healing, rule hot updates
- All-platform release pipeline (tag-triggered; Windows/macOS/Ubuntu/Android/musl static)
- Documentation site (this site, Cloudflare Pages)

## In Progress / Planned

| Direction | Content | Source |
| --- | --- | --- |
| Mobile system island | Android foreground-service persistent notification / iOS Live Activities, with a foreground/background split architecture | `docs/todo/island.md` |
| Production signing | Windows EV signing, macOS notarization, Android keystore + Play Store release | `docs/release.md` |
| Limited delegated management | Central console proxy forwarding (carrying the real operator identity header), the phase-two candidate of the D route | — |
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
