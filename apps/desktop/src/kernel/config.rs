//! Split out of subscription.rs: config generation and loop prevention (pure move, zero logic changes)

use crate::roles;

use super::store::{SubStore, Subscription};

/// mixed inbound (avoids the Clash 7890 family, local proxy 57890, and the commonly taken 57891)
pub const MIHOMO_MIXED_PORT: u16 = 57892;
/// TUN mode: mihomo socks inbound (fallback for traffic anet misses, direct to the subscription egress via the IN-TYPE rule)
pub const MIHOMO_SOCKS_PORT: u16 = 57893;
/// external-controller (avoids 9090)
pub const MIHOMO_CTRL_PORT: u16 = 59292;

// ==================== Config generation (full rewrite, never hand-edit) ====================

fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render mihomo config.yaml from the subscription list (loads only the active subscription; single provider always named main).
/// mode is the outbound mode (rule|global|direct; invalid values fall back to rule); tun=true uses the TUN skeleton (§2.3).
/// relay_hosts are the connected delegated nodes' relay entry hosts, rendered as carriage rules in TUN mode only.
pub fn render_config(store: &SubStore, mode: &str, tun: bool, relay_hosts: &[String]) -> String {
    if tun {
        return render_config_tun(store, relay_hosts);
    }
    let mode = if roles::valid_sub_mode(mode) {
        mode
    } else {
        "rule"
    };
    let active = store.subscriptions.iter().find(|s| s.active);
    let mut s = String::new();
    s.push_str("# 本文件由 AgileNet 自动生成，手动修改将在下次启动时被覆盖\n");
    s.push_str(&format!("mixed-port: {MIHOMO_MIXED_PORT}\n"));
    s.push_str("allow-lan: false\n");
    s.push_str(&format!(
        "external-controller: 127.0.0.1:{MIHOMO_CTRL_PORT}\n"
    ));
    s.push_str(&format!("secret: \"{}\"\n", yaml_escape(&store.secret)));
    s.push_str("log-level: warning\n");
    s.push_str(&format!("mode: {mode}\n"));
    s.push_str("unified-delay: true\n");
    push_provider_section(&mut s, active);
    s.push_str("proxy-groups:\n");
    s.push_str("  - name: AGILE-SUB\n");
    s.push_str("    type: select\n");
    if active.is_some() {
        s.push_str("    use:\n");
        s.push_str("      - main\n");
    }
    s.push_str("rules:\n");
    s.push_str("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n");
    s.push_str("  - MATCH,AGILE-SUB\n");
    s
}

/// proxy-providers section (shared by both modes; kept because proxy-page latency tests/switching still go through the control plane, decoupled from the data plane).
/// Locally imported subscriptions (url with a file:// prefix) use type: file referencing the on-disk YAML, not fetched over URL.
fn push_provider_section(s: &mut String, active: Option<&Subscription>) {
    if let Some(sub) = active {
        s.push_str("proxy-providers:\n");
        s.push_str("  main:\n");
        if let Some(path) = sub.url.strip_prefix("file://") {
            s.push_str("    type: file\n");
            s.push_str(&format!("    path: \"{}\"\n", yaml_escape(path)));
        } else {
            s.push_str("    type: http\n");
            s.push_str(&format!("    url: \"{}\"\n", yaml_escape(&sub.url)));
            s.push_str("    interval: 86400\n");
            s.push_str("    proxy: DIRECT\n");
        }
        s.push_str("    health-check:\n");
        s.push_str("      enable: true\n");
        s.push_str("      url: http://www.gstatic.com/generate_204\n");
        s.push_str("      interval: 600\n");
    }
}

/// TUN mode config skeleton (tun.md §2.3; the full-rewrite principle still applies):
/// no mixed-port (57892 disabled — the key to loop prevention); TUN captures all traffic, fake-ip preserves domain names,
/// and all TCP is handed to the anet router via ANET-IN (socks5 127.0.0.1:57890) for routing.
/// anet stays in front with no subscription configured: the AGILE-SUB group falls back to a DIRECT member, so the
/// skeleton is valid (and usable for pure delegated-tunnel scenarios) with zero subscriptions.
/// Process-level loop prevention: anet-gui.exe's own raw dials (Direct decisions, tunnel transport to relay entries)
/// would be re-captured by auto-route and loop back into ANET-IN; the PROCESS-NAME rule makes them exit directly via
/// mihomo (auto-detect-interface binds the physical NIC, no re-capture). Relay entry hosts ride the subscription group
/// via per-host carriage rules rendered ahead of the process rule (keeps the "anet in front, FlClash behind" semantics).
/// Standing decision: TUN config does not go through the override script chain — scripts act on subscription proxy config semantics,
/// so this skeleton's loop-prevention constraints (no mixed-port / ANET-IN outbound / MATCH target) must stay intact.
fn render_config_tun(store: &SubStore, relay_hosts: &[String]) -> String {
    let active = store.subscriptions.iter().find(|s| s.active);
    let mut s = String::new();
    s.push_str("# 本文件由 AgileNet 自动生成，手动修改将在下次启动时被覆盖（TUN 模式）\n");
    // Loop-prevention key: no mixed-port (57892 disabled), otherwise a 57890→57892→MATCH→57890 dead loop (§2.5)
    s.push_str(&format!(
        "external-controller: 127.0.0.1:{MIHOMO_CTRL_PORT}\n"
    ));
    s.push_str(&format!("secret: \"{}\"\n", yaml_escape(&store.secret)));
    s.push_str("log-level: warning\n");
    // Process lookup runs only because a PROCESS-NAME rule exists (strict = zero overhead otherwise)
    s.push_str("find-process-mode: strict\n");
    // Subscription egress (P1.5): socks inbound serves as anet's fallback, direct to AGILE-SUB via the IN-TYPE rule below;
    // without FlClash, traffic missed under TUN can still exit via subscription nodes (mihomo's own outbound is not captured by TUN)
    s.push_str(&format!("socks-port: {MIHOMO_SOCKS_PORT}\n"));
    s.push_str("tun:\n");
    s.push_str("  enable: true\n");
    s.push_str("  stack: mixed              # TCP 系统栈 / UDP gVisor；异常时降级 gvisor\n");
    s.push_str("  auto-route: true\n");
    s.push_str("  auto-detect-interface: true\n");
    s.push_str("  dns-hijack:\n");
    s.push_str("    - any:53\n");
    s.push_str("dns:\n");
    // fake-ip preserves domain names: SOCKS5 CONNECT reaches 57890 with the domain intact, so AgileNet domain rules can match
    s.push_str("  enable: true\n");
    s.push_str("  enhanced-mode: fake-ip\n");
    s.push_str("  fake-ip-range: 198.18.0.1/16\n");
    s.push_str("  nameserver:\n");
    s.push_str("    - 223.5.5.5\n");
    s.push_str("    - 119.29.29.29\n");
    s.push_str("proxies:\n");
    s.push_str("  - name: ANET-IN\n");
    s.push_str("    type: socks5\n");
    s.push_str("    server: 127.0.0.1\n");
    s.push_str("    port: 57890             # 唯一允许出现 57890 的位置（出站形式）\n");
    push_provider_section(&mut s, active);
    s.push_str("proxy-groups:\n");
    s.push_str("  - name: AGILE-SUB\n");
    s.push_str("    type: select\n");
    if active.is_some() {
        s.push_str("    use:\n");
        s.push_str("      - main\n");
    } else {
        // No active subscription (pure delegated-tunnel TUN): a DIRECT member keeps the group valid
        s.push_str("    proxies:\n");
        s.push_str("      - DIRECT\n");
    }
    s.push_str("rules:\n");
    s.push_str("  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT   # 压制 QUIC：anet 入站不支持 UDP，强制回退 TCP\n");
    s.push_str("  - NETWORK,UDP,DIRECT                          # 其余 UDP（STUN 等）直连，P1 不接管\n");
    s.push_str("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n");
    // Tunnel-transport carriage: the GUI's raw dials to relay entries keep riding the subscription
    // group (rendered ahead of the process-level DIRECT rule; fake-ip maps captured dials back to domains)
    for host in relay_hosts {
        match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => {
                s.push_str(&format!("  - IP-CIDR,{host}/32,AGILE-SUB,no-resolve\n"))
            }
            Ok(std::net::IpAddr::V6(_)) => {
                s.push_str(&format!("  - IP-CIDR6,{host}/128,AGILE-SUB,no-resolve\n"))
            }
            Err(_) => s.push_str(&format!("  - DOMAIN,{host},AGILE-SUB\n")),
        }
    }
    // Process-level loop prevention: anet-gui's own raw dials (Direct decisions, tunnel transport)
    // must never re-enter ANET-IN — mihomo dials them directly, bound to the physical interface
    s.push_str("  - PROCESS-NAME,anet-gui.exe,DIRECT\n");
    s.push_str("  - IN-TYPE,socks,AGILE-SUB                   # anet 回落（socks 入站）直达订阅出口\n");
    s.push_str("  - MATCH,ANET-IN                               # 全部 TCP 转交 anet 路由器\n");
    s
}

/// Loop-prevention static check (§2.5 hard constraints): runs after config generation and before writing to disk; any violation refuses to start the kernel.
/// TUN config: must not contain mixed-port; 57892 is forbidden; 57890 may appear exactly once, as a proxies outbound;
/// rules must end with MATCH→ANET-IN (never point back to 57892).
/// Non-TUN config: keeps the original assertion (referencing local proxy 57890 is forbidden; mixed-port 57892 is the kernel's own inbound, which is legal).
/// The secret line is random hex and may coincidentally hit a port-number string, so it is excluded from the check.
pub(crate) fn check_no_loop(cfg: &str, tun: bool) -> Result<(), String> {
    let body: Vec<&str> = cfg
        .lines()
        .filter(|l| !l.starts_with("secret:"))
        .collect();
    let hit = |needle: &str| body.iter().filter(|l| l.contains(needle)).count();
    if tun {
        if hit("mixed-port") > 0 {
            return Err("TUN 配置严禁含 mixed-port（57892 与 57890 互指会成死环）".into());
        }
        if hit("57892") > 0 {
            return Err("TUN 配置严禁引用 57892（防环）".into());
        }
        let n = hit("57890");
        if n != 1 || !body.iter().any(|l| l.trim().starts_with("port: 57890")) {
            return Err("TUN 配置中 57890 须且仅须出现在 ANET-IN proxies 出站".into());
        }
        if hit("  - MATCH,ANET-IN") != 1 {
            return Err("TUN 配置 rules 必须以 MATCH,ANET-IN 收尾".into());
        }
        // P1.5 subscription egress: the socks inbound and the IN-TYPE rule must each appear exactly once
        if hit("57893") != 1 || !body.iter().any(|l| l.starts_with("socks-port: 57893")) {
            return Err("TUN 配置须含且仅含 socks-port: 57893（订阅出口入站）".into());
        }
        if hit("  - IN-TYPE,socks,AGILE-SUB") != 1 {
            return Err("TUN 配置 rules 须含 IN-TYPE,socks,AGILE-SUB（订阅出口规则）".into());
        }
        // Process-level loop prevention: the GUI's raw dials must exit directly, never re-enter ANET-IN
        if hit("  - PROCESS-NAME,anet-gui.exe,DIRECT") != 1 {
            return Err("TUN 配置 rules 须含且仅含 PROCESS-NAME,anet-gui.exe,DIRECT（进程级防环）".into());
        }
    } else if hit("57890") > 0 {
        return Err("配置不得引用本地代理端口 57890（防环）".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_render_basic() {
        let mut store = SubStore {
            secret: "s3cret".into(),
            ..Default::default()
        };
        let mk = |id: &str, name: &str, url: &str, active: bool| Subscription {
            id: id.into(),
            name: name.into(),
            url: url.into(),
            active,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        };
        store
            .subscriptions
            .push(mk("a", "机场A", "https://example.com/sub?token=abc", true));
        store
            .subscriptions
            .push(mk("b", "机场B", "https://b.example.com/link", false));
        let cfg = render_config(&store, "rule", false, &[]);
        assert!(cfg.contains("mixed-port: 57892"));
        assert!(cfg.contains("external-controller: 127.0.0.1:59292"));
        assert!(cfg.contains("secret: \"s3cret\""));
        // Only the active subscription is loaded (single provider always named main)
        assert!(cfg.contains("  main:\n"));
        assert!(cfg.contains("url: \"https://example.com/sub?token=abc\""));
        assert!(!cfg.contains("b.example.com"));
        assert!(cfg.contains("      - main\n"));
        assert!(cfg.contains("  - MATCH,AGILE-SUB\n"));
        assert!(cfg.contains("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"));
        assert!(check_no_loop(&cfg, false).is_ok());
    }

    #[test]
    fn config_escapes_quotes() {
        let mut store = SubStore {
            secret: "s".into(),
            ..Default::default()
        };
        store.subscriptions.push(Subscription {
            id: "a".into(),
            name: "x".into(),
            url: "https://evil.com/\"injected".into(),
            active: true,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        });
        let cfg = render_config(&store, "rule", false, &[]);
        assert!(cfg.contains("\\\"injected"));
    }

    #[test]
    fn config_render_local_file_provider() {
        // Locally imported subscription (file:// prefix) renders as type: file + path, not fetched over URL
        let mut store = SubStore {
            secret: "s".into(),
            ..Default::default()
        };
        store.subscriptions.push(Subscription {
            id: "a".into(),
            name: "本地".into(),
            url: "file://C:/Users/x/local-a.yaml".into(),
            active: true,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        });
        let cfg = render_config(&store, "rule", false, &[]);
        assert!(cfg.contains("    type: file\n"));
        assert!(cfg.contains("    path: \"C:/Users/x/local-a.yaml\"\n"));
        assert!(!cfg.contains("type: http"));
        assert!(!cfg.contains("interval: 86400"));
        assert!(check_no_loop(&cfg, false).is_ok());
        // The TUN skeleton supports this too
        let cfg = render_config(&store, "rule", true, &[]);
        assert!(cfg.contains("    type: file\n"));
        assert!(check_no_loop(&cfg, true).is_ok());
    }

    #[test]
    fn config_render_mode_three_states() {
        let store = SubStore::default();
        for (mode, expect) in [
            ("rule", "mode: rule\n"),
            ("global", "mode: global\n"),
            ("direct", "mode: direct\n"),
        ] {
            assert!(render_config(&store, mode, false, &[]).contains(expect), "mode={mode}");
        }
        // Invalid values fall back to rule
        assert!(render_config(&store, "bogus", false, &[]).contains("mode: rule\n"));
    }

    /// TUN mode config snapshot (tun.md §2.3 skeleton, field by field) + loop-prevention check passes
    #[test]
    fn config_render_tun_snapshot() {
        let mut store = SubStore {
            secret: "s3cret".into(),
            ..Default::default()
        };
        store.subscriptions.push(Subscription {
            id: "a".into(),
            name: "机场A".into(),
            url: "https://example.com/sub?token=abc".into(),
            active: true,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        });
        let cfg = render_config(&store, "rule", true, &[]);
        // Skeleton header: no mixed-port (loop-prevention key), control plane kept
        assert!(!cfg.contains("mixed-port"));
        assert!(cfg.contains("external-controller: 127.0.0.1:59292"));
        assert!(cfg.contains("secret: \"s3cret\""));
        // tun section: enable / stack mixed / auto-route / auto-detect-interface / dns-hijack
        assert!(cfg.contains("tun:\n  enable: true\n"));
        assert!(cfg.contains("  stack: mixed"));
        assert!(cfg.contains("  auto-route: true\n"));
        assert!(cfg.contains("  auto-detect-interface: true\n"));
        assert!(cfg.contains("    - any:53\n"));
        // dns section: fake-ip preserves domain names
        assert!(cfg.contains("  enhanced-mode: fake-ip\n"));
        assert!(cfg.contains("  fake-ip-range: 198.18.0.1/16\n"));
        assert!(cfg.contains("    - 223.5.5.5\n"));
        // ANET-IN socks5 → 57890 (all TCP handed to the anet router)
        assert!(cfg.contains("  - name: ANET-IN\n    type: socks5\n    server: 127.0.0.1\n"));
        assert!(cfg.contains("    port: 57890"));
        // P1.5 subscription egress: socks inbound 57893 + IN-TYPE rule direct to AGILE-SUB
        assert!(cfg.contains("socks-port: 57893\n"));
        assert!(cfg.contains("  - IN-TYPE,socks,AGILE-SUB"));
        // proxy-providers kept (proxy-page latency tests/switching still go through the control plane)
        assert!(cfg.contains("proxy-providers:\n  main:\n"));
        assert!(cfg.contains("url: \"https://example.com/sub?token=abc\""));
        assert!(cfg.contains("  - name: AGILE-SUB\n    type: select\n    use:\n      - main\n"));
        // Process lookup only when process rules exist; GUI raw dials exit directly (loop prevention)
        assert!(cfg.contains("find-process-mode: strict\n"));
        // rules: QUIC suppression + UDP DIRECT + loopback direct + process-level DIRECT + MATCH→ANET-IN
        assert!(cfg.contains("  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
        assert!(cfg.contains("  - NETWORK,UDP,DIRECT"));
        assert!(cfg.contains("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n"));
        assert!(cfg.contains("  - PROCESS-NAME,anet-gui.exe,DIRECT\n"));
        assert!(cfg.contains("  - MATCH,ANET-IN"));
        assert!(check_no_loop(&cfg, true).is_ok(), "TUN 骨架须过防环检查");
    }

    /// Pure delegated-tunnel TUN (no subscription at all): the group carries a DIRECT member so the
    /// skeleton stays valid, and the loop-prevention check still passes
    #[test]
    fn config_render_tun_without_subscription() {
        let store = SubStore {
            secret: "s3cret".into(),
            ..Default::default()
        };
        let cfg = render_config(&store, "rule", true, &[]);
        assert!(!cfg.contains("proxy-providers:"));
        assert!(cfg.contains("  - name: AGILE-SUB\n    type: select\n    proxies:\n      - DIRECT\n"));
        assert!(cfg.contains("  - PROCESS-NAME,anet-gui.exe,DIRECT\n"));
        assert!(check_no_loop(&cfg, true).is_ok(), "无订阅 TUN 骨架须过防环检查");
    }

    /// Relay carriage rules: domains render as DOMAIN→AGILE-SUB, IP literals as host CIDRs; they must
    /// sit ahead of the process-level DIRECT rule so tunnel transport keeps riding the subscription
    #[test]
    fn config_render_tun_relay_carriage() {
        let store = SubStore {
            secret: "s".into(),
            ..Default::default()
        };
        let hosts = vec![
            "relay.example.com".to_string(),
            "203.0.113.7".to_string(),
            "2001:db8::1".to_string(),
        ];
        let cfg = render_config(&store, "rule", true, &hosts);
        assert!(cfg.contains("  - DOMAIN,relay.example.com,AGILE-SUB\n"));
        assert!(cfg.contains("  - IP-CIDR,203.0.113.7/32,AGILE-SUB,no-resolve\n"));
        assert!(cfg.contains("  - IP-CIDR6,2001:db8::1/128,AGILE-SUB,no-resolve\n"));
        let carriage = cfg.find("DOMAIN,relay.example.com").unwrap();
        let proc_rule = cfg.find("PROCESS-NAME,anet-gui.exe").unwrap();
        assert!(carriage < proc_rule, "搭车规则须排在进程级直连之前");
        assert!(check_no_loop(&cfg, true).is_ok());
    }

    /// Full coverage of the loop-prevention static check (each tun.md §2.5 clause)
    #[test]
    fn check_no_loop_covers_all_clauses() {
        let store = SubStore {
            secret: "s".into(),
            ..Default::default()
        };
        let tun_cfg = render_config(&store, "rule", true, &[]);
        let base_cfg = render_config(&store, "rule", false, &[]);
        assert!(check_no_loop(&tun_cfg, true).is_ok());
        assert!(check_no_loop(&base_cfg, false).is_ok());

        // TUN: contains mixed-port → reject
        let bad = tun_cfg.replace("tun:\n", "mixed-port: 57892\ntun:\n");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN: 57892 appears (rules point back to it) → reject
        let bad = tun_cfg.replace("  - MATCH,ANET-IN", "  - MATCH,ANET-IN\n  - DST-PORT,57892,DIRECT");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN: 57890 appears twice (rules point back to the local proxy) → reject
        let bad = tun_cfg.replace(
            "  - MATCH,ANET-IN",
            "  - IP-CIDR,127.0.0.1/32,DIRECT # 57890\n  - MATCH,ANET-IN",
        );
        assert!(check_no_loop(&bad, true).is_err());
        // TUN: 57890 not on the proxies outbound line (moved into a comment) → reject
        let bad = tun_cfg.replace("    port: 57890", "    port: 15789 # 57890");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN: missing MATCH,ANET-IN → reject
        let bad = tun_cfg.replace("  - MATCH,ANET-IN", "  - MATCH,AGILE-SUB");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN: missing process-level DIRECT rule → reject
        let bad = tun_cfg.replace("  - PROCESS-NAME,anet-gui.exe,DIRECT\n", "");
        assert!(check_no_loop(&bad, true).is_err());
        // Non-TUN: referencing 57890 → reject; mixed-port 57892 is the kernel's own inbound (legal, keep the original assertion)
        let bad = base_cfg.replace("  - MATCH,AGILE-SUB", "  - MATCH,AGILE-SUB # 57890");
        assert!(check_no_loop(&bad, false).is_err());
        assert!(base_cfg.contains("mixed-port: 57892"));
        assert!(check_no_loop(&base_cfg, false).is_ok());
        // A secret line whose random hex coincidentally hits a port string must not be flagged
        let store = SubStore {
            secret: "57890abcdef".into(),
            ..Default::default()
        };
        let cfg = render_config(&store, "rule", false, &[]);
        assert!(check_no_loop(&cfg, false).is_ok(), "secret 行不参与检查");
        let cfg = render_config(&store, "rule", true, &[]);
        assert!(check_no_loop(&cfg, true).is_ok(), "secret 行不参与检查");
    }
}
