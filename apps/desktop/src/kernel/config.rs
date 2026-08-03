//! 从 subscription.rs 拆分：配置生成与防环（纯搬运，零逻辑变更）

use crate::roles;

use super::store::{SubStore, Subscription};

/// mixed 入站（避让 Clash 7890 系、本地代理 57890 与常见占用 57891）
pub const MIHOMO_MIXED_PORT: u16 = 57892;
/// TUN 模式：mihomo socks 入站（anet 未命中流量的回落点，经 IN-TYPE 规则直达订阅出口）
pub const MIHOMO_SOCKS_PORT: u16 = 57893;
/// external-controller（避让 9090）
pub const MIHOMO_CTRL_PORT: u16 = 59292;

// ==================== 配置生成（全量重写，严禁手改） ====================

fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 由订阅清单生成 mihomo config.yaml（仅加载当前激活订阅，单 provider 恒名 main）。
/// mode 为出站模式（rule|global|direct，非法值回落 rule）；tun=true 走 TUN 骨架（§2.3）。
pub fn render_config(store: &SubStore, mode: &str, tun: bool) -> String {
    if tun {
        return render_config_tun(store);
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

/// proxy-providers 段（两种模式共用；保留：代理页测速/切换仍走控制面，与数据面解耦）。
/// 本地导入订阅（url 为 file:// 前缀）走 type: file 引用落盘 YAML，不经 URL 拉取。
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

/// TUN 模式配置骨架（tun.md §2.3，全量重写原则不变）：
/// 无 mixed-port（关闭 57892，防环关键）；TUN 捕获全部流量，fake-ip 保域名，
/// 全部 TCP 经 ANET-IN（socks5 127.0.0.1:57890）转交 anet 路由器分流。
/// 既定决策：TUN 配置不经过覆写脚本链——脚本作用于订阅代理配置语义，
/// 本骨架的防环约束（无 mixed-port / ANET-IN 出站 / MATCH 指向）必须完整保留。
fn render_config_tun(store: &SubStore) -> String {
    let active = store.subscriptions.iter().find(|s| s.active);
    let mut s = String::new();
    s.push_str("# 本文件由 AgileNet 自动生成，手动修改将在下次启动时被覆盖（TUN 模式）\n");
    // 防环关键：严禁 mixed-port（57892 关闭），否则 57890→57892→MATCH→57890 死环（§2.5）
    s.push_str(&format!(
        "external-controller: 127.0.0.1:{MIHOMO_CTRL_PORT}\n"
    ));
    s.push_str(&format!("secret: \"{}\"\n", yaml_escape(&store.secret)));
    s.push_str("log-level: warning\n");
    // 订阅出口（P1.5）：socks 入站给 anet 回落用，经下方 IN-TYPE 规则直达 AGILE-SUB；
    // 无 FlClash 时 TUN 下未命中流量也能经订阅节点出网（mihomo 自身出站不被 TUN 捕获）
    s.push_str(&format!("socks-port: {MIHOMO_SOCKS_PORT}\n"));
    s.push_str("tun:\n");
    s.push_str("  enable: true\n");
    s.push_str("  stack: mixed              # TCP 系统栈 / UDP gVisor；异常时降级 gvisor\n");
    s.push_str("  auto-route: true\n");
    s.push_str("  auto-detect-interface: true\n");
    s.push_str("  dns-hijack:\n");
    s.push_str("    - any:53\n");
    s.push_str("dns:\n");
    // fake-ip 保域名：SOCKS5 CONNECT 以域名形式到达 57890，AgileNet 域名规则方可匹配
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
    }
    s.push_str("rules:\n");
    s.push_str("  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT   # 压制 QUIC：anet 入站不支持 UDP，强制回退 TCP\n");
    s.push_str("  - NETWORK,UDP,DIRECT                          # 其余 UDP（STUN 等）直连，P1 不接管\n");
    s.push_str("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n");
    s.push_str("  - IN-TYPE,socks,AGILE-SUB                   # anet 回落（socks 入站）直达订阅出口\n");
    s.push_str("  - MATCH,ANET-IN                               # 全部 TCP 转交 anet 路由器\n");
    s
}

/// 防环静态检查（§2.5 硬约束）：配置生成后、落盘前执行，违规即拒绝启动内核。
/// TUN 配置：不得含 mixed-port；57892 严禁出现；57890 仅以 proxies 出站形式出现一次；
/// rules 必须 MATCH→ANET-IN（严禁回指 57892）。
/// 非 TUN 配置：维持原断言（严禁引用本地代理 57890；mixed-port 57892 是内核自身入站，合法）。
/// secret 行为随机十六进制，可能巧合命中端口数字串，不参与检查。
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
        // P1.5 订阅出口：socks 入站与 IN-TYPE 规则必须各出现且仅出现一次
        if hit("57893") != 1 || !body.iter().any(|l| l.starts_with("socks-port: 57893")) {
            return Err("TUN 配置须含且仅含 socks-port: 57893（订阅出口入站）".into());
        }
        if hit("  - IN-TYPE,socks,AGILE-SUB") != 1 {
            return Err("TUN 配置 rules 须含 IN-TYPE,socks,AGILE-SUB（订阅出口规则）".into());
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
        let cfg = render_config(&store, "rule", false);
        assert!(cfg.contains("mixed-port: 57892"));
        assert!(cfg.contains("external-controller: 127.0.0.1:59292"));
        assert!(cfg.contains("secret: \"s3cret\""));
        // 仅加载激活订阅（单 provider 恒名 main）
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
        let cfg = render_config(&store, "rule", false);
        assert!(cfg.contains("\\\"injected"));
    }

    #[test]
    fn config_render_local_file_provider() {
        // 本地导入订阅（file:// 前缀）渲染为 type: file + path，不经 URL 拉取
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
        let cfg = render_config(&store, "rule", false);
        assert!(cfg.contains("    type: file\n"));
        assert!(cfg.contains("    path: \"C:/Users/x/local-a.yaml\"\n"));
        assert!(!cfg.contains("type: http"));
        assert!(!cfg.contains("interval: 86400"));
        assert!(check_no_loop(&cfg, false).is_ok());
        // TUN 骨架同样支持
        let cfg = render_config(&store, "rule", true);
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
            assert!(render_config(&store, mode, false).contains(expect), "mode={mode}");
        }
        // 非法值回落 rule
        assert!(render_config(&store, "bogus", false).contains("mode: rule\n"));
    }

    /// TUN 模式配置快照（tun.md §2.3 骨架逐字段）+ 防环检查通过
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
        let cfg = render_config(&store, "rule", true);
        // 骨架头部：无 mixed-port（防环关键），控制面保留
        assert!(!cfg.contains("mixed-port"));
        assert!(cfg.contains("external-controller: 127.0.0.1:59292"));
        assert!(cfg.contains("secret: \"s3cret\""));
        // tun 段：enable / stack mixed / auto-route / auto-detect-interface / dns-hijack
        assert!(cfg.contains("tun:\n  enable: true\n"));
        assert!(cfg.contains("  stack: mixed"));
        assert!(cfg.contains("  auto-route: true\n"));
        assert!(cfg.contains("  auto-detect-interface: true\n"));
        assert!(cfg.contains("    - any:53\n"));
        // dns 段：fake-ip 保域名
        assert!(cfg.contains("  enhanced-mode: fake-ip\n"));
        assert!(cfg.contains("  fake-ip-range: 198.18.0.1/16\n"));
        assert!(cfg.contains("    - 223.5.5.5\n"));
        // ANET-IN socks5 → 57890（全量 TCP 转交 anet 路由器）
        assert!(cfg.contains("  - name: ANET-IN\n    type: socks5\n    server: 127.0.0.1\n"));
        assert!(cfg.contains("    port: 57890"));
        // P1.5 订阅出口：socks 入站 57893 + IN-TYPE 规则直达 AGILE-SUB
        assert!(cfg.contains("socks-port: 57893\n"));
        assert!(cfg.contains("  - IN-TYPE,socks,AGILE-SUB"));
        // proxy-providers 保留（代理页测速/切换仍走控制面）
        assert!(cfg.contains("proxy-providers:\n  main:\n"));
        assert!(cfg.contains("url: \"https://example.com/sub?token=abc\""));
        assert!(cfg.contains("  - name: AGILE-SUB\n    type: select\n    use:\n      - main\n"));
        // rules：QUIC 压制 + UDP DIRECT + 回环直连 + MATCH→ANET-IN
        assert!(cfg.contains("  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
        assert!(cfg.contains("  - NETWORK,UDP,DIRECT"));
        assert!(cfg.contains("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n"));
        assert!(cfg.contains("  - MATCH,ANET-IN"));
        assert!(check_no_loop(&cfg, true).is_ok(), "TUN 骨架须过防环检查");
    }

    /// 防环静态检查全覆盖（tun.md §2.5 各条）
    #[test]
    fn check_no_loop_covers_all_clauses() {
        let store = SubStore {
            secret: "s".into(),
            ..Default::default()
        };
        let tun_cfg = render_config(&store, "rule", true);
        let base_cfg = render_config(&store, "rule", false);
        assert!(check_no_loop(&tun_cfg, true).is_ok());
        assert!(check_no_loop(&base_cfg, false).is_ok());

        // TUN：含 mixed-port → 拒绝
        let bad = tun_cfg.replace("tun:\n", "mixed-port: 57892\ntun:\n");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：57892 出现（rules 回指）→ 拒绝
        let bad = tun_cfg.replace("  - MATCH,ANET-IN", "  - MATCH,ANET-IN\n  - DST-PORT,57892,DIRECT");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：57890 重复出现（rules 回指本地代理）→ 拒绝
        let bad = tun_cfg.replace(
            "  - MATCH,ANET-IN",
            "  - IP-CIDR,127.0.0.1/32,DIRECT # 57890\n  - MATCH,ANET-IN",
        );
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：57890 不在 proxies 出站行（被挪到注释里）→ 拒绝
        let bad = tun_cfg.replace("    port: 57890", "    port: 15789 # 57890");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：缺 MATCH,ANET-IN → 拒绝
        let bad = tun_cfg.replace("  - MATCH,ANET-IN", "  - MATCH,AGILE-SUB");
        assert!(check_no_loop(&bad, true).is_err());
        // 非 TUN：引用 57890 → 拒绝；mixed-port 57892 是内核自身入站（合法，维持原断言）
        let bad = base_cfg.replace("  - MATCH,AGILE-SUB", "  - MATCH,AGILE-SUB # 57890");
        assert!(check_no_loop(&bad, false).is_err());
        assert!(base_cfg.contains("mixed-port: 57892"));
        assert!(check_no_loop(&base_cfg, false).is_ok());
        // secret 行随机十六进制巧合命中端口串不误伤
        let store = SubStore {
            secret: "57890abcdef".into(),
            ..Default::default()
        };
        let cfg = render_config(&store, "rule", false);
        assert!(check_no_loop(&cfg, false).is_ok(), "secret 行不参与检查");
        let cfg = render_config(&store, "rule", true);
        assert!(check_no_loop(&cfg, true).is_ok(), "secret 行不参与检查");
    }
}
