//! doctor — 自我诊断引擎（`anet doctor` 与 anet-gui「自我诊断」按钮共用）。
//!
//! 契约要点：
//! - [`run`] 返回结构化 [`DoctorReport`]（serde Serialize 即 GUI 契约，字段名不得改动），
//!   [`render`] 负责人类可读渲染（分节 + 状态标记 + 建议 + 汇总行）；
//! - 能安全自动修复的问题直接修并标 `fixed`：孤儿 mihomo、残留系统代理、损坏的 GUI
//!   配置文件（备份后重置）、非法自定义规则、系统 hosts 托管块漂移、损坏的 wintun/内核文件；
//! - 退出码语义由调用方决定：[`exit_code`] —— 有 `err` 项 → 1，否则 0（warn/info 不影响）；
//! - 本机操作：不走会话校验、不写审计日志；节点数据库仅以只读方式打开（CIDR 冲突检查）。
//!
//! 检查各节按域拆分子模块（ports/sysproxy/tun/kernel/network/config/rules），
//! 报告模型在 model、跨节小工具在 util；本入口只留编排、渲染与对外 pub API。

mod config;
mod kernel;
mod model;
mod network;
mod ports;
mod rules;
mod sysproxy;
mod tun;
mod util;

pub use model::{
    DoctorContext, DoctorItem, DoctorReport, DoctorSection, DoctorStatus, DoctorSummary,
};
// wintun.dll 钉值对外导出：anet-gui wintun 下发与本节校验共用同一来源
pub use tun::WINTUN_DLL_SHA256;

use std::time::Instant;

use super::netstat;

// ==================== 入口 ====================

/// 检查节计划（id, 标题），顺序即执行顺序；GUI 据此在诊断开始时预渲染骨架占位。
pub const SECTION_PLAN: [(&str, &str); 7] = [
    ("ports", "端口与占用"),
    ("sysproxy", "系统代理"),
    ("tun", "TUN 支持"),
    ("kernel", "订阅内核"),
    ("network", "网络连通"),
    ("config", "配置与数据"),
    ("rules", "规则冲突"),
];

/// 执行全部检查并生成报告（检查项失败只落到对应 item，绝不 panic/中断整体）。
pub async fn run(ctx: DoctorContext) -> DoctorReport {
    run_streaming(ctx, |_| {}).await
}

/// 同 [`run`]，但每完成一节即回调（GUI 流式渲染：逐节到达逐节上屏）。
pub async fn run_streaming(
    ctx: DoctorContext,
    on_section: impl Fn(&DoctorSection),
) -> DoctorReport {
    let start = Instant::now();
    // socket 枚举一次，ports/sysproxy/kernel 三节共享（失败时 ports 节报 err，其余按无监听处理）
    let socks_result = netstat::sockets();
    let enum_failed = socks_result.is_err();
    let socks = socks_result.unwrap_or_default();

    let mut sections = Vec::with_capacity(SECTION_PLAN.len());
    let mut push = |sec: DoctorSection| {
        on_section(&sec);
        sections.push(sec);
    };
    push(ports::section_ports(&ctx, &socks, enum_failed));
    push(sysproxy::section_sysproxy(&ctx, &socks));
    push(tun::section_tun(&ctx));
    push(kernel::section_kernel(&ctx, &socks).await);
    push(network::section_network().await);
    push(config::section_config(&ctx));
    push(rules::section_rules(&ctx));
    let summary = summarize(&sections);
    DoctorReport {
        sections,
        summary,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// 退出码：有 err → 1，否则 0（warn/info 不影响）。
pub fn exit_code(report: &DoctorReport) -> i32 {
    if report.summary.err > 0 { 1 } else { 0 }
}

fn summarize(sections: &[DoctorSection]) -> DoctorSummary {
    let mut s = DoctorSummary::default();
    for sec in sections {
        for it in &sec.items {
            match it.status {
                DoctorStatus::Ok => s.ok += 1,
                DoctorStatus::Warn => s.warn += 1,
                DoctorStatus::Err => s.err += 1,
                DoctorStatus::Fixed => s.fixed += 1,
                DoctorStatus::Info => {}
            }
        }
    }
    s
}

fn item(
    id: impl Into<String>,
    label: impl Into<String>,
    status: DoctorStatus,
    detail: impl Into<String>,
    suggestion: Option<String>,
) -> DoctorItem {
    DoctorItem {
        id: id.into(),
        label: label.into(),
        status,
        detail: detail.into(),
        suggestion,
    }
}

fn section(id: &str, title: &str, items: Vec<DoctorItem>) -> DoctorSection {
    DoctorSection {
        id: id.into(),
        title: title.into(),
        items,
    }
}

/// 人类可读渲染（cli 无着色体系，沿用 [标记] 文本风格）。
pub fn render(report: &DoctorReport) -> String {
    let mut out = String::from("AgileNet 自我诊断报告");
    for sec in &report.sections {
        out.push_str(&format!("\n\n■ {}", sec.title));
        for it in &sec.items {
            out.push_str(&format!(
                "\n  {} {}：{}",
                tag(it.status),
                it.label,
                it.detail
            ));
            if let Some(s) = &it.suggestion {
                out.push_str(&format!("\n      建议：{s}"));
            }
        }
    }
    let s = &report.summary;
    out.push_str(&format!(
        "\n\n汇总：通过 {} · 警告 {} · 错误 {} · 已修复 {}（耗时 {}ms）",
        s.ok, s.warn, s.err, s.fixed, report.duration_ms
    ));
    out
}

fn tag(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Ok => "[通过]",
        DoctorStatus::Info => "[提示]",
        DoctorStatus::Warn => "[警告]",
        DoctorStatus::Err => "[错误]",
        DoctorStatus::Fixed => "[修复]",
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::config::section_config;
    use super::ports::eval_port;
    use super::rules::{
        cidr_conflicts, duplicate_patterns, read_managed_block, rewrite_managed_block,
        sanitize_rules_file, section_rules, strip_managed_block,
    };
    use super::*;
    use crate::tool::netstat::SocketInfo;
    use serde_json::json;
    use std::path::{Path, PathBuf};

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anet-doctor-test-{}-{}",
            tag,
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_ctx(dir: &Path, fix: bool) -> DoctorContext {
        DoctorContext {
            gui: true,
            fix,
            data_dir: dir.to_path_buf(),
            db_path: None,
            managed_pids: Vec::new(),
        }
    }

    fn listen_socket(port: u16, pid: Option<u32>, process: Option<&str>) -> SocketInfo {
        SocketInfo {
            proto: "tcp".into(),
            local: format!("127.0.0.1:{port}"),
            remote: None,
            state: Some("LISTEN".into()),
            pid,
            process: process.map(|s| s.into()),
        }
    }

    // ---------- 契约与汇总 ----------

    #[test]
    fn status_serializes_lowercase_contract() {
        assert_eq!(serde_json::to_value(DoctorStatus::Ok).unwrap(), "ok");
        assert_eq!(serde_json::to_value(DoctorStatus::Info).unwrap(), "info");
        assert_eq!(serde_json::to_value(DoctorStatus::Warn).unwrap(), "warn");
        assert_eq!(serde_json::to_value(DoctorStatus::Err).unwrap(), "err");
        assert_eq!(serde_json::to_value(DoctorStatus::Fixed).unwrap(), "fixed");
    }

    #[test]
    fn report_json_shape_matches_contract() {
        let report = DoctorReport {
            sections: vec![section(
                "s",
                "节",
                vec![item("i", "l", DoctorStatus::Ok, "d", Some("sug".into()))],
            )],
            summary: DoctorSummary { ok: 1, warn: 0, err: 0, fixed: 0 },
            duration_ms: 5,
        };
        let v = serde_json::to_value(&report).unwrap();
        assert!(v["duration_ms"].is_u64());
        assert_eq!(v["summary"]["ok"], 1);
        let it = &v["sections"][0]["items"][0];
        assert_eq!(it["id"], "i");
        assert_eq!(it["label"], "l");
        assert_eq!(it["status"], "ok");
        assert_eq!(it["detail"], "d");
        assert_eq!(it["suggestion"], "sug");
        // suggestion 缺省序列化为 null（GUI 契约字段必须存在）
        let it2 = serde_json::to_value(item("a", "b", DoctorStatus::Info, "c", None)).unwrap();
        assert!(it2.get("suggestion").is_some());
        assert!(it2["suggestion"].is_null());
    }

    #[test]
    fn summary_counts_and_exit_code() {
        let report = DoctorReport {
            sections: vec![section(
                "s",
                "节",
                vec![
                    item("a", "x", DoctorStatus::Ok, "", None),
                    item("b", "x", DoctorStatus::Info, "", None),
                    item("c", "x", DoctorStatus::Warn, "", None),
                    item("d", "x", DoctorStatus::Err, "", None),
                    item("e", "x", DoctorStatus::Fixed, "", None),
                ],
            )],
            summary: DoctorSummary::default(),
            duration_ms: 0,
        };
        let s = summarize(&report.sections);
        assert_eq!((s.ok, s.warn, s.err, s.fixed), (1, 1, 1, 1));
        let mut r = report;
        r.summary = summarize(&r.sections);
        assert_eq!(exit_code(&r), 1);
        r.sections[0].items.retain(|i| i.status != DoctorStatus::Err);
        r.summary = summarize(&r.sections);
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn render_contains_sections_tags_and_suggestion() {
        let report = DoctorReport {
            sections: vec![section(
                "ports",
                "端口与占用",
                vec![
                    item("p1", "API :59090", DoctorStatus::Ok, "未监听（anet-svc 未运行）", None),
                    item(
                        "p2",
                        "Relay :54430",
                        DoctorStatus::Err,
                        "被 evil.exe (PID 9) 占用",
                        Some("结束占用进程".into()),
                    ),
                ],
            )],
            summary: DoctorSummary { ok: 1, warn: 0, err: 1, fixed: 0 },
            duration_ms: 7,
        };
        let text = render(&report);
        assert!(text.contains("■ 端口与占用"));
        assert!(text.contains("[通过] API :59090"));
        assert!(text.contains("[错误] Relay :54430"));
        assert!(text.contains("建议：结束占用进程"));
        assert!(text.contains("错误 1"));
        assert!(text.contains("耗时 7ms"));
    }

    // ---------- 端口评估 ----------

    #[test]
    fn eval_port_foreign_occupation_is_err() {
        let socks = [listen_socket(59090, Some(4242), Some("nginx.exe"))];
        let refs: Vec<&SocketInfo> = socks.iter().collect();
        let it = eval_port(59090, "API 管理面", &refs, false, "x");
        assert_eq!(it.status, DoctorStatus::Err);
        assert!(it.detail.contains("nginx.exe"));
        assert!(it.detail.contains("4242"));
        assert!(it.suggestion.as_deref().unwrap_or("").contains("killport"));
    }

    #[test]
    fn eval_port_our_process_is_ok() {
        for name in ["anet-svc.exe", "mihomo", "anet-gui.exe"] {
            let socks = [listen_socket(59292, Some(1), Some(name))];
            let refs: Vec<&SocketInfo> = socks.iter().collect();
            let it = eval_port(59292, "控制面", &refs, false, "x");
            assert_eq!(it.status, DoctorStatus::Ok, "{name} 应视为本家");
        }
    }

    #[test]
    fn eval_port_expected_missing_is_warn_otherwise_info() {
        let it = eval_port(57890, "本地代理", &[], true, "客户端角色已开启");
        assert_eq!(it.status, DoctorStatus::Warn);
        let it = eval_port(57890, "本地代理", &[], false, "客户端角色未开启");
        assert_eq!(it.status, DoctorStatus::Info);
        assert!(it.detail.contains("未监听"));
    }

    #[test]
    fn eval_port_hidden_pid_is_warn() {
        let socks = [listen_socket(59090, None, None)];
        let refs: Vec<&SocketInfo> = socks.iter().collect();
        let it = eval_port(59090, "API", &refs, false, "x");
        assert_eq!(it.status, DoctorStatus::Warn);
        assert!(it.detail.contains("无权限"));
    }

    // ---------- 规则检查 ----------

    #[test]
    fn duplicate_patterns_case_insensitive() {
        let v = json!({"bypass":[
            {"id":"a","pattern":"*.Baidu.com"},
            {"id":"b","pattern":"*.baidu.com"},
            {"id":"c","pattern":"foo.com"}
        ]});
        assert_eq!(duplicate_patterns(&v), vec!["*.baidu.com".to_string()]);
    }

    #[test]
    fn sanitize_removes_invalid_and_cascades_combo_keys() {
        let mut v = json!({
            "bypass":[
                {"id":"b1","pattern":"ok.com"},
                {"id":"b2","pattern":"bad pattern"},
                {"id":"b3","pattern":""}
            ],
            "hosts":[
                {"id":"h1","hostname":"git.internal","ip":"10.0.0.9"},
                {"id":"h2","hostname":"1.2.3.4","ip":"10.0.0.9"},
                {"id":"h3","hostname":"x.com","ip":"not-an-ip"}
            ],
            "combos":[{"id":"c1","name":"n","rule_keys":["b1","b2","h2"]}]
        });
        let removed = sanitize_rules_file(&mut v);
        assert_eq!(removed.len(), 4); // b2 空白 / b3 空串 / h2 主机名为 IP / h3 IP 不可解析
        let bypass = v["bypass"].as_array().unwrap();
        assert_eq!(bypass.len(), 1);
        assert_eq!(bypass[0]["pattern"], "ok.com");
        let hosts = v["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        // 组合中失效 id 被级联清理
        let keys = v["combos"][0]["rule_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "b1");
    }

    #[test]
    fn rules_section_fixes_invalid_entries_on_disk() {
        let dir = tmp_dir("rules");
        std::fs::write(
            dir.join("gui-custom-rules.json"),
            r#"{"bypass":[{"id":"b1","pattern":"ok.com"},{"id":"b2","pattern":"bad pattern"}],"hosts":[],"combos":[]}"#,
        )
        .unwrap();
        let sec = section_rules(&test_ctx(&dir, true));
        let fixed = sec.items.iter().find(|i| i.id == "custom-invalid").unwrap();
        assert_eq!(fixed.status, DoctorStatus::Fixed);
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("gui-custom-rules.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["bypass"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- hosts 托管块 ----------

    #[test]
    fn managed_block_roundtrip_and_strip() {
        let content = "127.0.0.1 localhost\n# AgileNet begin\n10.0.0.9 git.internal\n# AgileNet end\n";
        let entries = read_managed_block(content);
        assert_eq!(entries, vec![("git.internal".to_string(), "10.0.0.9".to_string())]);
        let stripped = strip_managed_block(content);
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }

    #[test]
    fn rewrite_managed_block_updates_file() {
        let dir = tmp_dir("hosts");
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n# AgileNet begin\n9.9.9.9 stale\n# AgileNet end\n").unwrap();
        rewrite_managed_block(&path, &[("a.internal".into(), "1.1.1.1".into())]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("1.1.1.1 a.internal"));
        assert!(!content.contains("stale"));
        assert!(content.contains("127.0.0.1 localhost"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- 配置文件修复 ----------

    #[test]
    fn config_section_backs_up_and_resets_corrupt_file() {
        let dir = tmp_dir("config");
        std::fs::write(dir.join("gui-settings.json"), "not json{{{").unwrap();
        let sec = section_config(&test_ctx(&dir, true));
        let it = sec
            .items
            .iter()
            .find(|i| i.id == "file-gui-settings.json")
            .unwrap();
        assert_eq!(it.status, DoctorStatus::Fixed);
        // 新文件可解析且为默认三字段
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("gui-settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["client"], true);
        // 备份存在
        let bak = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("gui-settings.json.bak-"));
        assert!(bak, "应生成 .bak-时间戳 备份");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_section_reports_corrupt_without_fix() {
        let dir = tmp_dir("config-nofix");
        std::fs::write(dir.join("subscriptions.json"), "{{bad").unwrap();
        let sec = section_config(&test_ctx(&dir, false));
        let it = sec
            .items
            .iter()
            .find(|i| i.id == "file-subscriptions.json")
            .unwrap();
        assert_eq!(it.status, DoctorStatus::Err);
        assert!(it.suggestion.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- CIDR 冲突 ----------

    #[test]
    fn cidr_conflicts_detects_containment_and_duplicates() {
        let values = vec![
            "10.0.0.0/8".to_string(),
            "10.12.0.0/16".to_string(),
            "192.168.0.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "2001:db8:1::/48".to_string(),
        ];
        let conflicts = cidr_conflicts(&values);
        assert!(conflicts.contains(&("10.0.0.0/8".into(), "10.12.0.0/16".into())));
        assert!(conflicts.contains(&("10.0.0.0/8".into(), "10.0.0.0/8".into())));
        assert!(conflicts.contains(&("2001:db8::/32".into(), "2001:db8:1::/48".into())));
        assert!(!conflicts.iter().any(|(a, b)| a == "192.168.0.0/24" || b == "192.168.0.0/24"));
    }

    #[test]
    fn cidr_conflicts_skips_unparseable() {
        let values = vec!["not-a-cidr".to_string(), "10.0.0.0/8".to_string()];
        assert!(cidr_conflicts(&values).is_empty());
    }

    // ---------- 端到端冒烟 ----------

    #[tokio::test]
    async fn run_produces_all_sections_and_consistent_summary() {
        let dir = tmp_dir("run");
        let report = run(test_ctx(&dir, false)).await;
        let ids: Vec<&str> = report.sections.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["ports", "sysproxy", "tun", "kernel", "network", "config", "rules"]
        );
        let s = summarize(&report.sections);
        assert_eq!(s.ok, report.summary.ok);
        assert_eq!(s.err, report.summary.err);
        assert_eq!(exit_code(&report), if s.err > 0 { 1 } else { 0 });
        // 渲染不 panic 且含汇总行
        assert!(render(&report).contains("汇总："));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
