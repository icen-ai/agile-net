//! Subscription override script engine (QuickJS sandbox): runs user JS in order on render_config output before handing it to mihomo.
//!
//! - Pipeline: YAML → serde_json::Value → call each enabled script's `main(config)` in order → YAML
//! - Sandbox: one Runtime/Context per script (rquickjs embedded QuickJS, no external runtime);
//!   32MB memory / 1MB stack / 2s execution interrupt (interrupt handler)
//! - Fault tolerance: script exception / missing main / non-object return → skip that script and continue,
//!   auditing `gui.sub_script_error` (script name + error summary, never the full script body)

use crate::roles::SubScript;

/// Per-script execution time limit (interrupt handler fires when reached)
#[cfg(not(target_os = "android"))]
const SCRIPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Sandbox memory limit
#[cfg(not(target_os = "android"))]
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;
/// Sandbox stack limit
#[cfg(not(target_os = "android"))]
const STACK_LIMIT: usize = 1024 * 1024;

/// Build the one-shot eval program: user code + trailing wrapper (fetch and call main, JSON in/out, return type check).
/// config is injected as a JS string literal (restored via JSON.parse); the result is retrieved via JSON.stringify.
#[cfg(not(target_os = "android"))]
fn build_program(code: &str, cfg_json: &str) -> String {
    let cfg_lit = serde_json::to_string(cfg_json).unwrap_or_else(|_| "\"{}\"".into());
    format!(
        "{code}\n;(() => {{\n  if (typeof main !== 'function') throw new Error('缺少 main(config) 函数');\n  const cfg = JSON.parse({cfg_lit});\n  const out = main(cfg);\n  if (!out || typeof out !== 'object' || Array.isArray(out)) throw new Error('main 必须返回配置对象');\n  return JSON.stringify(out);\n}})()"
    )
}

/// Error summary: first line, truncated (for audit / dynamic-island display; never the full script body)
#[cfg(not(target_os = "android"))]
fn summarize(err: &str) -> String {
    let first = err.lines().next().unwrap_or(err).trim();
    const MAX: usize = 200;
    if first.chars().count() > MAX {
        let mut s: String = first.chars().take(MAX).collect();
        s.push('…');
        s
    } else {
        first.to_string()
    }
}

/// Run a single script in a one-shot QuickJS sandbox: eval user code, then call main(config) and return
/// the new config. Any failure (syntax/runtime/timeout/missing main/non-object return) is an Err.
#[cfg(not(target_os = "android"))]
pub fn run_script(code: &str, cfg: &serde_json::Value) -> Result<serde_json::Value, String> {
    let cfg_json = serde_json::to_string(cfg).map_err(|e| e.to_string())?;
    let rt = rquickjs::Runtime::new().map_err(|e| format!("脚本引擎初始化失败: {e}"))?;
    rt.set_memory_limit(MEMORY_LIMIT);
    rt.set_max_stack_size(STACK_LIMIT);
    let deadline = std::time::Instant::now() + SCRIPT_TIMEOUT;
    rt.set_interrupt_handler(Some(Box::new(move || {
        std::time::Instant::now() >= deadline
    })));
    let ctx = rquickjs::Context::full(&rt).map_err(|e| format!("脚本引擎初始化失败: {e}"))?;
    let out: Result<String, String> = ctx.with(|ctx| {
        let program = build_program(code, &cfg_json);
        match ctx.eval::<String, _>(program) {
            Ok(s) => Ok(s),
            Err(e) => Err(summarize(
                &rquickjs::CaughtError::from_error(&ctx, e).to_string(),
            )),
        }
    });
    let out = out?;
    serde_json::from_str(&out).map_err(|e| format!("脚本返回结果无法解析: {e}"))
}

/// Android stub: rquickjs ships no android bindings and the subscription kernel itself is a desktop
/// capability (no sidecar on Android) — the script engine is compiled out on this platform.
#[cfg(target_os = "android")]
pub fn run_script(_code: &str, _cfg: &serde_json::Value) -> Result<serde_json::Value, String> {
    Err("覆写脚本在 Android 端不可用（订阅内核为桌面端能力）".into())
}

/// Run the enabled script chain (Vec order) on YAML config text. Any script failure: skip it, audit
/// gui.sub_script_error (script name + summary), and continue with the rest.
/// Returns (final YAML, failure summaries [(script name, error)]); returns input verbatim when no script is enabled or config parsing fails.
#[cfg(not(target_os = "android"))]
pub fn apply_scripts(yaml: &str, scripts: &[SubScript]) -> (String, Vec<(String, String)>) {
    let mut fails = Vec::new();
    if !scripts.iter().any(|s| s.enabled) {
        return (yaml.to_string(), fails);
    }
    // render_config output is our own; a parse failure is an internal error: pass through verbatim (conservative, do not break kernel startup)
    let Ok(mut cfg) = serde_yaml::from_str::<serde_json::Value>(yaml) else {
        return (yaml.to_string(), fails);
    };
    for sc in scripts.iter().filter(|s| s.enabled) {
        match run_script(&sc.code, &cfg) {
            Ok(v) => cfg = v,
            Err(e) => {
                crate::roles::audit(
                    "gui.sub_script_error",
                    serde_json::json!({"name": sc.name, "error": e}),
                );
                fails.push((sc.name.clone(), e));
            }
        }
    }
    match serde_yaml::to_string(&cfg) {
        Ok(out) => (out, fails),
        Err(_) => (yaml.to_string(), fails),
    }
}

/// Android: no engine — pass the config through verbatim (the kernel cannot run on Android anyway).
#[cfg(target_os = "android")]
pub fn apply_scripts(yaml: &str, _scripts: &[SubScript]) -> (String, Vec<(String, String)>) {
    (yaml.to_string(), Vec::new())
}

/// Test run: execute a code snippet against the given YAML config (errors not skipped); returns the new config.
pub fn test_run(code: &str, yaml: &str) -> Result<serde_json::Value, String> {
    let cfg: serde_json::Value =
        serde_yaml::from_str(yaml).map_err(|e| format!("当前配置解析失败: {e}"))?;
    run_script(code, &cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(name: &str, code: &str, enabled: bool) -> SubScript {
        SubScript {
            id: name.into(),
            name: name.into(),
            code: code.into(),
            enabled,
            order: 0,
        }
    }

    fn base_cfg() -> serde_json::Value {
        serde_json::json!({
            "mixed-port": 57892,
            "proxies": [{"name": "A"}],
            "rules": ["MATCH,AGILE-SUB"],
        })
    }

    /// User example script: push a proxy + unshift a rule
    const USER_SCRIPT: &str = r#"
const main = (config) => {
  config.proxies = config.proxies || [];
  config.proxies.push({ name: "自建", type: "ss", server: "1.2.3.4", port: 8388 });
  config.rules = config.rules || [];
  config.rules.unshift("DOMAIN-SUFFIX,example.com,自建");
  return config;
};
"#;

    #[test]
    fn user_script_push_and_unshift() {
        let out = run_script(USER_SCRIPT, &base_cfg()).unwrap();
        assert_eq!(out["proxies"].as_array().unwrap().len(), 2);
        assert_eq!(out["proxies"][1]["name"], "自建");
        assert_eq!(out["rules"][0], "DOMAIN-SUFFIX,example.com,自建");
        assert_eq!(out["rules"][1], "MATCH,AGILE-SUB");
    }

    #[test]
    fn chain_order_is_significant() {
        let prepend = script(
            "prepend",
            "const main = (c) => { c.rules.unshift('FIRST'); return c; };",
            true,
        );
        let mark = script(
            "mark",
            "const main = (c) => { c.rules.unshift(c.rules[0] === 'FIRST' ? 'AFTER' : 'BEFORE'); return c; };",
            true,
        );
        let yaml = serde_yaml::to_string(&base_cfg()).unwrap();
        let (out, fails) = apply_scripts(&yaml, &[prepend.clone(), mark.clone()]);
        assert!(fails.is_empty());
        let cfg: serde_json::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(cfg["rules"][0], "AFTER");
        // Reversed order yields a different result (when mark runs first, the head rule is not FIRST)
        let (out2, _) = apply_scripts(&yaml, &[mark, prepend]);
        let cfg2: serde_json::Value = serde_yaml::from_str(&out2).unwrap();
        assert_eq!(cfg2["rules"][0], "FIRST");
    }

    #[test]
    fn failing_script_skipped_and_chain_continues() {
        let boom = script("boom", "const main = (c) => { throw new Error('炸了'); };", true);
        let no_main = script("no-main", "const notMain = (c) => c;", true);
        let non_obj = script("non-obj", "const main = (c) => 42;", true);
        let good = script(
            "good",
            "const main = (c) => { c.rules.push('TAIL'); return c; };",
            true,
        );
        let yaml = serde_yaml::to_string(&base_cfg()).unwrap();
        let (out, fails) = apply_scripts(&yaml, &[boom, no_main, non_obj, good]);
        assert_eq!(fails.len(), 3);
        assert_eq!(fails[0].0, "boom");
        assert!(fails[0].1.contains("炸了"));
        assert!(fails[1].1.contains("main"));
        let cfg: serde_json::Value = serde_yaml::from_str(&out).unwrap();
        let rules = cfg["rules"].as_array().unwrap();
        assert_eq!(rules.last().unwrap(), "TAIL");
    }

    #[test]
    fn disabled_scripts_not_executed() {
        let off = script(
            "off",
            "const main = (c) => { c.rules.push('OFF'); return c; };",
            false,
        );
        let yaml = serde_yaml::to_string(&base_cfg()).unwrap();
        let (out, fails) = apply_scripts(&yaml, &[off]);
        assert!(fails.is_empty());
        let cfg: serde_json::Value = serde_yaml::from_str(&out).unwrap();
        assert!(!cfg["rules"].as_array().unwrap().contains(&serde_json::json!("OFF")));
    }

    #[test]
    fn infinite_loop_interrupted_within_timeout() {
        let start = std::time::Instant::now();
        let r = run_script("const main = (c) => { while (true) {} };", &base_cfg());
        assert!(r.is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "中断超时: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn syntax_error_reported() {
        let r = run_script("const main = (c) => {{{{", &base_cfg());
        assert!(r.is_err());
    }

    #[test]
    fn test_run_roundtrip() {
        let yaml = serde_yaml::to_string(&base_cfg()).unwrap();
        let out = test_run(USER_SCRIPT, &yaml).unwrap();
        assert_eq!(out["proxies"].as_array().unwrap().len(), 2);
        // Test-run errors propagate directly (not skipped)
        assert!(test_run("const main = () => { throw new Error('x'); };", &yaml).is_err());
    }

    #[test]
    fn summarize_truncates() {
        let long = "x".repeat(500);
        let s = summarize(&long);
        assert!(s.chars().count() <= 201);
        assert_eq!(summarize("a\nb"), "a");
    }
}
