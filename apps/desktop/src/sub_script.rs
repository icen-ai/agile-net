//! 订阅覆写脚本引擎（QuickJS 沙箱）：render_config 产物交给 mihomo 前按序执行用户 JS。
//!
//! - 管线：YAML → serde_json::Value → 依序调用每个启用脚本的 `main(config)` → YAML
//! - 沙箱：每脚本独立 Runtime/Context（rquickjs 嵌入式 QuickJS，无外部运行时）；
//!   内存 32MB / 栈 1MB / 执行 2s 中断（interrupt handler）
//! - 容错：脚本异常 / 缺少 main / 返回非对象 → 跳过该脚本继续后续，
//!   记审计 `gui.sub_script_error`（脚本名 + 错误摘要，不落脚本全文）

use crate::roles::{self, SubScript};

/// 单脚本执行时限（interrupt handler 轮询到达即中断）
const SCRIPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// 沙箱内存上限
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;
/// 沙箱栈上限
const STACK_LIMIT: usize = 1024 * 1024;

/// 拼装单次 eval 程序：用户代码 + 尾部队列（取 main 并调用、JSON 进出、返回类型校验）。
/// config 以 JS 字符串字面量注入（JSON.parse 还原），结果经 JSON.stringify 取回。
fn build_program(code: &str, cfg_json: &str) -> String {
    let cfg_lit = serde_json::to_string(cfg_json).unwrap_or_else(|_| "\"{}\"".into());
    format!(
        "{code}\n;(() => {{\n  if (typeof main !== 'function') throw new Error('缺少 main(config) 函数');\n  const cfg = JSON.parse({cfg_lit});\n  const out = main(cfg);\n  if (!out || typeof out !== 'object' || Array.isArray(out)) throw new Error('main 必须返回配置对象');\n  return JSON.stringify(out);\n}})()"
    )
}

/// 错误摘要：取首行并截断（审计/灵动岛展示用，不含脚本全文）
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

/// 在一次性 QuickJS 沙箱中执行单个脚本：eval 用户代码后调用 main(config)，
/// 返回新配置。任何异常（语法/运行时/超时/缺 main/返回非对象）均为 Err。
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

/// 对 YAML 配置文本执行启用脚本链（Vec 顺序）。任一脚本失败：跳过、记审计
/// gui.sub_script_error（脚本名 + 摘要）、继续后续脚本。
/// 返回 (最终 YAML, 失败摘要[(脚本名, 错误)])；无启用脚本或配置解析失败时原样返回。
pub fn apply_scripts(yaml: &str, scripts: &[SubScript]) -> (String, Vec<(String, String)>) {
    let mut fails = Vec::new();
    if !scripts.iter().any(|s| s.enabled) {
        return (yaml.to_string(), fails);
    }
    // render_config 为自家产物，解析失败属内部错误：原样放行（保守不破坏内核启动）
    let Ok(mut cfg) = serde_yaml::from_str::<serde_json::Value>(yaml) else {
        return (yaml.to_string(), fails);
    };
    for sc in scripts.iter().filter(|s| s.enabled) {
        match run_script(&sc.code, &cfg) {
            Ok(v) => cfg = v,
            Err(e) => {
                roles::audit(
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

/// 试跑：对给定 YAML 配置执行一段代码（不跳过错误），返回新配置。
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

    /// 用户示例脚本：push 代理 + unshift 规则
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
        // 反序执行结果不同（mark 先跑时首条不是 FIRST）
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
        // 试跑错误直接透出（不跳过）
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
