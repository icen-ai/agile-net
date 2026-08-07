//! TUI data source: API first (writes go through server-side audit, same capabilities as the
//! admin UI), direct-DB read-only fallback.
//!
//! - Default: read the `anet login` session and talk to the node API; on health-check failure
//!   or missing session, automatically degrade to DB read-only and say so
//! - `--offline`: force DB read-only (fallback viewer when the node is down/broken)
//! - API calls block_on a TUI-private current-thread runtime (the TUI main loop stays sync)

use anyhow::{Result, anyhow};
use serde_json::Value;

use crate::cli::AnetClient;
use crate::db::Database;

// ==================== Row models (decouples rendering from data source) ====================

/// Group-set display cell from an API list item: comma-joined names of the resolved refs ("-" = unrestricted).
fn groups_display_json(v: &Value) -> String {
    let names: Vec<&str> = v["groups"]
        .as_array()
        .map(|a| a.iter().filter_map(|g| g["name"].as_str()).collect())
        .unwrap_or_default();
    if names.is_empty() {
        "-".into()
    } else {
        names.join(",")
    }
}

/// Group-set display cell from resolved DB refs ("-" = unrestricted).
fn groups_display_refs(refs: &[crate::db::models::GroupRef]) -> String {
    if refs.is_empty() {
        "-".into()
    } else {
        refs.iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Default, Clone)]
pub struct RuleRow {
    pub id: String,
    pub rule_type: String,
    pub value: String,
    pub resolve: bool,
    pub group_count: i64,
    pub remark: String,
}

#[derive(Default, Clone)]
pub struct GroupRow {
    pub id: String,
    pub name: String,
    pub rule_count: i64,
    pub remark: String,
}

#[derive(Default, Clone)]
pub struct DelegatedRow {
    pub id: String,
    pub prefix: String,
    pub label: String,
    /// Consumer mode: dedicated 专线 / split 分流
    pub mode: String,
    /// Entry mode: direct / relay
    pub entry_mode: String,
    /// Concurrency tier: single / multi
    pub concurrency: String,
    pub max_sessions: i64,
    pub created_at: String,
}

#[derive(Default, Clone)]
pub struct TokenRow {
    pub id: String,
    pub prefix: String,
    pub expose: bool,
    pub scope: String,
    /// ACL group name ("-" = unrestricted)
    pub group_name: String,
    pub remark: String,
    pub last_used: String,
    pub created_at: String,
}

#[derive(Default, Clone)]
pub struct ConnectorRow {
    pub id: String,
    pub name: String,
    pub upstream_addr: String,
    /// ACL group name ("-" = unrestricted)
    pub group_name: String,
    pub enabled: bool,
    /// Live state (connected/connecting/reconnecting/disconnected); empty in DB read-only mode (no runtime)
    pub state: String,
    pub remark: String,
}

#[derive(Default, Clone)]
pub struct AuditRow {
    pub created_at: String,
    pub operator: String,
    pub action: String,
    pub target: String,
    pub ip: String,
}

#[derive(Default, Clone)]
pub struct DashboardRow {
    pub name: String,
    pub version: String,
    pub config_version: u64,
    /// Extra info rows (label, value)
    pub extra: Vec<(String, String)>,
}

// ==================== Data source ====================

pub struct ApiSource {
    client: AnetClient,
    rt: tokio::runtime::Runtime,
    base: String,
}

pub enum Source {
    Api(ApiSource),
    Db(Database),
}

impl Source {
    pub fn readonly(&self) -> bool {
        matches!(self, Source::Db(_))
    }

    pub fn label(&self) -> String {
        match self {
            Source::Api(s) => format!("API {}（写操作落审计）", s.base),
            Source::Db(_) => "DB 只读（anet login 后可启用 API 管理模式）".into(),
        }
    }

    // ---------- Reads ----------

    pub fn dashboard(&mut self) -> Result<DashboardRow> {
        match self {
            Source::Api(s) => {
                let d: Value = s.call("GET", "/api/v1/admin/node/status", None)?;
                let l = &d["roles"]["listener"];
                let cs_summary = d["roles"]["connector_status"].as_str().unwrap_or("disabled");
                Ok(DashboardRow {
                    name: d["node_name"].as_str().unwrap_or("-").into(),
                    version: format!("v{}", d["version"].as_str().unwrap_or("-")),
                    config_version: d["uptime"].as_u64().unwrap_or(0), // reuse slot: the API has no config version; uptime seconds go to extra
                    extra: vec![
                        ("运行时长".into(), format!("{}s", d["uptime"].as_u64().unwrap_or(0))),
                        (
                            "Relay".into(),
                            if l["enabled"].as_bool().unwrap_or(false) {
                                format!(
                                    "{}（扇入 {} · 在线客户端 {}）",
                                    l["addr"].as_str().unwrap_or("-"),
                                    l["connected_connectors"].as_u64().unwrap_or(0),
                                    l["online_clients"].as_u64().unwrap_or(0)
                                )
                            } else {
                                "未启用".into()
                            },
                        ),
                        (
                            "扇出".into(),
                            if cs_summary == "disabled" {
                                "未配置".into()
                            } else {
                                d["roles"]["connectors"]
                                    .as_array()
                                    .map(|arr| {
                                        arr.iter()
                                            .map(|c| {
                                                format!(
                                                    "{} [{}]",
                                                    c["upstream"].as_str().unwrap_or("-"),
                                                    c["status"].as_str().unwrap_or("-")
                                                )
                                            })
                                            .collect::<Vec<_>>()
                                            .join(" · ")
                                    })
                                    .unwrap_or_else(|| "-".into())
                            },
                        ),
                    ],
                })
            }
            Source::Db(db) => {
                let name = db
                    .get_config("node_name")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "AgileNet 端点".into());
                Ok(DashboardRow {
                    name,
                    version: format!("v{}", env!("CARGO_PKG_VERSION")),
                    config_version: db.config_version().unwrap_or(0),
                    extra: Vec::new(),
                })
            }
        }
    }

    pub fn rules(&mut self) -> Result<Vec<RuleRow>> {
        match self {
            Source::Api(s) => {
                let d = s.call("GET", "/api/v1/admin/rules?page_size=500", None)?;
                Ok(d["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|r| RuleRow {
                        id: r["id"].as_str().unwrap_or_default().into(),
                        rule_type: r["type"].as_str().unwrap_or("-").into(),
                        value: r["value"].as_str().unwrap_or("-").into(),
                        resolve: r["resolve"].as_bool().unwrap_or(false),
                        group_count: r["group_count"].as_i64().unwrap_or(0),
                        remark: r["remark"].as_str().unwrap_or("").into(),
                    })
                    .collect())
            }
            Source::Db(db) => Ok(db
                .list_rules(1, 500, None, None)?
                .0
                .into_iter()
                .map(|r| RuleRow {
                    id: r.id,
                    rule_type: r.rule_type,
                    value: r.value,
                    resolve: r.resolve,
                    group_count: r.group_count,
                    remark: r.remark,
                })
                .collect()),
        }
    }

    pub fn groups(&mut self) -> Result<Vec<GroupRow>> {
        match self {
            Source::Api(s) => {
                let d = s.call("GET", "/api/v1/admin/groups?page_size=500", None)?;
                Ok(d["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|g| GroupRow {
                        id: g["id"].as_str().unwrap_or_default().into(),
                        name: g["name"].as_str().unwrap_or("-").into(),
                        rule_count: g["rule_count"].as_i64().unwrap_or(0),
                        remark: g["remark"].as_str().unwrap_or("").into(),
                    })
                    .collect())
            }
            Source::Db(db) => Ok(db
                .list_groups(1, 500, None)?
                .0
                .into_iter()
                .map(|g| GroupRow {
                    id: g.id,
                    name: g.name,
                    rule_count: g.rule_count,
                    remark: g.remark,
                })
                .collect()),
        }
    }

    pub fn delegated(&mut self) -> Result<Vec<DelegatedRow>> {
        match self {
            Source::Api(s) => {
                let d = s.call("GET", "/api/v1/admin/delegation/tokens", None)?;
                Ok(d["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|t| DelegatedRow {
                        id: t["id"].as_str().unwrap_or_default().into(),
                        prefix: t["token_prefix"].as_str().unwrap_or("-").into(),
                        label: t["label"].as_str().unwrap_or("-").into(),
                        mode: t["mode"].as_str().unwrap_or("dedicated").into(),
                        entry_mode: t["entry_mode"].as_str().unwrap_or("-").into(),
                        concurrency: t["concurrency"].as_str().unwrap_or("-").into(),
                        max_sessions: t["max_sessions"].as_i64().unwrap_or(0),
                        created_at: t["created_at"].as_str().unwrap_or("-").into(),
                    })
                    .collect())
            }
            Source::Db(db) => Ok(db
                .list_delegated_tokens()?
                .into_iter()
                .map(|t| DelegatedRow {
                    id: t.id,
                    prefix: t.token_prefix,
                    label: t.label,
                    mode: t.mode,
                    entry_mode: t.entry_mode,
                    concurrency: t.concurrency,
                    max_sessions: t.max_sessions,
                    created_at: t.created_at,
                })
                .collect()),
        }
    }

    pub fn tokens(&mut self) -> Result<Vec<TokenRow>> {
        match self {
            Source::Api(s) => {
                let d = s.call("GET", "/api/v1/admin/node/relay-tokens", None)?;
                Ok(d["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|t| TokenRow {
                        id: t["id"].as_str().unwrap_or_default().into(),
                        prefix: t["token_prefix"].as_str().unwrap_or("-").into(),
                        expose: t["expose_control"].as_bool().unwrap_or(false),
                        scope: t["control_scope"].as_str().unwrap_or("full").into(),
                        group_name: groups_display_json(t),
                        remark: t["remark"].as_str().unwrap_or("").into(),
                        last_used: t["last_used_at"].as_str().unwrap_or("未使用").into(),
                        created_at: t["created_at"].as_str().unwrap_or("-").into(),
                    })
                    .collect())
            }
            Source::Db(db) => Ok(db
                .list_relay_tokens()?
                .into_iter()
                .map(|t| TokenRow {
                    id: t.id,
                    prefix: t.token_prefix,
                    expose: t.expose_control,
                    scope: t.control_scope,
                    group_name: groups_display_refs(&t.groups),
                    remark: t.remark,
                    last_used: t.last_used_at.unwrap_or_else(|| "未使用".into()),
                    created_at: t.created_at,
                })
                .collect()),
        }
    }

    pub fn connectors(&mut self) -> Result<Vec<ConnectorRow>> {
        match self {
            Source::Api(s) => {
                // list items carry ConnectorManager live state merged server-side (state field)
                let d = s.call("GET", "/api/v1/admin/connectors", None)?;
                Ok(d["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|c| ConnectorRow {
                        id: c["id"].as_str().unwrap_or_default().into(),
                        name: c["name"].as_str().unwrap_or("-").into(),
                        upstream_addr: c["upstream_addr"].as_str().unwrap_or("-").into(),
                        group_name: groups_display_json(c),
                        enabled: c["enabled"].as_bool().unwrap_or(false),
                        state: c["state"].as_str().unwrap_or("disconnected").into(),
                        remark: c["remark"].as_str().unwrap_or("").into(),
                    })
                    .collect())
            }
            Source::Db(db) => Ok(db
                .list_connectors()?
                .into_iter()
                .map(|c| ConnectorRow {
                    id: c.id,
                    name: c.name,
                    upstream_addr: c.upstream_addr,
                    group_name: groups_display_refs(&c.groups),
                    enabled: c.enabled,
                    state: String::new(),
                    remark: c.remark,
                })
                .collect()),
        }
    }

    pub fn audit_logs(&mut self) -> Result<Vec<AuditRow>> {
        match self {
            Source::Api(s) => {
                let d = s.call("GET", "/api/v1/admin/audit-logs?page_size=200", None)?;
                Ok(d["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|l| AuditRow {
                        created_at: l["created_at"].as_str().unwrap_or("-").into(),
                        operator: l["operator"].as_str().unwrap_or("-").into(),
                        action: l["action"].as_str().unwrap_or("-").into(),
                        target: l["target"].as_str().unwrap_or("-").into(),
                        ip: l["ip"].as_str().unwrap_or("-").into(),
                    })
                    .collect())
            }
            Source::Db(db) => Ok(db
                .list_audit_logs(1, 200, None)?
                .0
                .into_iter()
                .map(|l| AuditRow {
                    created_at: l.created_at,
                    operator: l.operator,
                    action: l.action,
                    target: l.target.unwrap_or_else(|| "-".into()),
                    ip: l.ip.unwrap_or_else(|| "-".into()),
                })
                .collect()),
        }
    }

    // ---------- Writes (API mode only; DB read-only is gated by the caller via readonly) ----------

    /// Returns the plaintext token (visible only this once).
    pub fn create_token(&mut self, remark: &str) -> Result<String> {
        match self {
            Source::Api(s) => {
                let d = s.call(
                    "POST",
                    "/api/v1/admin/node/relay-tokens",
                    Some(serde_json::json!({ "remark": remark })),
                )?;
                d["token"]
                    .as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| anyhow!("响应缺少 token"))
            }
            Source::Db(_) => Err(anyhow!("只读模式（数据库直连）")),
        }
    }

    pub fn delete_rule(&mut self, id: &str) -> Result<()> {
        match self {
            Source::Api(s) => {
                s.call("DELETE", &format!("/api/v1/admin/rules/{id}"), None)?;
                Ok(())
            }
            Source::Db(_) => Err(anyhow!("只读模式（数据库直连）")),
        }
    }

    pub fn delete_group(&mut self, id: &str) -> Result<()> {
        match self {
            Source::Api(s) => {
                s.call("DELETE", &format!("/api/v1/admin/groups/{id}"), None)?;
                Ok(())
            }
            Source::Db(_) => Err(anyhow!("只读模式（数据库直连）")),
        }
    }

    pub fn delete_delegated(&mut self, id: &str) -> Result<()> {
        match self {
            Source::Api(s) => {
                s.call(
                    "DELETE",
                    &format!("/api/v1/admin/delegation/tokens/{id}"),
                    None,
                )?;
                Ok(())
            }
            Source::Db(_) => Err(anyhow!("只读模式（数据库直连）")),
        }
    }

    pub fn delete_token(&mut self, id: &str) -> Result<()> {
        match self {
            Source::Api(s) => {
                s.call(
                    "DELETE",
                    &format!("/api/v1/admin/node/relay-tokens/{id}"),
                    None,
                )?;
                Ok(())
            }
            Source::Db(_) => Err(anyhow!("只读模式（数据库直连）")),
        }
    }
}

impl ApiSource {
    fn call(&mut self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        self.rt.block_on(self.client.api(method, path, body))
    }
}

// ==================== Connection decision ====================

pub struct ConnectOutcome {
    pub source: Source,
    /// Degradation note (why DB mode was entered; None in API mode)
    pub degraded_note: Option<String>,
}

/// Connect the data source: API first (needs an `anet login` session), degrades to DB read-only on failure.
pub fn connect(api_override: Option<String>, offline: bool, db_path: &str) -> Result<ConnectOutcome> {
    let open_db = |note: Option<String>| -> Result<ConnectOutcome> {
        Ok(ConnectOutcome {
            source: Source::Db(Database::open(db_path)?),
            degraded_note: note,
        })
    };
    if offline {
        return open_db(Some("--offline 指定：数据库直连只读模式".into()));
    }
    let Some(session) = crate::cli::Session::load() else {
        return open_db(Some("未发现登录会话（anet login 后启用 API 管理模式）".into()));
    };
    let api = api_override.unwrap_or(session.api.clone());
    let mut client = AnetClient::from_session(Some(api.clone()))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // health check: node offline / session expired -> degrade to read-only
    let healthy = rt
        .block_on(client.api("GET", "/api/v1/admin/node/status", None))
        .is_ok();
    if healthy {
        Ok(ConnectOutcome {
            source: Source::Api(ApiSource {
                client,
                rt,
                base: api,
            }),
            degraded_note: None,
        })
    } else {
        open_db(Some(format!(
            "节点 API 不可达或会话失效（{api}），已降级数据库只读模式"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("anet-tui-src-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // PIDs recycle across cargo runs — a stale file from an earlier process would fail the
        // first insert with UNIQUE constraint errors; start from a clean slate (hermetic tests)
        for suffix in ["t.db", "t.db-shm", "t.db-wal"] {
            let _ = std::fs::remove_file(dir.join(suffix));
        }
        dir.join("t.db").to_string_lossy().to_string()
    }

    #[test]
    fn offline_goes_db_readonly() {
        let db = tmp_db("offline");
        let out = connect(None, true, &db).unwrap();
        assert!(out.source.readonly());
        assert!(out.degraded_note.is_some());
        assert!(out.source.label().contains("只读"));
    }

    #[test]
    fn unreachable_api_degrades_to_db() {
        let db = tmp_db("degrade");
        // dead port (9 = discard): with a session the health check fails and degrades; without one it degrades too
        let out = connect(Some("http://127.0.0.1:9".into()), false, &db).unwrap();
        assert!(out.source.readonly());
        assert!(out.degraded_note.is_some());
    }

    #[test]
    fn db_rows_carry_group_name() {
        let db = Database::open(tmp_db("group")).unwrap();
        let g = db.create_group("G1", "").unwrap();
        db.create_relay_token_with_quota("hash-t1", "tun_t1", "", false, "full", Some(&g.id), None)
            .unwrap();
        db.create_relay_token_with_quota("hash-t2", "tun_t2", "", false, "full", None, None)
            .unwrap();
        db.create_connector(
            "peer-a",
            "",
            "127.0.0.1:54430",
            "psk_secret",
            "",
            false,
            "",
            "",
            "",
            "10.0.0.0/8",
            Some(&g.id),
            "",
        )
        .unwrap();
        let mut src = Source::Db(db);

        let tokens = src.tokens().unwrap();
        assert_eq!(tokens.len(), 2);
        // created within the same second share created_at; do not assert by position
        let group_of = |prefix: &str| {
            tokens
                .iter()
                .find(|t| t.prefix == prefix)
                .map(|t| t.group_name.clone())
        };
        assert_eq!(group_of("tun_t1").as_deref(), Some("G1"));
        assert_eq!(group_of("tun_t2").as_deref(), Some("-")); // unrestricted

        let conns = src.connectors().unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].name, "peer-a");
        assert_eq!(conns[0].group_name, "G1");
        assert!(conns[0].enabled);
        assert!(conns[0].state.is_empty()); // DB read-only has no runtime state
    }

    #[test]
    fn db_delegated_rows_carry_concurrency_fields() {
        let db = Database::open(tmp_db("delegated")).unwrap();
        db.create_delegated_token(
            "hash-d1",
            "d_d1",
            "label-1",
            "[]",
            "[]",
            "",
            "dedicated",
            "",
            "direct",
            "multi",
            8,
            None,
            None,
        )
        .unwrap();
        let mut src = Source::Db(db);
        let rows = src.delegated().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].prefix, "d_d1");
        assert_eq!(rows[0].entry_mode, "direct");
        assert_eq!(rows[0].concurrency, "multi");
        assert_eq!(rows[0].max_sessions, 8);
    }
}
