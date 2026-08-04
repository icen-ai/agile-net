//! Adopted-group live mirror (federation P1 acceptance): an adopted group is read-only and
//! follows its pushed source — on every watcher tick the source's rules and E2E flag are
//! re-applied. Writes happen only on drift; a source that is offline or has vanished leaves
//! the last snapshot in place (the mirror never amplifies an outage into an ACL wipe).

use crate::db::Database;
use agile_net_core::relay::listener::PeerOffer;

/// Re-apply every adopted group's source state (rules + E2E flag); bumps config_version once
/// when anything actually changed. Returns the number of changed groups.
pub fn sync_adopted(db: &Database, offers: &[PeerOffer]) -> u32 {
    let Ok(adopted) = db.list_adopted_groups() else {
        return 0;
    };
    let mut changed = 0u32;
    for g in adopted {
        let Some(src) = offers
            .iter()
            .find(|o| o.node_id == g.adopted_node)
            .and_then(|o| o.groups.iter().find(|pg| pg.name == g.adopted_name))
        else {
            continue; // source offline or un-pushed — the last snapshot keeps serving
        };

        // desired bindings, materialized by unique (type, value) — same rule reuse as adoption
        let mut desired: Vec<String> = Vec::new();
        for value in &src.rules {
            let value = value.trim();
            if value.is_empty() || value.len() > 256 {
                continue;
            }
            let ty = if value.parse::<ip_network::IpNetwork>().is_ok() {
                "ip-cidr"
            } else {
                "host"
            };
            match db.find_rule_id(ty, value) {
                Ok(Some(id)) => desired.push(id),
                Ok(None) => {
                    let remark = format!("上送自 {}/{}", g.adopted_node, g.adopted_name);
                    if let Ok(r) = db.create_rule(ty, value, false, &remark) {
                        desired.push(r.id);
                    }
                }
                Err(_) => {}
            }
        }
        desired.sort();
        desired.dedup();
        let mut current: Vec<String> = db
            .rules_of_group(&g.id)
            .map(|rs| rs.into_iter().map(|r| r.id).collect())
            .unwrap_or_default();
        current.sort();
        if current != desired && db.set_group_rules(&g.id, &desired).is_ok() {
            changed += 1;
        }

        if g.e2e_required != src.e2e_required {
            // a late enable may fail closed against attachments made meanwhile — the divergence
            // stays visible in the UI and the next tick retries
            match db.set_group_e2e_required(&g.id, src.e2e_required) {
                Ok(()) => changed += 1,
                Err(e) => {
                    tracing::debug!(group = %g.name, error = %e, "adopted group e2e flag sync deferred")
                }
            }
        }
    }
    if changed > 0 {
        let _ = db.bump_config_version();
        tracing::info!(count = changed, "adopted groups re-synced from pushed sources");
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pushed(node: &str, name: &str, rules: &[&str], e2e: bool) -> PeerOffer {
        PeerOffer {
            node_id: node.to_string(),
            advertise: Vec::new(),
            groups: vec![agile_net_core::proto::message::PushedGroupMsg {
                name: name.to_string(),
                remark: String::new(),
                rules: rules.iter().map(|s| s.to_string()).collect(),
                e2e_required: e2e,
            }],
        }
    }

    #[test]
    fn mirror_follows_source_drift_and_stays_on_vanish() {
        let db = Database::in_memory().unwrap();
        let g = db.create_group("git@peer-c", "上送").unwrap();
        db.set_group_adoption(&g.id, "peer-c", "git").unwrap();

        // source appears with two rules -> mirrored
        let offers = vec![pushed("peer-c", "git", &["10.12.0.0/16", "git.internal"], false)];
        assert_eq!(sync_adopted(&db, &offers), 1);
        let vals: Vec<String> = db
            .rules_of_group(&g.id)
            .unwrap()
            .into_iter()
            .map(|r| r.value)
            .collect();
        assert_eq!(vals.len(), 2);

        // source drifts (one rule swapped) -> follows; a second tick is a no-op (drift-only writes)
        let offers = vec![pushed("peer-c", "git", &["10.12.0.0/16", "ops.internal"], true)];
        assert_eq!(sync_adopted(&db, &offers), 2); // rules + e2e flag
        assert_eq!(sync_adopted(&db, &offers), 0);
        assert!(db.get_group(&g.id).unwrap().unwrap().e2e_required);

        // source vanishes -> the last snapshot stays (rules untouched)
        assert_eq!(sync_adopted(&db, &[]), 0);
        let vals: Vec<String> = db
            .rules_of_group(&g.id)
            .unwrap()
            .into_iter()
            .map(|r| r.value)
            .collect();
        assert_eq!(vals.len(), 2);
    }
}
