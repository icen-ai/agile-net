//! Split from db/mod.rs: connector/node_config tables and encrypted fan-out token storage (pure move, no logic change)

use super::generate_secret_hex;
use super::models::*;
use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::{Error, Result};
use rusqlite::params;

impl Database {
    // ==================== Connector (fan-out, first-class resource) ====================

    /// Create a fan-out connector (token stored encrypted; never shown again, only resettable).
    #[allow(clippy::too_many_arguments)]
    pub fn create_connector(
        &self,
        name: &str,
        my_name: &str,
        upstream_addr: &str,
        token_plain: &str,
        sni_hostname: &str,
        insecure: bool,
        ca_cert_path: &str,
        pinned_cert_path: &str,
        pinned_fingerprint: &str,
        advertise: &str,
        group_id: Option<&str>,
        remark: &str,
    ) -> Result<ConnectorRecord> {
        let token_enc = self.encrypt_secret(token_plain)?;
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO connector (id, name, my_name, upstream_addr, token_enc, sni_hostname, insecure, ca_cert_path, pinned_cert_path, pinned_fingerprint, advertise, group_id, enabled, remark, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,1,?13,?14,?14)",
            params![id, name, my_name, upstream_addr, token_enc, sni_hostname, insecure as i32, ca_cert_path, pinned_cert_path, pinned_fingerprint, advertise, group_id, remark, now],
        )
        .map_err(db_err)?;
        Ok(ConnectorRecord {
            id,
            name: name.to_string(),
            my_name: my_name.to_string(),
            upstream_addr: upstream_addr.to_string(),
            token_enc,
            sni_hostname: sni_hostname.to_string(),
            insecure,
            ca_cert_path: ca_cert_path.to_string(),
            pinned_cert_path: pinned_cert_path.to_string(),
            pinned_fingerprint: pinned_fingerprint.to_string(),
            advertise: advertise.to_string(),
            group_id: group_id.map(|g| g.to_string()),
            push_groups: String::new(),
            enabled: true,
            remark: remark.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// List all fan-out connectors (display view; never contains token plaintext/ciphertext).
    pub fn list_connectors(&self) -> Result<Vec<ConnectorView>> {
        // Fetch all rows and release the connection first (memory pool size is 1; decryption and
        // the group-ref resolution below need another conn)
        let recs = {
            let conn = self.conn();
            let mut stmt = conn
                .prepare(
                    "SELECT c.id, c.name, c.my_name, c.upstream_addr, c.token_enc, c.sni_hostname, c.insecure, c.ca_cert_path, c.pinned_cert_path, c.pinned_fingerprint, c.advertise,
                            c.group_id, c.enabled, c.remark, c.created_at, c.updated_at, c.push_groups
                     FROM connector c ORDER BY c.created_at DESC",
                )
                .map_err(db_err)?;
            let mut rows = stmt.query([]).map_err(db_err)?;
            let mut recs = Vec::new();
            while let Some(r) = rows.next().map_err(db_err)? {
                recs.push(ConnectorRecord {
                    id: r.get(0).map_err(db_err)?,
                    name: r.get(1).map_err(db_err)?,
                    my_name: r.get(2).map_err(db_err)?,
                    upstream_addr: r.get(3).map_err(db_err)?,
                    token_enc: r.get(4).map_err(db_err)?,
                    sni_hostname: r.get(5).map_err(db_err)?,
                    insecure: r.get::<_, i32>(6).map_err(db_err)? != 0,
                    ca_cert_path: r.get(7).map_err(db_err)?,
                    pinned_cert_path: r.get(8).map_err(db_err)?,
                    pinned_fingerprint: r.get(9).map_err(db_err)?,
                    advertise: r.get(10).map_err(db_err)?,
                    group_id: r.get(11).map_err(db_err)?,
                    enabled: r.get::<_, i32>(12).map_err(db_err)? != 0,
                    remark: r.get(13).map_err(db_err)?,
                    created_at: r.get(14).map_err(db_err)?,
                    updated_at: r.get(15).map_err(db_err)?,
                    push_groups: r.get(16).map_err(db_err)?,
                });
            }
            recs
        };
        let mut items = Vec::new();
        for rec in recs {
            // Group sets (comma-separated group_id) resolve per member in Rust (naming
            // sovereignty: refs carry the adoption lineage for badge rendering)
            let groups = self.group_refs_of(rec.group_id.as_deref());
            // Prefix display: decrypt and take the first 8 chars for identification only; leave empty on decrypt failure (key rotation etc.)
            let token_prefix = self
                .decrypt_secret(&rec.token_enc)
                .map(|t| token_prefix_of(&t))
                .unwrap_or_default();
            items.push(ConnectorView {
                id: rec.id,
                name: rec.name,
                my_name: rec.my_name,
                upstream_addr: rec.upstream_addr,
                token_prefix,
                sni_hostname: rec.sni_hostname,
                insecure: rec.insecure,
                ca_cert_path: rec.ca_cert_path,
                pinned_cert_path: rec.pinned_cert_path,
                pinned_fingerprint: rec.pinned_fingerprint,
                advertise: rec.advertise,
                group_id: rec.group_id,
                groups,
                push_groups: rec.push_groups,
                enabled: rec.enabled,
                remark: rec.remark,
                created_at: rec.created_at,
                updated_at: rec.updated_at,
            });
        }
        Ok(items)
    }

    /// Get a connector record by ID (includes ciphertext; internal use only, never log/audit it).
    pub fn get_connector(&self, id: &str) -> Result<Option<ConnectorRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, my_name, upstream_addr, token_enc, sni_hostname, insecure, ca_cert_path, pinned_cert_path, pinned_fingerprint, advertise, group_id, enabled, remark, created_at, updated_at, push_groups
                 FROM connector WHERE id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(ConnectorRecord {
                id: r.get(0).map_err(db_err)?,
                name: r.get(1).map_err(db_err)?,
                my_name: r.get(2).map_err(db_err)?,
                upstream_addr: r.get(3).map_err(db_err)?,
                token_enc: r.get(4).map_err(db_err)?,
                sni_hostname: r.get(5).map_err(db_err)?,
                insecure: r.get::<_, i32>(6).map_err(db_err)? != 0,
                ca_cert_path: r.get(7).map_err(db_err)?,
                pinned_cert_path: r.get(8).map_err(db_err)?,
                pinned_fingerprint: r.get(9).map_err(db_err)?,
                advertise: r.get(10).map_err(db_err)?,
                group_id: r.get(11).map_err(db_err)?,
                enabled: r.get::<_, i32>(12).map_err(db_err)? != 0,
                remark: r.get(13).map_err(db_err)?,
                created_at: r.get(14).map_err(db_err)?,
                updated_at: r.get(15).map_err(db_err)?,
                push_groups: r.get(16).map_err(db_err)?,
            }),
            None => None,
        })
    }

    /// Set the pushed policy groups (federation P1; comma-separated local group IDs, empty = no upload).
    pub fn set_connector_push_groups(&self, id: &str, push_groups: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE connector SET push_groups = ?1, updated_at = ?2 WHERE id = ?3",
            params![push_groups, now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Get a connector's fan-out token plaintext by ID (decrypted, runtime connect only; never log/audit it).
    pub fn get_connector_secret(&self, id: &str) -> Result<String> {
        let rec = self
            .get_connector(id)?
            .ok_or_else(|| Error::Other("connector not found".into()))?;
        self.decrypt_secret(&rec.token_enc)
    }

    /// Update a connector (token_plain = None keeps the existing token).
    #[allow(clippy::too_many_arguments)]
    pub fn update_connector(
        &self,
        id: &str,
        name: &str,
        my_name: &str,
        upstream_addr: &str,
        token_plain: Option<&str>,
        sni_hostname: &str,
        insecure: bool,
        ca_cert_path: &str,
        pinned_cert_path: &str,
        pinned_fingerprint: &str,
        advertise: &str,
        group_id: Option<&str>,
        remark: &str,
    ) -> Result<()> {
        let token_enc = match token_plain {
            Some(t) => self.encrypt_secret(t)?,
            None => {
                self.get_connector(id)?
                    .ok_or_else(|| Error::Other("connector not found".into()))?
                    .token_enc
            }
        };
        let conn = self.conn();
        conn.execute(
            "UPDATE connector SET name = ?1, my_name = ?2, upstream_addr = ?3, token_enc = ?4, sni_hostname = ?5,
                    insecure = ?6, ca_cert_path = ?7, pinned_cert_path = ?8, pinned_fingerprint = ?9, advertise = ?10, group_id = ?11, remark = ?12, updated_at = ?13
             WHERE id = ?14",
            params![name, my_name, upstream_addr, token_enc, sni_hostname, insecure as i32, ca_cert_path, pinned_cert_path, pinned_fingerprint, advertise, group_id, remark, now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn set_connector_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE connector SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            params![enabled as i32, now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn delete_connector(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM connector WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// Initial import of TOML `[[connectors]]`: skip names that already exist (DB is the source of truth at runtime).
    #[allow(clippy::too_many_arguments)]
    pub fn import_connector_if_absent(
        &self,
        name: &str,
        upstream_addr: &str,
        token_plain: &str,
        sni_hostname: &str,
        insecure: bool,
        ca_cert_path: &str,
        pinned_cert_path: &str,
        advertise: &str,
        group_id: Option<&str>,
        remark: &str,
    ) -> Result<bool> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM connector WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if count > 0 {
            return Ok(false);
        }
        drop(conn);
        self.create_connector(
            name,
            "",
            upstream_addr,
            token_plain,
            sni_hostname,
            insecure,
            ca_cert_path,
            pinned_cert_path,
            "",
            advertise,
            group_id,
            remark,
        )?;
        Ok(true)
    }

    // ==================== Fan-out token encrypted storage (the only reversible exception, §5) ====================

    /// AES-256-GCM encrypt a sensitive credential; storage format `v1:nonce_b64:ct_b64`.
    /// Machine key generated on first use (32 random bytes, hex), stored in node_config.connector_token_key.
    pub fn encrypt_secret(&self, plain: &str) -> Result<String> {
        let key = self.connector_token_key()?;
        let nonce_bytes: [u8; 12] = rand::random();
        let mut in_out = plain.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
            ring::aead::Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| Error::Other("encrypt_secret failed".into()))?;
        Ok(format!(
            "v1:{}:{}",
            b64_encode(&nonce_bytes),
            b64_encode(&in_out)
        ))
    }

    /// Decrypt `v1:` ciphertext (version mismatch / wrong key both error; errors never contain plaintext/ciphertext).
    pub fn decrypt_secret(&self, enc: &str) -> Result<String> {
        let mut parts = enc.splitn(3, ':');
        let (ver, nonce_b64, ct_b64) = match (parts.next(), parts.next(), parts.next()) {
            (Some(v), Some(n), Some(c)) => (v, n, c),
            _ => return Err(Error::Other("secret format invalid".into())),
        };
        if ver != "v1" {
            return Err(Error::Other("secret version unsupported".into()));
        }
        let nonce_raw = b64_decode(nonce_b64)?;
        let nonce_bytes: [u8; 12] = nonce_raw
            .try_into()
            .map_err(|_| Error::Other("secret nonce invalid".into()))?;
        let mut in_out = b64_decode(ct_b64)?;
        let key = self.connector_token_key()?;
        let plain = key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                ring::aead::Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| Error::Other("secret decrypt failed".into()))?;
        String::from_utf8(plain.to_vec()).map_err(|e| Error::Other(e.to_string()))
    }

    /// Load or generate the fan-out token machine key (same mechanism as jwt_secret).
    fn connector_token_key(&self) -> Result<ring::aead::LessSafeKey> {
        let hex_key = match self.get_config("connector_token_key")? {
            Some(k) if !k.is_empty() => k,
            _ => {
                let k = generate_secret_hex();
                self.set_config("connector_token_key", &k)?;
                k
            }
        };
        let bytes = hex_decode(&hex_key)?;
        let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &bytes)
            .map_err(|_| Error::Other("connector_token_key invalid".into()))?;
        Ok(ring::aead::LessSafeKey::new(unbound))
    }

    // ==================== Node Config ====================

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT value FROM node_config WHERE key = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![key]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(r.get(0).map_err(db_err)?),
            None => None,
        })
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO node_config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Bump the config version (called on rule/group changes)
    pub fn bump_config_version(&self) -> Result<u64> {
        let current = self.get_config("config_version")?;
        let next = current.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) + 1;
        self.set_config("config_version", &next.to_string())?;
        Ok(next)
    }

    pub fn config_version(&self) -> Result<u64> {
        Ok(self
            .get_config("config_version")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }
}

/// hex decode (for the connector machine key)
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Other("hex length invalid".into()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| Error::Other(e.to_string()))
        })
        .collect()
}

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::Other(e.to_string()))
}

/// Token prefix for display (first 8 chars, list identification only)
fn token_prefix_of(plain: &str) -> String {
    plain.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a group, return its id
    fn mk_group(db: &Database, name: &str) -> String {
        db.create_group(name, "").expect("create group").id
    }

    #[test]
    fn secret_encrypt_decrypt_roundtrip() {
        let db = Database::in_memory().unwrap();
        let plain = "psk_0123456789abcdef0123456789abcdef0123456789abcdef";
        let enc1 = db.encrypt_secret(plain).unwrap();
        let enc2 = db.encrypt_secret(plain).unwrap();
        // Random nonce: same plaintext encrypts differently each time, with version prefix
        assert_ne!(enc1, enc2);
        assert!(enc1.starts_with("v1:"));
        assert_eq!(db.decrypt_secret(&enc1).unwrap(), plain);
        assert_eq!(db.decrypt_secret(&enc2).unwrap(), plain);
        // Machine key persisted to node_config
        assert!(
            db.get_config("connector_token_key")
                .unwrap()
                .is_some_and(|k| k.len() == 64)
        );
        // Bad format / version / ciphertext all error
        assert!(db.decrypt_secret("garbage").is_err());
        assert!(db.decrypt_secret("v2:AAAA:BBBB").is_err());
        assert!(db.decrypt_secret("v1:AAAA:BBBB").is_err());
        // A different key cannot decrypt (another DB instance)
        let db2 = Database::in_memory().unwrap();
        assert!(db2.decrypt_secret(&enc1).is_err());
    }

    #[test]
    fn connector_crud_full_path() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "peers");
        let token = "psk_connector-token-0123456789abcdef";

        // create
        let rec = db
            .create_connector(
                "site-a",
                "机房 A 机",
                "1.2.3.4:54430",
                token,
                "a.example.com",
                false,
                "/etc/anet/ca.pem",
                "",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "10.0.0.0/8",
                Some(&gid),
                "站点 A",
            )
            .expect("create connector");
        assert!(rec.enabled);
        assert_eq!(rec.my_name, "机房 A 机");
        assert_eq!(rec.group_id.as_deref(), Some(gid.as_str()));
        assert_eq!(rec.ca_cert_path, "/etc/anet/ca.pem");
        assert_eq!(rec.pinned_cert_path, "");
        assert_eq!(
            rec.pinned_fingerprint,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        // Stored as ciphertext: not plaintext, with version prefix
        assert!(rec.token_enc.starts_with("v1:"));
        assert!(!rec.token_enc.contains(token));

        // get / get_connector_secret (decrypts back to plaintext)
        let got = db.get_connector(&rec.id).unwrap().expect("get connector");
        assert_eq!(got.name, "site-a");
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token);

        // list (view carries the resolved group set and prefix display, no plaintext/ciphertext)
        let views = db.list_connectors().unwrap();
        assert_eq!(views.len(), 1);
        let v = &views[0];
        assert_eq!(v.groups.len(), 1);
        assert_eq!(v.groups[0].name, "peers");
        assert!(v.groups[0].adopted_node.is_empty());
        assert_eq!(v.token_prefix, "psk_conn");
        let json = serde_json::to_string(v).unwrap();
        assert!(!json.contains(token));
        assert!(!json.contains("token_enc"));
        assert_eq!(v.my_name, "机房 A 机");

        // update: token None = keep existing token; all other fields change
        db.update_connector(
            &rec.id,
            "site-a2",
            "",
            "5.6.7.8:54430",
            None,
            "",
            true,
            "",
            "/etc/anet/pinned.pem",
            "",
            "",
            None,
            "改名",
        )
        .expect("update keep token");
        let got = db.get_connector(&rec.id).unwrap().unwrap();
        assert_eq!(got.name, "site-a2");
        assert_eq!(got.my_name, "");
        assert!(got.insecure);
        assert_eq!(got.ca_cert_path, "");
        assert_eq!(got.pinned_cert_path, "/etc/anet/pinned.pem");
        assert_eq!(got.pinned_fingerprint, "");
        assert_eq!(got.group_id, None);
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token);

        // update: explicit token reset
        let token2 = "psk_rotated-token-abcdef0123456789";
        db.update_connector(
            &rec.id,
            "site-a2",
            "",
            "5.6.7.8:54430",
            Some(token2),
            "",
            true,
            "",
            "",
            "",
            "",
            None,
            "",
        )
        .expect("update rotate token");
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token2);

        // set_enabled / delete
        db.set_connector_enabled(&rec.id, false).expect("disable");
        assert!(!db.get_connector(&rec.id).unwrap().unwrap().enabled);
        db.delete_connector(&rec.id).expect("delete");
        assert!(db.get_connector(&rec.id).unwrap().is_none());
        assert!(db.list_connectors().unwrap().is_empty());
    }

    #[test]
    fn import_connector_if_absent_skips_existing() {
        let db = Database::in_memory().unwrap();
        let first = db
            .import_connector_if_absent(
                "site-a",
                "1.2.3.4:54430",
                "psk_first",
                "",
                false,
                "",
                "",
                "",
                None,
                "toml 导入",
            )
            .expect("first import");
        assert!(first);
        // Existing name skipped; the original record is not overwritten
        let second = db
            .import_connector_if_absent(
                "site-a",
                "9.9.9.9:54430",
                "psk_second",
                "",
                false,
                "",
                "",
                "",
                None,
                "",
            )
            .expect("second import");
        assert!(!second);
        let views = db.list_connectors().unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].upstream_addr, "1.2.3.4:54430");
    }
}
