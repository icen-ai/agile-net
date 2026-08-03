//! 从 db/mod.rs 拆分：connector/node_config 表与扇出 token 加密存储（纯搬运，零逻辑变更）

use super::generate_secret_hex;
use super::models::*;
use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::{Error, Result};
use rusqlite::params;

impl Database {
    // ==================== Connector（扇出，一等资源） ====================

    /// 创建扇出 connector（token 加密落库，创建后亦不回显，只允许重置）。
    #[allow(clippy::too_many_arguments)]
    pub fn create_connector(
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
    ) -> Result<ConnectorRecord> {
        let token_enc = self.encrypt_secret(token_plain)?;
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO connector (id, name, upstream_addr, token_enc, sni_hostname, insecure, ca_cert_path, pinned_cert_path, advertise, group_id, enabled, remark, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,?12)",
            params![id, name, upstream_addr, token_enc, sni_hostname, insecure as i32, ca_cert_path, pinned_cert_path, advertise, group_id, remark, now],
        )
        .map_err(db_err)?;
        Ok(ConnectorRecord {
            id,
            name: name.to_string(),
            upstream_addr: upstream_addr.to_string(),
            token_enc,
            sni_hostname: sni_hostname.to_string(),
            insecure,
            ca_cert_path: ca_cert_path.to_string(),
            pinned_cert_path: pinned_cert_path.to_string(),
            advertise: advertise.to_string(),
            group_id: group_id.map(|g| g.to_string()),
            enabled: true,
            remark: remark.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// 列出全部扇出 connector（展示视图，绝不含 token 明文/密文）。
    pub fn list_connectors(&self) -> Result<Vec<ConnectorView>> {
        // 先取出全部行并归还连接（内存库连接池为 1，解密需再次取连接）
        let recs = {
            let conn = self.conn();
            let mut stmt = conn
                .prepare(
                    "SELECT c.id, c.name, c.upstream_addr, c.token_enc, c.sni_hostname, c.insecure, c.ca_cert_path, c.pinned_cert_path, c.advertise,
                            c.group_id, g.name, c.enabled, c.remark, c.created_at, c.updated_at
                     FROM connector c LEFT JOIN \"group\" g ON c.group_id = g.id ORDER BY c.created_at DESC",
                )
                .map_err(db_err)?;
            let mut rows = stmt.query([]).map_err(db_err)?;
            let mut recs = Vec::new();
            while let Some(r) = rows.next().map_err(db_err)? {
                let rec = ConnectorRecord {
                    id: r.get(0).map_err(db_err)?,
                    name: r.get(1).map_err(db_err)?,
                    upstream_addr: r.get(2).map_err(db_err)?,
                    token_enc: r.get(3).map_err(db_err)?,
                    sni_hostname: r.get(4).map_err(db_err)?,
                    insecure: r.get::<_, i32>(5).map_err(db_err)? != 0,
                    ca_cert_path: r.get(6).map_err(db_err)?,
                    pinned_cert_path: r.get(7).map_err(db_err)?,
                    advertise: r.get(8).map_err(db_err)?,
                    group_id: r.get(9).map_err(db_err)?,
                    enabled: r.get::<_, i32>(11).map_err(db_err)? != 0,
                    remark: r.get(12).map_err(db_err)?,
                    created_at: r.get(13).map_err(db_err)?,
                    updated_at: r.get(14).map_err(db_err)?,
                };
                let group_name: Option<String> = r.get(10).map_err(db_err)?;
                recs.push((rec, group_name));
            }
            recs
        };
        let mut items = Vec::new();
        for (rec, group_name) in recs {
            // 前缀展示位：解密取前 8 字符仅用于辨认；解密失败（密钥轮换等）留空
            let token_prefix = self
                .decrypt_secret(&rec.token_enc)
                .map(|t| token_prefix_of(&t))
                .unwrap_or_default();
            items.push(ConnectorView {
                id: rec.id,
                name: rec.name,
                upstream_addr: rec.upstream_addr,
                token_prefix,
                sni_hostname: rec.sni_hostname,
                insecure: rec.insecure,
                ca_cert_path: rec.ca_cert_path,
                pinned_cert_path: rec.pinned_cert_path,
                advertise: rec.advertise,
                group_id: rec.group_id,
                group_name,
                enabled: rec.enabled,
                remark: rec.remark,
                created_at: rec.created_at,
                updated_at: rec.updated_at,
            });
        }
        Ok(items)
    }

    /// 按 ID 取 connector 记录（含密文，仅供内部使用，严禁日志/审计输出）。
    pub fn get_connector(&self, id: &str) -> Result<Option<ConnectorRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, upstream_addr, token_enc, sni_hostname, insecure, ca_cert_path, pinned_cert_path, advertise, group_id, enabled, remark, created_at, updated_at
                 FROM connector WHERE id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(ConnectorRecord {
                id: r.get(0).map_err(db_err)?,
                name: r.get(1).map_err(db_err)?,
                upstream_addr: r.get(2).map_err(db_err)?,
                token_enc: r.get(3).map_err(db_err)?,
                sni_hostname: r.get(4).map_err(db_err)?,
                insecure: r.get::<_, i32>(5).map_err(db_err)? != 0,
                ca_cert_path: r.get(6).map_err(db_err)?,
                pinned_cert_path: r.get(7).map_err(db_err)?,
                advertise: r.get(8).map_err(db_err)?,
                group_id: r.get(9).map_err(db_err)?,
                enabled: r.get::<_, i32>(10).map_err(db_err)? != 0,
                remark: r.get(11).map_err(db_err)?,
                created_at: r.get(12).map_err(db_err)?,
                updated_at: r.get(13).map_err(db_err)?,
            }),
            None => None,
        })
    }

    /// 按 ID 取 connector 的扇出 token 明文（解密，仅供运行时连接用；严禁日志/审计输出）。
    pub fn get_connector_secret(&self, id: &str) -> Result<String> {
        let rec = self
            .get_connector(id)?
            .ok_or_else(|| Error::Other("connector not found".into()))?;
        self.decrypt_secret(&rec.token_enc)
    }

    /// 更新 connector（token_plain 为 None = 保留原 token）。
    #[allow(clippy::too_many_arguments)]
    pub fn update_connector(
        &self,
        id: &str,
        name: &str,
        upstream_addr: &str,
        token_plain: Option<&str>,
        sni_hostname: &str,
        insecure: bool,
        ca_cert_path: &str,
        pinned_cert_path: &str,
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
            "UPDATE connector SET name = ?1, upstream_addr = ?2, token_enc = ?3, sni_hostname = ?4,
                    insecure = ?5, ca_cert_path = ?6, pinned_cert_path = ?7, advertise = ?8, group_id = ?9, remark = ?10, updated_at = ?11
             WHERE id = ?12",
            params![name, upstream_addr, token_enc, sni_hostname, insecure as i32, ca_cert_path, pinned_cert_path, advertise, group_id, remark, now_rfc3339(), id],
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

    /// TOML `[[connectors]]` 初始导入：同名已存在则跳过（运行时以 DB 为准）。
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
            upstream_addr,
            token_plain,
            sni_hostname,
            insecure,
            ca_cert_path,
            pinned_cert_path,
            advertise,
            group_id,
            remark,
        )?;
        Ok(true)
    }

    // ==================== 扇出 token 加密存储（全库唯一可逆例外，§5） ====================

    /// AES-256-GCM 加密敏感凭据，落库格式 `v1:nonce_b64:ct_b64`。
    /// 机器密钥首用生成（32 随机字节 hex），存 node_config.connector_token_key。
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

    /// 解密 `v1:` 格式密文（版本不符/密钥错误均报错；错误信息不含明文/密文）。
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

    /// 装载或生成扇出 token 机器密钥（与 jwt_secret 同机制）。
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

    /// 配置版本号递增（规则/权限组/账号组变更时调用）
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

/// hex 解码（connector 机器密钥用）
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

/// token 前缀展示位（前 8 字符，仅用于列表辨认）
fn token_prefix_of(plain: &str) -> String {
    plain.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建一个权限组，返回 id
    fn mk_group(db: &Database, name: &str) -> String {
        db.create_group(name, "").expect("create group").id
    }

    #[test]
    fn secret_encrypt_decrypt_roundtrip() {
        let db = Database::in_memory().unwrap();
        let plain = "psk_0123456789abcdef0123456789abcdef0123456789abcdef";
        let enc1 = db.encrypt_secret(plain).unwrap();
        let enc2 = db.encrypt_secret(plain).unwrap();
        // 随机 nonce：同明文两次密文不同，且带版本前缀
        assert_ne!(enc1, enc2);
        assert!(enc1.starts_with("v1:"));
        assert_eq!(db.decrypt_secret(&enc1).unwrap(), plain);
        assert_eq!(db.decrypt_secret(&enc2).unwrap(), plain);
        // 机器密钥已持久化到 node_config
        assert!(
            db.get_config("connector_token_key")
                .unwrap()
                .is_some_and(|k| k.len() == 64)
        );
        // 非法格式/版本/密文均报错
        assert!(db.decrypt_secret("garbage").is_err());
        assert!(db.decrypt_secret("v2:AAAA:BBBB").is_err());
        assert!(db.decrypt_secret("v1:AAAA:BBBB").is_err());
        // 密钥不同则无法解密（另一库实例）
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
                "1.2.3.4:54430",
                token,
                "a.example.com",
                false,
                "/etc/anet/ca.pem",
                "",
                "10.0.0.0/8",
                Some(&gid),
                "站点 A",
            )
            .expect("create connector");
        assert!(rec.enabled);
        assert_eq!(rec.group_id.as_deref(), Some(gid.as_str()));
        assert_eq!(rec.ca_cert_path, "/etc/anet/ca.pem");
        assert_eq!(rec.pinned_cert_path, "");
        // 密文落库：不是明文、带版本前缀
        assert!(rec.token_enc.starts_with("v1:"));
        assert!(!rec.token_enc.contains(token));

        // get / get_connector_secret（解密回明文）
        let got = db.get_connector(&rec.id).unwrap().expect("get connector");
        assert_eq!(got.name, "site-a");
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token);

        // list（视图带组名与前缀展示位，不含明文/密文）
        let views = db.list_connectors().unwrap();
        assert_eq!(views.len(), 1);
        let v = &views[0];
        assert_eq!(v.group_name.as_deref(), Some("peers"));
        assert_eq!(v.token_prefix, "psk_conn");
        let json = serde_json::to_string(v).unwrap();
        assert!(!json.contains(token));
        assert!(!json.contains("token_enc"));

        // update：token None = 保留原 token，其余字段全改
        db.update_connector(
            &rec.id,
            "site-a2",
            "5.6.7.8:54430",
            None,
            "",
            true,
            "",
            "/etc/anet/pinned.pem",
            "",
            None,
            "改名",
        )
        .expect("update keep token");
        let got = db.get_connector(&rec.id).unwrap().unwrap();
        assert_eq!(got.name, "site-a2");
        assert!(got.insecure);
        assert_eq!(got.ca_cert_path, "");
        assert_eq!(got.pinned_cert_path, "/etc/anet/pinned.pem");
        assert_eq!(got.group_id, None);
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token);

        // update：显式重置 token
        let token2 = "psk_rotated-token-abcdef0123456789";
        db.update_connector(
            &rec.id,
            "site-a2",
            "5.6.7.8:54430",
            Some(token2),
            "",
            true,
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
        // 同名存在则跳过，且原记录不被覆盖
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
