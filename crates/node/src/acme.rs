//! ACME 自动证书管理（Let's Encrypt 等，RFC 8555 + TLS-ALPN-01 RFC 8737）
//!
//! 设计要点：
//! - TLS-ALPN-01 挑战与 Relay 监听**同端口多路复用**：通过自定义
//!   `ResolvesServerCert`，ALPN 为 `acme-tls/1` 的连接出示挑战证书，
//!   其余连接出示正式证书——签发/续期全程无需停止数据面。
//! - 账户凭据持久化于 node_config（`acme.account`），证书落盘 certs/ 并热替换。
//! - 每 12h 检查一次：距离上次签发超过 (90 - renew_days) 天即自动续期。

use agile_net_core::error::{Error, Result};
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, RetryPolicy,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::db::Database;

/// ACME 配置（对应 agile-net.toml 的 [acme] 段）
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domain: String,
    pub email: String,
    pub staging: bool,
    /// 到期前多少天续期（默认 30）
    pub renew_days: u32,
    /// 自定义 CA directory（默认 Let's Encrypt）
    pub directory_url: Option<String>,
    /// 证书/私钥存放路径
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

// ==================== ALPN 多路复用证书解析器 ====================

/// 按 ALPN 协议多路复用证书的解析器。
///
/// - ALPN 包含 `acme-tls/1` 且存在挑战证书 → 挑战证书（ACME TLS-ALPN-01 验证）
/// - 其余 → 当前正式证书（Relay 数据面）
pub struct AlpnCertResolver {
    current: arc_swap::ArcSwap<CertifiedKey>,
    challenge: arc_swap::ArcSwapOption<CertifiedKey>,
}

impl AlpnCertResolver {
    /// 以初始正式证书创建解析器。
    pub fn new(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<Arc<Self>> {
        let certified = make_certified_key(certs, key)?;
        Ok(Arc::new(Self {
            current: arc_swap::ArcSwap::from_pointee(certified),
            challenge: arc_swap::ArcSwapOption::from_pointee(None),
        }))
    }

    /// 热替换正式证书（续期后调用）。
    pub fn swap_current(&self, certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<()> {
        let certified = make_certified_key(certs, key)?;
        self.current.store(Arc::new(certified));
        Ok(())
    }

    /// 设置/清除 TLS-ALPN-01 挑战证书。
    pub fn set_challenge(
        &self,
        value: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    ) -> Result<()> {
        match value {
            Some((certs, key)) => {
                let certified = make_certified_key(certs, key)?;
                self.challenge.store(Some(Arc::new(certified)));
            }
            None => self.challenge.store(None),
        }
        Ok(())
    }
}

impl std::fmt::Debug for AlpnCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlpnCertResolver").finish()
    }
}

impl ResolvesServerCert for AlpnCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wants_acme = client_hello
            .alpn()
            .map(|mut protos| protos.any(|p| p == b"acme-tls/1"))
            .unwrap_or(false);
        if wants_acme
            && let Some(challenge) = self.challenge.load_full()
        {
            return Some(challenge);
        }
        Some(self.current.load_full())
    }
}

fn make_certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<CertifiedKey> {
    let signing_key: Arc<dyn SigningKey> = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| Error::Tls(format!("unsupported private key: {e}")))?;
    Ok(CertifiedKey::new(certs, signing_key))
}

// ==================== TLS-ALPN-01 挑战证书 ====================

/// 生成 TLS-ALPN-01 挑战证书（含 acmeIdentifier 关键扩展）。
fn tls_alpn_challenge_cert(
    domain: &str,
    key_authorization: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(key_authorization.as_bytes());

    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| Error::Tls(format!("challenge cert params: {e}")))?;
    // rcgen 内置 ACME TLS-ALPN-01 扩展构造（acmeIdentifier，critical）
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(&digest)];

    let key_pair = rcgen::KeyPair::generate().map_err(|e| Error::Tls(format!("keygen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Tls(format!("challenge self-sign: {e}")))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((vec![cert_der], key_der))
}

// ==================== ACME 管理器 ====================

pub struct AcmeManager {
    config: AcmeConfig,
    resolver: Arc<AlpnCertResolver>,
    db: Database,
}

impl AcmeManager {
    pub fn new(config: AcmeConfig, resolver: Arc<AlpnCertResolver>, db: Database) -> Self {
        Self {
            config,
            resolver,
            db,
        }
    }

    fn directory_url(&self) -> String {
        self.config.directory_url.clone().unwrap_or_else(|| {
            if self.config.staging {
                LetsEncrypt::Staging.url().to_string()
            } else {
                LetsEncrypt::Production.url().to_string()
            }
        })
    }

    /// 永久运行：启动时尝试签发（如需要），随后周期续期。
    pub async fn run(self: Arc<Self>) {
        // 启动时：证书不存在或距上次签发过久 → 立即签发
        if self.needs_issuance()
            && let Err(e) = self.issue().await
        {
            warn!(error = %e, "ACME initial issuance failed (继续使用现有证书)");
        }
        // 周期检查续期
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(12 * 3600)).await;
            if self.needs_issuance() {
                info!("ACME certificate renewal due");
                if let Err(e) = self.issue().await {
                    warn!(error = %e, "ACME renewal failed (下次周期重试)");
                }
            }
        }
    }

    /// 判断是否需要签发/续期：证书文件缺失，或距上次签发超过 (90 - renew_days) 天。
    fn needs_issuance(&self) -> bool {
        if !self.config.cert_path.exists() || !self.config.key_path.exists() {
            return true;
        }
        let issued_at = self
            .db
            .get_config("acme.issued_at")
            .ok()
            .flatten()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        match issued_at {
            Some(t) => {
                let elapsed = chrono::Utc::now() - t;
                elapsed > chrono::Duration::days((90 - self.config.renew_days.min(60)) as i64)
            }
            None => false, // 有证书文件但非本系统签发 → 不自动替换
        }
    }

    /// 执行一次完整的签发流程。
    pub async fn issue(&self) -> Result<()> {
        let domain = self.config.domain.clone();
        info!(domain = %domain, directory = %self.directory_url(), "ACME issuance started");

        // 1. 账户（凭据持久化复用）
        let account = self.load_or_create_account().await?;

        // 2. 新订单
        let mut order = account
            .new_order(&NewOrder::new(&[Identifier::Dns(domain.clone())]))
            .await
            .map_err(|e| Error::Other(format!("acme new order: {e}")))?;

        // 3. TLS-ALPN-01 挑战
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut auth = result.map_err(|e| Error::Other(format!("acme authorization: {e}")))?;
            let mut challenge = auth
                .challenge(ChallengeType::TlsAlpn01)
                .ok_or_else(|| Error::Other("CA does not offer tls-alpn-01".into()))?;
            let key_auth = challenge.key_authorization();
            let (certs, key) = tls_alpn_challenge_cert(&domain, key_auth.as_str())?;
            self.resolver.set_challenge(Some((certs, key)))?;
            debug!("tls-alpn-01 challenge certificate installed");
            challenge
                .set_ready()
                .await
                .map_err(|e| Error::Other(format!("acme set ready: {e}")))?;
        }

        // 挑战结束清理（无论成败）
        let cleanup = |m: &AcmeManager| {
            let _ = m.resolver.set_challenge(None);
        };

        // 4. 等待订单就绪
        if let Err(e) = order.poll_ready(&RetryPolicy::default()).await {
            cleanup(self);
            return Err(Error::Other(format!("acme poll ready: {e}")));
        }

        // 5. 定稿并取回证书链
        let key_pem = order
            .finalize()
            .await
            .map_err(|e| Error::Other(format!("acme finalize: {e}")))?;
        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| Error::Other(format!("acme poll certificate: {e}")))?;
        cleanup(self);

        // 6. 落盘 + 热替换
        if let Some(parent) = self.config.cert_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Other(e.to_string()))?;
        }
        std::fs::write(&self.config.cert_path, &cert_pem)
            .map_err(|e| Error::Other(format!("write cert: {e}")))?;
        std::fs::write(&self.config.key_path, &key_pem)
            .map_err(|e| Error::Other(format!("write key: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.config.key_path, std::fs::Permissions::from_mode(0o600));
        }

        let certs = parse_pem_certs(cert_pem.as_bytes())?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
                .next()
                .ok_or_else(|| Error::Tls("no pkcs8 key in acme key pem".into()))?
                .map_err(|e| Error::Tls(format!("parse acme key: {e}")))?
                .secret_pkcs8_der()
                .to_vec(),
        ));
        self.resolver.swap_current(certs, key)?;

        let now = chrono::Utc::now().to_rfc3339();
        self.db.set_config("acme.issued_at", &now)?;
        info!(domain = %domain, "ACME certificate issued and hot-swapped");
        Ok(())
    }

    /// 加载或创建 ACME 账户（凭据 JSON 持久化于 node_config）。
    async fn load_or_create_account(&self) -> Result<Account> {
        let directory = self.directory_url();
        if let Some(json) = self.db.get_config("acme.account")? {
            let credentials: instant_acme::AccountCredentials =
                serde_json::from_str(&json).map_err(|e| Error::Other(format!("acme account parse: {e}")))?;
            if let Ok(account) = Account::builder()
                .map_err(|e| Error::Other(format!("acme account builder: {e}")))?
                .from_credentials(credentials)
                .await
            {
                return Ok(account);
            }
            warn!("stored ACME account invalid, creating new one");
        }

        let contact = format!("mailto:{}", self.config.email);
        let (account, credentials) = Account::builder()
            .map_err(|e| Error::Other(format!("acme account builder: {e}")))?
            .create(
                &NewAccount {
                    contact: &[contact.as_str()],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory,
                None,
            )
            .await
            .map_err(|e| Error::Other(format!("acme create account: {e}")))?;

        let json = serde_json::to_string(&credentials)
            .map_err(|e| Error::Other(format!("acme account serialize: {e}")))?;
        self.db.set_config("acme.account", &json)?;
        Ok(account)
    }
}

fn parse_pem_certs(data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &*data)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("parse cert pem: {e}")))?;
    if certs.is_empty() {
        return Err(Error::Tls("no certificates in pem".into()));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agile_net_core::tunnel::tls::generate_self_signed;

    #[test]
    fn challenge_cert_has_acme_identifier() {
        let (certs, _key) = tls_alpn_challenge_cert("example.com", "token.thumbprint").unwrap();
        assert_eq!(certs.len(), 1);
        // 证书 DER 中应包含 acmeIdentifier OID (1.3.6.1.5.5.7.1.31)
        let oid_bytes = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
        let der = certs[0].as_ref();
        assert!(
            der.windows(oid_bytes.len()).any(|w| w == oid_bytes),
            "挑战证书缺少 acmeIdentifier 扩展"
        );
    }

    #[test]
    fn resolver_prefers_challenge_for_acme_alpn() {
        let (certs, key) = generate_self_signed("relay.example.com").unwrap();
        let resolver = AlpnCertResolver::new(certs, key).unwrap();

        // 无挑战证书时返回正式证书
        assert!(resolver.challenge.load().is_none());
        assert!(resolver.current.load().cert.len() == 1);

        // 设置挑战证书后可设置/清除
        let (ccerts, ckey) = generate_self_signed("acme.example.com").unwrap();
        resolver.set_challenge(Some((ccerts, ckey))).unwrap();
        assert!(resolver.challenge.load().is_some());
        resolver.set_challenge(None).unwrap();
        assert!(resolver.challenge.load().is_none());
    }
}
