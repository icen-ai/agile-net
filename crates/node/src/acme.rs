//! ACME automatic certificate management (Let's Encrypt etc., RFC 8555 + TLS-ALPN-01 RFC 8737).
//!
//! Design notes:
//! - The TLS-ALPN-01 challenge is **multiplexed on the same port** as the relay listener:
//!   via a custom `ResolvesServerCert`, connections with ALPN `acme-tls/1` get the
//!   challenge certificate, everything else gets the production certificate —
//!   issuance/renewal never interrupts the data plane.
//! - Account credentials persist in node_config (`acme.account`); certificates are
//!   written to certs/ and hot-swapped.
//! - Checked every 12h: auto-renew once (90 - renew_days) days have passed since issuance.

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

/// ACME configuration (the [acme] section of agile-net.toml).
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domain: String,
    pub email: String,
    pub staging: bool,
    /// Renew this many days before expiry (default 30).
    pub renew_days: u32,
    /// Custom CA directory (default Let's Encrypt).
    pub directory_url: Option<String>,
    /// Certificate/private key storage paths.
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

// ==================== ALPN-multiplexing cert resolver ====================

/// Certificate resolver that multiplexes by ALPN protocol.
///
/// - ALPN contains `acme-tls/1` and a challenge certificate exists → challenge certificate (ACME TLS-ALPN-01 validation)
/// - otherwise → the current production certificate (relay data plane)
pub struct AlpnCertResolver {
    current: arc_swap::ArcSwap<CertifiedKey>,
    challenge: arc_swap::ArcSwapOption<CertifiedKey>,
}

impl AlpnCertResolver {
    /// Create a resolver with the initial production certificate.
    pub fn new(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Arc<Self>> {
        let certified = make_certified_key(certs, key)?;
        Ok(Arc::new(Self {
            current: arc_swap::ArcSwap::from_pointee(certified),
            challenge: arc_swap::ArcSwapOption::from_pointee(None),
        }))
    }

    /// Hot-swap the production certificate (called after renewal).
    pub fn swap_current(
        &self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<()> {
        let certified = make_certified_key(certs, key)?;
        self.current.store(Arc::new(certified));
        Ok(())
    }

    /// Set/clear the TLS-ALPN-01 challenge certificate.
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
        if wants_acme && let Some(challenge) = self.challenge.load_full() {
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

// ==================== TLS-ALPN-01 challenge certificate ====================

/// Generate the TLS-ALPN-01 challenge certificate (with the critical acmeIdentifier extension).
fn tls_alpn_challenge_cert(
    domain: &str,
    key_authorization: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(key_authorization.as_bytes());

    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| Error::Tls(format!("challenge cert params: {e}")))?;
    // rcgen built-in ACME TLS-ALPN-01 extension construction (acmeIdentifier, critical)
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(&digest)];

    let key_pair = rcgen::KeyPair::generate().map_err(|e| Error::Tls(format!("keygen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Tls(format!("challenge self-sign: {e}")))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((vec![cert_der], key_der))
}

// ==================== ACME manager ====================

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

    /// Run forever: attempt issuance at startup (if needed), then renew periodically.
    pub async fn run(self: Arc<Self>) {
        // At startup: certificate missing or last issuance too long ago → issue immediately.
        if self.needs_issuance()
            && let Err(e) = self.issue().await
        {
            warn!(error = %e, "ACME initial issuance failed (继续使用现有证书)");
        }
        // Periodic renewal check.
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

    /// Whether issuance/renewal is needed: cert files missing, or more than (90 - renew_days) days since issuance.
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
            None => false, // cert files exist but were not issued by this system → never auto-replace
        }
    }

    /// Run one full issuance flow.
    pub async fn issue(&self) -> Result<()> {
        let domain = self.config.domain.clone();
        info!(domain = %domain, directory = %self.directory_url(), "ACME issuance started");

        // 1. Account (credentials persisted and reused)
        let account = self.load_or_create_account().await?;

        // 2. New order
        let mut order = account
            .new_order(&NewOrder::new(&[Identifier::Dns(domain.clone())]))
            .await
            .map_err(|e| Error::Other(format!("acme new order: {e}")))?;

        // 3. TLS-ALPN-01 challenge
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

        // Challenge cleanup (success or failure)
        let cleanup = |m: &AcmeManager| {
            let _ = m.resolver.set_challenge(None);
        };

        // 4. Wait for the order to become ready
        if let Err(e) = order.poll_ready(&RetryPolicy::default()).await {
            cleanup(self);
            return Err(Error::Other(format!("acme poll ready: {e}")));
        }

        // 5. Finalize and fetch the certificate chain
        let key_pem = order
            .finalize()
            .await
            .map_err(|e| Error::Other(format!("acme finalize: {e}")))?;
        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| Error::Other(format!("acme poll certificate: {e}")))?;
        cleanup(self);

        // 6. Persist to disk + hot-swap
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
            let _ = std::fs::set_permissions(
                &self.config.key_path,
                std::fs::Permissions::from_mode(0o600),
            );
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

    /// Load or create the ACME account (credentials JSON persisted in node_config).
    async fn load_or_create_account(&self) -> Result<Account> {
        let directory = self.directory_url();
        if let Some(json) = self.db.get_config("acme.account")? {
            let credentials: instant_acme::AccountCredentials = serde_json::from_str(&json)
                .map_err(|e| Error::Other(format!("acme account parse: {e}")))?;
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
        // The cert DER should contain the acmeIdentifier OID (1.3.6.1.5.5.7.1.31)
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

        // Without a challenge certificate, the production certificate is returned
        assert!(resolver.challenge.load().is_none());
        assert!(resolver.current.load().cert.len() == 1);

        // Challenge certificate can be set/cleared
        let (ccerts, ckey) = generate_self_signed("acme.example.com").unwrap();
        resolver.set_challenge(Some((ccerts, ckey))).unwrap();
        assert!(resolver.challenge.load().is_some());
        resolver.set_challenge(None).unwrap();
        assert!(resolver.challenge.load().is_none());
    }
}
