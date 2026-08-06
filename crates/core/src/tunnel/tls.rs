//! TLS 1.3 config builder
//!
//! Builds ServerConfig / ClientConfig with support for:
//! - automatic self-signed cert generation (development)
//! - external cert loading (production)
//! - SNI hostname camouflage

use crate::error::{Error, Result};
use crate::util::base64_encode;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::path::PathBuf;
use std::sync::Arc;

/// TLS config builder.
pub struct TlsConfigBuilder {
    /// Server cert path (listener mode)
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    /// Client custom CA root certs (connector mode)
    ca_cert: Option<Vec<CertificateDer<'static>>>,
    /// Server cert pinning: trust only the listed certs (connector mode)
    pinned_certs: Option<Vec<CertificateDer<'static>>>,
    /// Server cert SHA-256 fingerprint pinning (connector mode, one-click distribution via connect_url)
    pinned_fingerprint: Option<String>,
    /// SNI hostname (connector mode, camouflage)
    pub sni_hostname: String,
    /// Whether self-signed certs are allowed (dev mode)
    allow_self_signed: bool,
}

impl TlsConfigBuilder {
    pub fn new() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            ca_cert: None,
            pinned_certs: None,
            pinned_fingerprint: None,
            sni_hostname: "cdn.cloudflare.com".into(),
            allow_self_signed: false,
        }
    }

    pub fn cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cert_path = Some(path.into());
        self
    }

    pub fn key_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.key_path = Some(path.into());
        self
    }

    pub fn ca_certs(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        self.ca_cert = Some(certs);
        self
    }

    /// Cert pinning: trust only the given server certs (equivalent to pinning the peer cert into the root store).
    ///
    /// Recommended MITM resistance for private deployments — the node cert fingerprint is distributed out-of-band.
    pub fn pinned_certs(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        if !certs.is_empty() {
            self.pinned_certs = Some(certs);
        }
        self
    }

    /// Cert fingerprint pinning (SHA-256 hex, lightweight pinning distributed via connect_url).
    pub fn pinned_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.pinned_fingerprint = Some(fingerprint.into());
        self
    }

    pub fn sni_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.sni_hostname = hostname.into();
        self
    }

    pub fn allow_self_signed(mut self, allow: bool) -> Self {
        self.allow_self_signed = allow;
        self
    }

    /// Build a rustls ServerConfig (listener).
    ///
    /// Generates a self-signed cert when no cert path is configured.
    pub fn build_server(
        &self,
    ) -> Result<(Arc<rustls::ServerConfig>, Vec<CertificateDer<'static>>)> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (certs, key) =
            if let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) {
                load_certs_from_file(cert_path, key_path)?
            } else {
                generate_self_signed(&self.sni_hostname)?
            };

        let mut server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certs.clone(), key)
                .map_err(|e| Error::Tls(e.to_string()))?;
        // ALPN mimicry: a real browser ClientHello always carries h2/http1.1; empty ALPN is the cheapest single-field DPI filter
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok((Arc::new(server_config), certs))
    }

    /// Build a rustls ClientConfig (connector).
    ///
    /// Trust policy precedence: cert pinning > custom CA > skip verification (dev) > system CA.
    pub fn build_client(&self) -> Result<Arc<rustls::ClientConfig>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = if let Some(fp) = &self.pinned_fingerprint {
            // fingerprint pinning: hash comparison + rustls native signature check; MITM-resistant without distributing cert files
            let verifier = danger::PinnedFingerprintVerifier::new(fp)?;
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else if let Some(pinned) = &self.pinned_certs {
            // cert pinning: the pinned certs act as the only trust roots, MITM-resistant
            let mut root_store = rustls::RootCertStore::empty();
            for cert in pinned {
                root_store
                    .add(cert.clone())
                    .map_err(|e| Error::Tls(format!("failed to pin cert: {e}")))?;
            }
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else if let Some(ca_certs) = &self.ca_cert {
            // use custom CA
            let mut root_store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                root_store
                    .add(cert.clone())
                    .map_err(|e| Error::Tls(format!("failed to add CA cert: {e}")))?;
            }
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else if self.allow_self_signed {
            // dev mode: trust all certs (debug only, forbidden in production)
            let verifier = danger::NoCertificateVerification::new();
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else {
            // default: CA list embedded via webpki-roots
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // ALPN mimicry (same list as the server; ALPN-less peers still handshake fine)
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// Get the ServerName for a TLS connection.
    pub fn server_name(&self) -> Result<ServerName<'static>> {
        ServerName::try_from(self.sni_hostname.clone())
            .map_err(|e| Error::Tls(format!("invalid SNI hostname: {e}")))
    }
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Load cert and private key from PEM files.
fn load_certs_from_file(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_data =
        std::fs::read(cert_path).map_err(|e| Error::Tls(format!("read cert file: {e}")))?;
    let key_data =
        std::fs::read(key_path).map_err(|e| Error::Tls(format!("read key file: {e}")))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("parse cert PEM: {e}")))?;

    if certs.is_empty() {
        return Err(Error::Tls("no certificates found in PEM file".into()));
    }

    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| Error::Tls(format!("parse key PEM: {e}")))?
        .ok_or_else(|| Error::Tls("no private key found in PEM file".into()))?;

    Ok((certs, key))
}

/// Generate a self-signed cert (development).
pub fn generate_self_signed(
    hostname: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut params = CertificateParams::new(vec![hostname.to_string()])
        .map_err(|e| Error::Tls(format!("cert params: {e}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    // Subject mimicry: empty O/C fields are a strong homebrew-tunnel fingerprint; mimic a normal CDN cert
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Cloudflare, Inc.");
    params
        .distinguished_name
        .push(rcgen::DnType::CountryName, "US");
    // randomized expiry (random date in 2032-2038): a uniform 2036-01-01 across all nodes is a
    // correlation marker for large-scale scans; persisted existing certs are unaffected
    // (load_or_generate only reaches here on first generation)
    let year = (2032 + rand::random::<u32>() % 7) as i32;
    let month = (1 + rand::random::<u32>() % 12) as u8;
    let day = (1 + rand::random::<u32>() % 28) as u8;
    params.not_after = rcgen::date_time_ymd(year, month, day);

    let key_pair = KeyPair::generate().map_err(|e| Error::Tls(format!("keygen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Tls(format!("self-sign: {e}")))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}

/// Load an existing cert, or generate a self-signed one and persist it to disk (PEM).
///
/// Persistence keeps the cert stable across node restarts so clients can pin it reliably.
pub fn load_or_generate_self_signed(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    hostname: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if cert_path.exists() && key_path.exists() {
        return load_certs_from_file(&cert_path.to_path_buf(), &key_path.to_path_buf());
    }

    let (certs, key) = generate_self_signed(hostname)?;

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::Tls(format!("create cert dir: {e}")))?;
    }

    // write PEM
    let cert_pem = certs
        .iter()
        .map(|c| {
            let b64 = base64_encode(c.as_ref());
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                wrap64(&b64)
            )
        })
        .collect::<String>();
    std::fs::write(cert_path, cert_pem).map_err(|e| Error::Tls(format!("write cert: {e}")))?;

    let key_b64 = base64_encode(key.secret_der());
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        wrap64(&key_b64)
    );
    std::fs::write(key_path, key_pem).map_err(|e| Error::Tls(format!("write key: {e}")))?;

    // tighten private key file permissions (Unix 0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok((certs, key))
}

/// Compute a cert's SHA-256 fingerprint (hex, for distributing pinning configs).
pub fn cert_fingerprint_sha256(cert: &CertificateDer<'_>) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(cert.as_ref());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wrap PEM base64 at 64 columns.
fn wrap64(b64: &str) -> String {
    b64.as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Dangerous cert verifiers — dev mode, skips all verification.
mod danger {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    /// Cert SHA-256 fingerprint pinning verifier.
    ///
    /// Security argument: the hash comparison confirms the peer presents the target cert
    /// (public key); the TLS handshake CertificateVerify is natively verified by rustls
    /// (proving private-key possession). Together this is equivalent to cert pinning,
    /// MITM-resistant, and needs no cert file distribution.
    #[derive(Debug)]
    pub(super) struct PinnedFingerprintVerifier {
        expected: [u8; 32],
    }

    impl PinnedFingerprintVerifier {
        pub(super) fn new(fingerprint_hex: &str) -> crate::error::Result<Self> {
            let fp = fingerprint_hex.trim().to_lowercase();
            if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(crate::error::Error::Tls(
                    "invalid certificate fingerprint (expect 64 hex chars)".into(),
                ));
            }
            let mut expected = [0u8; 32];
            for (i, b) in expected.iter_mut().enumerate() {
                *b = u8::from_str_radix(&fp[i * 2..i * 2 + 2], 16)
                    .map_err(|e| crate::error::Error::Tls(e.to_string()))?;
            }
            Ok(Self { expected })
        }
    }

    impl ServerCertVerifier for PinnedFingerprintVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(end_entity.as_ref());
            if digest.as_slice() == self.expected {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            let algs = &rustls::crypto::ring::default_provider().signature_verification_algorithms;
            rustls::crypto::verify_tls12_signature(message, cert, dss, algs)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            let algs = &rustls::crypto::ring::default_provider().signature_verification_algorithms;
            rustls::crypto::verify_tls13_signature(message, cert, dss, algs)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }

    #[derive(Debug)]
    pub(super) struct NoCertificateVerification;

    impl NoCertificateVerification {
        pub(super) fn new() -> Self {
            Self
        }
    }

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_generation() {
        let (certs, _key) = generate_self_signed("test.example.com").unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
    }

    #[test]
    fn build_server_config_self_signed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let builder = TlsConfigBuilder::new().sni_hostname("test.example.com");
        let (config, certs) = builder.build_server().unwrap();
        assert!(!certs.is_empty());
        // ServerConfig created successfully
        let _ = config;
    }

    #[test]
    fn build_client_config_self_signed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let builder = TlsConfigBuilder::new()
            .allow_self_signed(true)
            .sni_hostname("test.example.com");
        let config = builder.build_client().unwrap();
        let _ = config;
    }
}
