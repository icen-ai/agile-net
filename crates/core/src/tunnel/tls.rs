//! TLS 1.3 配置构建器
//!
//! 提供 ServerConfig / ClientConfig 构建，支持：
//! - 自签证书自动生成（开发环境）
//! - 外部证书加载（生产环境）
//! - SNI 域名伪装

use crate::error::{Error, Result};
use crate::util::base64_encode;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::path::PathBuf;
use std::sync::Arc;

/// TLS 配置构建器。
pub struct TlsConfigBuilder {
    /// 服务端证书路径（listener 模式）
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    /// 客户端自定义 CA 根证书（connector 模式）
    ca_cert: Option<Vec<CertificateDer<'static>>>,
    /// 服务端证书固定（pinning）：仅信任列出的证书（connector 模式）
    pinned_certs: Option<Vec<CertificateDer<'static>>>,
    /// 服务端证书 SHA-256 指纹固定（connector 模式，connect_url 一键分发）
    pinned_fingerprint: Option<String>,
    /// SNI 域名（connector 模式，伪装用）
    pub sni_hostname: String,
    /// 是否允许自签证书（开发模式）
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

    /// 证书固定：仅信任指定的服务端证书（等效于把对端证书钉入根存储）。
    ///
    /// 这是私有化部署下抗 MITM 的推荐方式——节点证书指纹通过带外渠道分发。
    pub fn pinned_certs(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        if !certs.is_empty() {
            self.pinned_certs = Some(certs);
        }
        self
    }

    /// 证书指纹固定（SHA-256 hex，connect_url 分发的轻量 pinning）。
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

    /// 构建 rustls ServerConfig（listener 用）。
    ///
    /// 如果没有配置证书路径，自动生成自签证书。
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
        // ALPN 拟态：真实浏览器 ClientHello 必带 h2/http1.1，空 ALPN 是最廉价的 DPI 单字段筛子
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok((Arc::new(server_config), certs))
    }

    /// 构建 rustls ClientConfig（connector 用）。
    ///
    /// 信任策略优先级：证书固定 (pinning) > 自定义 CA > 跳过验证（开发） > 系统 CA。
    pub fn build_client(&self) -> Result<Arc<rustls::ClientConfig>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = if let Some(fp) = &self.pinned_fingerprint {
            // 证书指纹固定：哈希比对 + rustls 原生签名校验，抗 MITM 且免分发证书文件
            let verifier = danger::PinnedFingerprintVerifier::new(fp)?;
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else if let Some(pinned) = &self.pinned_certs {
            // 证书固定：钉入的证书作为唯一信任根，抗 MITM
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
            // 使用自定义 CA
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
            // 开发模式：信任所有证书（仅调试用，生产禁用）
            let verifier = danger::NoCertificateVerification::new();
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else {
            // 默认：使用 webpki-roots 内嵌的 CA 列表
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // ALPN 拟态（与服务端同列表；对端为旧版无 ALPN 时握手不受影响，向后兼容）
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// 获取 ServerName 用于 TLS 连接。
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

/// 从 PEM 文件加载证书和私钥。
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

/// 生成自签证书（开发用）。
pub fn generate_self_signed(
    hostname: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut params = CertificateParams::new(vec![hostname.to_string()])
        .map_err(|e| Error::Tls(format!("cert params: {e}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    // Subject 拟态：空 O/C 字段是自建隧道的强指纹，仿真正常 CDN 证书
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Cloudflare, Inc.");
    params
        .distinguished_name
        .push(rcgen::DnType::CountryName, "US");
    // 到期日随机化（2032-2038 随机年月）：全量节点统一 2036-01-01 是大规模扫描的关联特征；
    // 已持久化的存量证书不受影响（load_or_generate 只在首次生成时走这里）
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

/// 加载已有证书，不存在时生成自签证书并持久化到磁盘（PEM 格式）。
///
/// 持久化保证节点重启后证书不变，客户端可以稳定地做证书固定 (pinning)。
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

    // 写 PEM
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

    // 私钥文件权限收紧（Unix 0600）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok((certs, key))
}

/// 计算证书的 SHA-256 指纹（hex，用于证书固定配置分发）。
pub fn cert_fingerprint_sha256(cert: &CertificateDer<'_>) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(cert.as_ref());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// PEM 按 64 列折行。
fn wrap64(b64: &str) -> String {
    b64.as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

/// 危险的证书验证器——开发模式使用，跳过所有验证。
mod danger {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    /// 证书 SHA-256 指纹固定验证器。
    ///
    /// 安全性论证：哈希比对确认对端出示的即是目标证书（公钥），
    /// TLS 握手 CertificateVerify 由 rustls 原生验签（证明私钥持有），
    /// 两者结合等价于证书固定，抗 MITM，且无需分发证书文件。
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
        // ServerConfig 已成功创建
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
