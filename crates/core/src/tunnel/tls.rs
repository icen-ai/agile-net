//! TLS 1.3 配置构建器
//!
//! 提供 ServerConfig / ClientConfig 构建，支持：
//! - 自签证书自动生成（开发环境）
//! - 外部证书加载（生产环境）
//! - SNI 域名伪装

use crate::error::{Error, Result};
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
        let (certs, key) =
            if let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) {
                load_certs_from_file(cert_path, key_path)?
            } else {
                generate_self_signed(&self.sni_hostname)?
            };

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .map_err(|e| Error::Tls(e.to_string()))?;

        Ok((Arc::new(server_config), certs))
    }

    /// 构建 rustls ClientConfig（connector 用）。
    pub fn build_client(&self) -> Result<Arc<rustls::ClientConfig>> {
        let config = if self.allow_self_signed {
            // 开发模式：信任所有证书
            let verifier = danger::NoCertificateVerification::new();
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else if let Some(ca_certs) = &self.ca_cert {
            // 使用自定义 CA
            let mut root_store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                root_store
                    .add(cert.clone())
                    .map_err(|e| Error::Tls(format!("failed to add CA cert: {e}")))?;
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            // 默认：使用系统 CA + webpki-roots 不可用时退到空 store
            let mut root_store = rustls::RootCertStore::empty();
            // 使用 webpki-roots 内嵌的 CA 列表
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

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

    let key_pair = KeyPair::generate().map_err(|e| Error::Tls(format!("keygen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Tls(format!("self-sign: {e}")))?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((vec![cert_der], key_der))
}

/// 危险的证书验证器——开发模式使用，跳过所有验证。
mod danger {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

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
        let builder = TlsConfigBuilder::new().sni_hostname("test.example.com");
        let (config, certs) = builder.build_server().unwrap();
        assert!(!certs.is_empty());
        // ServerConfig 已成功创建
        let _ = config;
    }

    #[test]
    fn build_client_config_self_signed() {
        let builder = TlsConfigBuilder::new()
            .allow_self_signed(true)
            .sni_hostname("test.example.com");
        let config = builder.build_client().unwrap();
        let _ = config;
    }
}
