//! Device identity (node.md M2): each installation owns one ed25519 keypair, generated locally
//! (pure `ring` — no OpenSSH/ssh-keygen/gpg dependency, portable across Android/iOS/desktop).
//!
//! - `device_fp` = SHA-256 hex of the raw public key — a self-certifying ID: showing the
//!   fingerprint (UI/logs/screenshots) is safe, because proving it requires the private key.
//! - Handshake proof: the connecting side signs the TLS exporter secret (RFC 5705) — zero extra
//!   round trip, replay-bound to the TLS session. The signature itself lives in the handshake
//!   code; this module only does keys/signatures/encoding.
//! - The private key lives in a 0600 file under the brand data dir (`~/.anet/device.key`) —
//!   machine-wide, shared by the client and server roles of one box, deliberately NOT in the OS
//!   keyring (no pollution of the user's environment).

use std::path::Path;

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::error::{Error, Result};
use crate::util::{base64_encode, sha256_hex};

/// Default private-key path relative to the brand root (`~/.anet/device.key`).
pub const DEVICE_KEY_FILENAME: &str = "device.key";

/// RFC 5705 exporter label for the device-proof challenge (handshake v4).
pub const DEVICE_PROOF_LABEL: &[u8] = b"anet device proof v1";

/// Derive the per-session device-proof challenge from the TLS exporter (RFC 5705
/// `export_keying_material`). Both sides of the TLS session derive the same value; it is unique
/// per handshake (replay-bound) and never crosses the wire. A signature over this value proves
/// private-key possession to the TLS peer only.
pub fn session_challenge<S: rustls::SideData>(conn: &rustls::ConnectionCommon<S>) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, DEVICE_PROOF_LABEL, None)
        .map_err(|e| Error::Tls(format!("exporter derive failed: {e}")))?;
    Ok(out)
}

/// A device's ed25519 identity (private key in memory only after load/generate).
pub struct DeviceIdentity {
    pair: Ed25519KeyPair,
    pubkey: [u8; 32],
    /// Original PKCS#8 v2 document (ring cannot re-serialize a parsed key — keep the source bytes)
    pkcs8: Vec<u8>,
}

impl DeviceIdentity {
    /// Generate a fresh keypair (first run on this machine).
    pub fn generate() -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| Error::Other(format!("device keygen failed: {e}")))?;
        Self::from_pkcs8(doc.as_ref())
    }

    /// Parse a stored PKCS#8 v2 document.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        let pair = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|e| Error::Other(format!("device key parse failed: {e}")))?;
        let pubkey: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::Other("device key: bad pubkey length".into()))?;
        Ok(Self {
            pair,
            pubkey,
            pkcs8: bytes.to_vec(),
        })
    }

    /// Serialize for storage (PKCS#8 v2 DER).
    pub fn to_pkcs8(&self) -> Vec<u8> {
        self.pkcs8.clone()
    }

    /// Raw ed25519 public key (32 bytes).
    pub fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    /// device_fp: SHA-256 hex of the public key (full 64 chars; DB/registry key).
    pub fn device_fp(&self) -> String {
        fp_of(&self.pubkey)
    }

    /// Display form (first 12 hex), for badges and session tags.
    pub fn short_fp(&self) -> String {
        self.device_fp()[..12].to_string()
    }

    /// Sign a message (handshake challenge, certification record).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }

    /// Machine identity: load-or-create at the brand root (`~/.anet/device.key`). One identity
    /// per machine, shared by the client and server roles; never the OS keyring.
    pub fn machine() -> Result<Self> {
        Self::load_or_create(&crate::util::brand_root().join(DEVICE_KEY_FILENAME))
    }

    /// Ephemeral in-memory identity (tests / throwaway sessions): produces a valid proof but a
    /// fresh device_fp per instance; never touches the disk.
    pub fn ephemeral() -> Self {
        Self::generate().unwrap_or_else(|_| panic!("ed25519 keygen failed"))
    }

    /// Verify a signature against a claimed public key.
    pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, pubkey)
            .verify(msg, sig)
            .is_ok()
    }

    /// OpenSSH `authorized_keys`-format public key line (display/copy only — the private key is
    /// never exported). `ssh-ed25519 <base64> [comment]`.
    pub fn openssh_pubkey(&self, comment: &str) -> String {
        let mut blob = Vec::with_capacity(51);
        let kind = b"ssh-ed25519";
        blob.extend_from_slice(&(kind.len() as u32).to_be_bytes());
        blob.extend_from_slice(kind);
        blob.extend_from_slice(&(self.pubkey.len() as u32).to_be_bytes());
        blob.extend_from_slice(&self.pubkey);
        let line = format!("ssh-ed25519 {}", base64_encode(&blob));
        if comment.is_empty() {
            line
        } else {
            format!("{line} {comment}")
        }
    }

    /// Load the machine identity from `path`, creating it on first use. An existing but
    /// unparsable file is a hard error (silently regenerating would quietly change identity).
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_pkcs8(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = Self::generate()?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let bytes = id.to_pkcs8();
                write_private(path, &bytes)?;
                Ok(id)
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

/// device_fp of an arbitrary public key (peer-side binding check: claimed fp vs presented key).
pub fn fp_of(pubkey: &[u8]) -> String {
    sha256_hex(pubkey)
}

/// Write the private key with owner-only permissions (0600 on unix; Windows relies on the
/// user-profile ACL — the file never leaves the brand dir either way).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_verify_roundtrip() {
        let id = DeviceIdentity::generate().unwrap();
        let msg = b"anet/device-challenge/v1";
        let sig = id.sign(msg);
        assert!(DeviceIdentity::verify(id.pubkey(), msg, &sig));
        // wrong message / wrong key both fail
        assert!(!DeviceIdentity::verify(id.pubkey(), b"other", &sig));
        let other = DeviceIdentity::generate().unwrap();
        assert!(!DeviceIdentity::verify(other.pubkey(), msg, &sig));
    }

    #[test]
    fn pkcs8_roundtrip_keeps_identity() {
        let id = DeviceIdentity::generate().unwrap();
        let fp = id.device_fp();
        let restored = DeviceIdentity::from_pkcs8(&id.to_pkcs8()).unwrap();
        assert_eq!(fp, restored.device_fp());
        assert_eq!(id.pubkey(), restored.pubkey());
    }

    #[test]
    fn fp_is_sha256_of_pubkey_and_stable() {
        let id = DeviceIdentity::generate().unwrap();
        assert_eq!(id.device_fp(), sha256_hex(id.pubkey()));
        assert_eq!(id.device_fp().len(), 64);
        assert_eq!(id.short_fp().len(), 12);
        assert_eq!(fp_of(id.pubkey()), id.device_fp());
    }

    #[test]
    fn openssh_line_carries_the_pubkey() {
        let id = DeviceIdentity::generate().unwrap();
        let line = id.openssh_pubkey("anet-test");
        assert!(line.starts_with("ssh-ed25519 "));
        assert!(line.ends_with(" anet-test"));
        let b64 = line.split_whitespace().nth(1).unwrap();
        let blob = crate::util::base64_decode(b64).unwrap();
        // SSH wire format: string "ssh-ed25519" + string pubkey(32)
        assert_eq!(&blob[..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes());
        assert_eq!(&blob[19..51], id.pubkey());
    }

    #[test]
    fn load_or_create_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!(
            "anet-device-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join(DEVICE_KEY_FILENAME);
        let id = DeviceIdentity::load_or_create(&path).unwrap();
        let fp = id.device_fp();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "private key must be 0600");
        }
        let reloaded = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(fp, reloaded.device_fp());
        // corrupted file is a hard error, never a silent re-identity
        std::fs::write(&path, b"garbage").unwrap();
        assert!(DeviceIdentity::load_or_create(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
