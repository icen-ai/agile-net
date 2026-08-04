//! E2E payload encryption (federation P3) — zero-handshake PSK channels over relay hops.
//!
//! Key hierarchy:
//! - `e2e_key  = HKDF-SHA256(ikm = token plaintext, salt = "anet/e2e/v1", info = "")` — the
//!   client derives it from the share-link token, the issuer derives it at issuance; the relay
//!   only holds the token hash and **cannot** derive it.
//! - `chan_key = HKDF-SHA256(ikm = e2e_key, salt = chan_salt, info = "chan")` — a fresh 16-byte
//!   random salt per channel (carried inside the sealed Open blob) guarantees zero nonce reuse
//!   across sessions and channels (hard discipline 1: nonce reuse with AES-GCM is catastrophic).
//!
//! Wire formats:
//! - Open blob: `base64(nonce12 || ct)` where the plaintext is JSON
//!   `{target_addr, target_port, groups, chan_salt}` sealed under `e2e_key` with a random nonce.
//!   Decrypting it authenticates the channel origin (only token holders can seal).
//! - Data chunks: the stream is framed as `[u32 ct_len][ct]` blocks (the mux does not preserve
//!   chunk boundaries). Each block is one AEAD record under `chan_key` with
//!   `nonce = direction(1B) || 0*3 || seq(8B BE)`, seq starting at 0 per direction.
//!
//! Hard discipline 2: the receiver enforces a strictly increasing sequence per direction —
//! a replayed/reordered chunk fails the AEAD check against the expected nonce and the channel
//! must be torn down (fail closed; the relay cannot forge new ciphertexts but can replay old
//! ones, which must never surface as duplicated application-level mutations).

use crate::error::{Error, Result};
use crate::proto::message::E2eOpen;

use bytes::{Bytes, BytesMut};
use ring::{aead, hkdf};
use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// HKDF salt for the per-token E2E master key.
pub const E2E_SALT: &[u8] = b"anet/e2e/v1";
/// HKDF info for the per-channel sub-key.
pub const CHAN_INFO: &[u8] = b"chan";
/// Per-channel random salt length (bytes).
pub const CHAN_SALT_LEN: usize = 16;
/// Max plaintext per AEAD record (keeps sealed blocks well under the mux 256KB data cap).
pub const MAX_BLOCK: usize = 16 * 1024;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const LEN_PREFIX: usize = 4;

struct Len32;
impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = [0u8; 32];
    prk.expand(&[info], Len32)
        .and_then(|okm| okm.fill(&mut out))
        .expect("hkdf expand 32 bytes is infallible");
    out
}

/// E2E master key of a delegated token (issuer side: derive at issuance and store encrypted;
/// client side: derive from the share-link token on the fly).
pub fn derive_key(token_plaintext: &str) -> [u8; 32] {
    hkdf32(E2E_SALT, token_plaintext.as_bytes(), &[])
}

/// Key id carried in the E2E envelope: first 8 hex chars of the token SHA-256 hash.
pub fn kid_of(token_hash: &str) -> &str {
    token_hash.get(..8).unwrap_or(token_hash)
}

/// Per-channel sub-key (discipline 1: random salt per channel -> zero nonce reuse).
pub fn derive_chan_key(e2e_key: &[u8; 32], chan_salt: &[u8]) -> [u8; 32] {
    hkdf32(chan_salt, e2e_key, CHAN_INFO)
}

/// AEAD nonce: direction(1B) || 0*3 || seq(8B BE).
fn nonce(dir: u8, seq: u64) -> aead::Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[0] = dir;
    n[4..].copy_from_slice(&seq.to_be_bytes());
    aead::Nonce::assume_unique_for_key(n)
}

fn less_safe(key: &[u8; 32]) -> aead::LessSafeKey {
    aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key).expect("32B key"))
}

/// Plaintext payload of an E2E Open blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eOpenPayload {
    pub target_addr: String,
    pub target_port: u16,
    #[serde(default)]
    pub groups: Vec<String>,
    /// Base64 per-channel random salt.
    pub chan_salt: String,
}

/// Client side: seal an Open envelope for `target` and return it with the channel cipher
/// already initialized (send direction 0 = client -> issuer).
pub fn seal_open(
    e2e_key: &[u8; 32],
    kid: &str,
    hint: &str,
    target_addr: &str,
    target_port: u16,
    groups: &[String],
) -> (E2eOpen, ChannelCipher) {
    let chan_salt: [u8; CHAN_SALT_LEN] = rand::random();
    let payload = E2eOpenPayload {
        target_addr: target_addr.to_string(),
        target_port,
        groups: groups.to_vec(),
        chan_salt: crate::util::base64_encode(&chan_salt),
    };
    let plain = serde_json::to_vec(&payload).expect("E2eOpenPayload serialize");

    // random nonce per blob (multiple channels share e2e_key — a fixed blob nonce would be
    // cross-channel nonce reuse, the exact disaster discipline 1 exists to prevent)
    let blob_nonce: [u8; NONCE_LEN] = rand::random();
    let key = less_safe(e2e_key);
    let mut buf = plain;
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(blob_nonce),
        aead::Aad::empty(),
        &mut buf,
    )
    .expect("seal into owned vec");

    let mut wire = Vec::with_capacity(NONCE_LEN + buf.len());
    wire.extend_from_slice(&blob_nonce);
    wire.extend_from_slice(&buf);

    let chan_key = derive_chan_key(e2e_key, &chan_salt);
    (
        E2eOpen {
            kid: kid.to_string(),
            hint: hint.to_string(),
            blob: crate::util::base64_encode(&wire),
        },
        ChannelCipher::new(chan_key, 0),
    )
}

/// Issuer side: unwrap an E2E envelope (kid already resolved to the token's e2e_key by the
/// caller). Decrypting successfully authenticates the channel origin — only a token holder
/// could seal the blob. Returns the plaintext payload and the channel cipher (send direction
/// 1 = issuer -> client).
pub fn open_open(e2e_key: &[u8; 32], e2e: &E2eOpen) -> Result<(E2eOpenPayload, ChannelCipher)> {
    let wire = crate::util::base64_decode(&e2e.blob)
        .map_err(|_| Error::Protocol("e2e blob is not valid base64".into()))?;
    if wire.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Protocol("e2e blob too short".into()));
    }
    let (nonce_bytes, ct) = wire.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);

    let key = less_safe(e2e_key);
    let mut buf = ct.to_vec();
    let plain = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce_arr),
            aead::Aad::empty(),
            &mut buf,
        )
        .map_err(|_| Error::Auth("e2e blob authentication failed".into()))?;
    let payload: E2eOpenPayload = serde_json::from_slice(plain)
        .map_err(|e| Error::Protocol(format!("invalid e2e open payload: {e}")))?;

    let chan_salt = crate::util::base64_decode(&payload.chan_salt)
        .map_err(|_| Error::Protocol("invalid chan_salt".into()))?;
    if chan_salt.len() != CHAN_SALT_LEN {
        return Err(Error::Protocol("chan_salt length invalid".into()));
    }
    let chan_key = derive_chan_key(e2e_key, &chan_salt);
    Ok((payload, ChannelCipher::new(chan_key, 1)))
}

/// Per-channel AEAD record cipher with strict sequence enforcement (discipline 2).
pub struct ChannelCipher {
    key: aead::LessSafeKey,
    send_dir: u8,
    send_seq: u64,
    recv_seq: u64,
}

impl ChannelCipher {
    /// `send_dir`: 0 on the client (client -> issuer), 1 on the issuer.
    pub fn new(chan_key: [u8; 32], send_dir: u8) -> Self {
        Self {
            key: less_safe(&chan_key),
            send_dir,
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// Seal one plaintext block into a framed record `[u32 ct_len][ct+tag]`.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                nonce(self.send_dir, self.send_seq),
                aead::Aad::empty(),
                &mut buf,
            )
            .expect("seal into owned vec");
        self.send_seq += 1;
        let mut out = Vec::with_capacity(LEN_PREFIX + buf.len());
        out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&buf);
        out
    }

    /// Open one framed record. The record's implicit sequence number must equal the expected
    /// receive counter — any replay/reorder fails authentication and is fatal to the channel.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>> {
        let recv_dir = 1 - self.send_dir;
        let mut buf = record.to_vec();
        let plain = self
            .key
            .open_in_place(nonce(recv_dir, self.recv_seq), aead::Aad::empty(), &mut buf)
            .map_err(|_| Error::Protocol("e2e record authentication failed (replay?)".into()))?;
        self.recv_seq += 1;
        Ok(plain.to_vec())
    }
}

/// Stream wrapper applying E2E record encryption over any async stream (typically a MuxChannel).
///
/// Read path buffers incoming bytes, splits framed records and serves decrypted plaintext;
/// write path seals outgoing data into records (partial writes of a sealed record are tracked).
pub struct E2eStream<S> {
    inner: S,
    cipher: ChannelCipher,
    /// Undecoded inbound bytes (may contain a partial record).
    read_enc: BytesMut,
    /// Decrypted plaintext block being served (bytes, consumed offset).
    read_plain: Option<(Vec<u8>, usize)>,
    /// Sealed outbound record being flushed (bytes, written offset, accepted plaintext len).
    pending_write: Option<(Bytes, usize, usize)>,
    inner_eof: bool,
}

impl<S> E2eStream<S> {
    pub fn new(inner: S, cipher: ChannelCipher) -> Self {
        Self {
            inner,
            cipher,
            read_enc: BytesMut::with_capacity(2 * MAX_BLOCK),
            read_plain: None,
            pending_write: None,
            inner_eof: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for E2eStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // serve decrypted plaintext first
            if let Some((plain, off)) = &mut self.read_plain {
                let avail = plain.len() - *off;
                if avail > 0 {
                    let n = buf.remaining().min(avail);
                    buf.put_slice(&plain[*off..*off + n]);
                    *off += n;
                    return Poll::Ready(Ok(()));
                }
                self.read_plain = None;
            }

            // try to decode one complete record from the ciphertext buffer
            if self.read_enc.len() >= LEN_PREFIX {
                let ct_len = u32::from_be_bytes([
                    self.read_enc[0],
                    self.read_enc[1],
                    self.read_enc[2],
                    self.read_enc[3],
                ]) as usize;
                if ct_len > MAX_BLOCK + TAG_LEN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "e2e record too large",
                    )));
                }
                if self.read_enc.len() >= LEN_PREFIX + ct_len {
                    let record = self.read_enc.split_to(LEN_PREFIX + ct_len);
                    let plain = self
                        .cipher
                        .open(&record[LEN_PREFIX..])
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    self.read_plain = Some((plain, 0));
                    continue;
                }
            }

            if self.inner_eof {
                return Poll::Ready(Ok(())); // clean EOF with no pending plaintext
            }

            // need more ciphertext
            let mut chunk = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        self.inner_eof = true;
                    } else {
                        self.read_enc.extend_from_slice(rb.filled());
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for E2eStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // seal a new record only once the previous one is fully flushed (backpressure-safe:
        // the accepted plaintext length is fixed at seal time and reported on completion)
        if self.pending_write.is_none() {
            let block_len = buf.len().min(MAX_BLOCK);
            let sealed = self.cipher.seal(&buf[..block_len]);
            self.pending_write = Some((Bytes::from(sealed), 0, block_len));
        }

        let this = self.as_mut().get_mut(); // S: Unpin — field-level split borrows
        loop {
            {
                let (sealed, written, plain_len) = this.pending_write.as_ref().expect("just set");
                if *written == sealed.len() {
                    let n = *plain_len;
                    this.pending_write = None;
                    return Poll::Ready(Ok(n));
                }
            }
            let res = {
                let (sealed, written, _) = this.pending_write.as_ref().expect("pending");
                Pin::new(&mut this.inner).poll_write(cx, &sealed[*written..])
            };
            match res {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "e2e inner write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    this.pending_write.as_mut().expect("pending").1 += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        derive_key("psk_test-token-0123456789")
    }

    #[test]
    fn key_derivation_deterministic_and_domain_separated() {
        let k1 = derive_key("psk_aaa");
        let k2 = derive_key("psk_aaa");
        let k3 = derive_key("psk_bbb");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        // channel sub-keys differ per salt
        let c1 = derive_chan_key(&k1, b"0123456789abcdef");
        let c2 = derive_chan_key(&k1, b"fedcba9876543210");
        assert_ne!(c1, c2);
    }

    #[test]
    fn open_blob_roundtrip() {
        let key = test_key();
        let hash = crate::util::sha256_hex(b"psk_test-token-0123456789");
        let (env, mut client_cipher) = seal_open(
            &key,
            kid_of(&hash),
            "git.internal",
            "10.0.0.5",
            5432,
            &["db".to_string()],
        );
        assert_eq!(env.kid, hash[..8]);
        assert_eq!(env.hint, "git.internal");

        let (payload, mut issuer_cipher) = open_open(&key, &env).expect("unwrap");
        assert_eq!(payload.target_addr, "10.0.0.5");
        assert_eq!(payload.target_port, 5432);
        assert_eq!(payload.groups, vec!["db".to_string()]);

        // data plane: client -> issuer
        let rec = client_cipher.seal(b"SELECT 1");
        let plain = issuer_cipher.open(&rec[LEN_PREFIX..]).unwrap();
        assert_eq!(plain, b"SELECT 1");
        // issuer -> client
        let rec = issuer_cipher.seal(b"row1");
        let plain = client_cipher.open(&rec[LEN_PREFIX..]).unwrap();
        assert_eq!(plain, b"row1");
    }

    #[test]
    fn wrong_key_cannot_unwrap() {
        let (env, _) = seal_open(&test_key(), "kid", "h", "a", 1, &[]);
        let wrong = derive_key("psk_other");
        assert!(open_open(&wrong, &env).is_err());
    }

    #[test]
    fn replayed_record_rejected() {
        let key = test_key();
        let (env, mut a) = seal_open(&key, "kid", "h", "a", 1, &[]);
        let (_, mut b) = open_open(&key, &env).unwrap();
        let rec1 = a.seal(b"first");
        let rec2 = a.seal(b"second");
        // out-of-order delivery: the later record fails against the expected sequence 0
        assert!(b.open(&rec2[LEN_PREFIX..]).is_err());
        // a failed open must not advance the sequence (legitimate in-order record still passes)
        b.open(&rec1[LEN_PREFIX..]).unwrap();
        // replaying an old record is rejected (strict sequence, discipline 2)
        assert!(b.open(&rec1[LEN_PREFIX..]).is_err());
        // the live next record still passes afterwards
        b.open(&rec2[LEN_PREFIX..]).unwrap();
    }

    #[tokio::test]
    async fn e2e_stream_roundtrip_over_duplex() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let key = test_key();
        let (env, client_cipher) = seal_open(&key, "kid", "h", "a", 1, &[]);
        let (_, issuer_cipher) = open_open(&key, &env).unwrap();

        let (s1, s2) = tokio::io::duplex(64 * 1024);
        let mut client = E2eStream::new(s1, client_cipher);
        let mut issuer = E2eStream::new(s2, issuer_cipher);

        let payload = vec![b'x'; 100_000]; // spans many records
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        issuer.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, vec![b'x'; 100_000]);
    }
}
