'use strict';
/* AgileNet .anet credential file (federation P1 §2.8) — shared builder/parser on WebCrypto.
   desktop loads via <script src="aganet.js">; admin UI serves it embedded via crates/node/src/ui/mod.rs at /ui/aganet.js
   (same mechanism as aglink.js). THE single implementation for both ends.
   Envelope (JSON, human-readable):
     { magic:"ANET1", version:1, role:"connect"|"fanout", issuer, created_at, note,
       enc:"none"|"aes256gcm", salt?, nonce?, payload: {…technical fields…} | "b64 ciphertext" }
   Encryption is format-compatible with settings sync (sync.rs): PBKDF2-HMAC-SHA256 (100k iters,
   16B random salt) -> AES-256-GCM (12B nonce, tag appended); key input "agile-net-sync:v1:" + 4-digit PIN.
   Honest security note: PIN encryption defeats casual leakage (IM URL crawling/previews, chat-history
   search, clipboard managers, log collectors — files are not scraped); it does NOT resist targeted
   brute force on a captured file (4-digit PIN is offline-enumerable) — send the PIN via a separate channel. */
(function () {

const MAGIC = 'ANET1';
const VERSION = 1;
const KEY_PREFIX = 'agile-net-sync:v1:';

function canEncrypt() {
  return !!(window.crypto && crypto.subtle && window.isSecureContext !== false);
}

function b64e(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64d(s) {
  const bin = atob(String(s).trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function validatePin(pin) {
  if (!pin) return;
  if (/^\d{4}$/.test(pin)) return;
  throw { code: 'bad_pin' };
}

async function deriveKey(pin, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(KEY_PREFIX + pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/* Build the .anet file text. role: 'connect'|'fanout'; payload: plain technical-field object;
   pin: '' = plaintext envelope, 4 digits = AES-256-GCM (recommended default in the UI). */
async function build(meta, payload, pin) {
  validatePin(pin || '');
  const env = {
    magic: MAGIC,
    version: VERSION,
    role: meta.role,
    issuer: meta.issuer || '',
    created_at: new Date().toISOString(),
    note: meta.note || '',
    enc: 'none',
    payload,
  };
  if (pin) {
    if (!canEncrypt()) throw { code: 'no_crypto' };
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(pin, salt);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    env.enc = 'aes256gcm';
    env.salt = b64e(salt);
    env.nonce = b64e(nonce);
    env.payload = b64e(ct);
  }
  return JSON.stringify(env, null, 2) + '\n';
}

/* Parse the envelope WITHOUT decrypting (meta preview first). Returns
   { envelope, needPin } — needPin = encrypted and no plaintext fields available. Throws { code }. */
function parse(text) {
  let env;
  try { env = JSON.parse(String(text).trim()); } catch (e) { throw { code: 'bad_json' }; }
  if (!env || env.magic !== MAGIC) throw { code: 'bad_magic' };
  if (env.version !== VERSION) throw { code: 'bad_version' };
  if (env.role !== 'connect' && env.role !== 'fanout') throw { code: 'bad_role' };
  if (env.enc === 'aes256gcm') return { envelope: env, needPin: true };
  if (env.enc === 'none' || !env.enc) {
    if (!env.payload || typeof env.payload !== 'object') throw { code: 'bad_payload' };
    return { envelope: env, needPin: false };
  }
  throw { code: 'bad_enc' };
}

/* Decrypt an encrypted envelope (wrong PIN / corrupted file -> { code: 'decrypt' }). */
async function decrypt(envelope, pin) {
  validatePin(pin || '');
  if (!pin) throw { code: 'need_pin' };
  try {
    const key = await deriveKey(pin, b64d(envelope.salt));
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(envelope.nonce) },
      key,
      b64d(envelope.payload),
    );
    return JSON.parse(new TextDecoder().decode(pt));
  } catch (e) {
    if (e && e.code) throw e;
    throw { code: 'decrypt' };
  }
}

/* Suggested file name: <issuer>-<note>-<YYYY-MM-DD>.anet (§2.8 naming; sanitized, no spaces). */
function suggestName(issuer, note) {
  const clean = (s) => String(s || '')
    .replace(/[\\/:*?"<>|\s]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
  const date = new Date().toISOString().slice(0, 10);
  const parts = [clean(issuer) || 'agilenet', clean(note) || 'credential', date];
  return parts.join('-') + '.anet';
}

window.AgAnet = { canEncrypt, build, parse, decrypt, suggestName };
})();
