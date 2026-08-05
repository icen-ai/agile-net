'use strict';
/* AgileNet unified link parser/builder (aglink, federation P1 §2.7):
   desktop loads via <script src="aglink.js">; admin UI serves it embedded via crates/node/src/ui/mod.rs at /ui/aglink.js
   (same mechanism as agutil.js / agchart.js). THE single parser shared by every form on both ends —
   paste-to-import must never fork a second implementation.
   Link shapes (three-piece set: entry address + credential + entry cert fingerprint):
     fan-in account:  anet://connect?server=H&port=P&account=U&password=W&fp=FP[&admin=1]
     fan-out peer:    anet://fanout?server=H&port=P&token=psk_...&sni=SNI&fp=FP
   `server` may be a full `https://host[:port]` form (API behind a reverse proxy; the port param is then ignored).
   Generation always uses the new `anet://` scheme; parsing accepts the legacy `agilenet://` scheme forever (smooth migration).
   Errors are returned as neutral codes ({ error: 'bad_prefix'|'bad_role'|'missing_params'|'bad_port' }) — the caller maps them to i18n. */
(function () {

const SCHEMES = ['anet://', 'agilenet://'];
const ROLES = ['connect', 'fanout'];

function urlDecode(s) {
  try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (e) { return String(s); }
}

function urlEncode(s) {
  return encodeURIComponent(String(s));
}

/* Split "scheme://role?query" into { role, params } (params = plain object, values decoded). */
function splitUrl(url) {
  const raw = String(url || '').trim();
  const scheme = SCHEMES.find(s => raw.startsWith(s));
  if (!scheme) return { error: 'bad_prefix' };
  const rest = raw.slice(scheme.length);
  const q = rest.indexOf('?');
  const role = (q < 0 ? rest : rest.slice(0, q)).replace(/\/+$/, '');
  if (!ROLES.includes(role)) return { error: 'bad_role' };
  const params = {};
  if (q >= 0) {
    for (const pair of rest.slice(q + 1).split('&')) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      const k = eq < 0 ? pair : pair.slice(0, eq);
      const v = eq < 0 ? '' : pair.slice(eq + 1);
      params[k] = urlDecode(v);
    }
  }
  return { role, params };
}

/* Parse the server field: full `https://host[:port]` wins; otherwise host[:port] + the port param.
   Returns { server, addr } — server = display/build value, addr = host:port (or the full scheme form) for connection use. */
function resolveServer(p, defaultPort) {
  let server = String(p.server || '').trim().replace(/\/+$/, '');
  if (!server) return null;
  if (/^https?:\/\//i.test(server)) return { server, addr: server };
  // Bare host or host:port (IPv6 literals must come bracketed: [::1]:54430)
  const m = server.match(/^(\[[0-9a-fA-F:]+\]|[^:]+)(?::(\d+))?$/);
  if (!m) return { error: 'missing_params' };
  const host = m[1];
  const port = m[2] || String(p.port || '').trim() || String(defaultPort);
  if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) return { error: 'bad_port' };
  return { server: host + ':' + port, addr: host + ':' + port };
}

function truthy(v) { return v === '1' || String(v).toLowerCase() === 'true'; }

/* Parse a unified link. Returns:
   { role:'connect', server, addr, account, password, fp, insecure, admin, delegated, label,
     entries[], entryFps[] } |
   { role:'fanout',  server, addr, token, sni, fp, insecure } |
   { error }
   Federation P2: connect links may carry the disaster set (entry/entryfp, comma-joined parallel
   lists; empty = single entry) and the `d:<label>` account mark of a delegated credential. */
function parse(url) {
  const sp = splitUrl(url);
  if (sp.error) return sp;
  const p = sp.params;
  if (sp.role === 'connect') {
    const sv = resolveServer(p, 59090);
    if (!sv) return { error: 'missing_params' };
    if (sv.error) return sv;
    if (!p.account || !p.password) return { error: 'missing_params' };
    const entries = String(p.entry || '').split(',').map(s => s.trim()).filter(Boolean);
    const entryFps = String(p.entryfp || '').split(',').map(s => s.trim());
    while (entryFps.length < entries.length) entryFps.push('');
    const delegated = p.account.startsWith('d:');
    return {
      role: 'connect', server: sv.server, addr: sv.addr,
      account: p.account, password: p.password,
      fp: p.fp || '', insecure: truthy(p.insecure), admin: truthy(p.admin),
      delegated, label: delegated ? p.account.slice(2) : '',
      entries: entries.length ? entries : [sv.addr],
      entryFps: entries.length ? entryFps : [p.fp || ''],
      // federation P3: E2E routing hint (delegated links; the client seals every Open when set)
      ehint: p.ehint || '',
      // federation P3 entrust word (en_xxx opaque routing ID; preferred over ehint on v4+ relays)
      en: p.en || '',
      // federation P3 consumer tier: 'split' = E2E rule delivery (route selectively);
      // absent = dedicated 专线 (whole machine captured)
      emode: p.emode || '',
      // federation P3 delegated admin capability hint (ticket pull via the E2E config channel)
      eadmin: truthy(p.eadmin),
    };
  }
  const sv = resolveServer(p, 54430);
  if (!sv) return { error: 'missing_params' };
  if (sv.error) return sv;
  if (!p.token) return { error: 'missing_params' };
  return {
    role: 'fanout', server: sv.server, addr: sv.addr,
    token: p.token, sni: p.sni || '', fp: p.fp || '', insecure: truthy(p.insecure),
  };
}

function qs(params) {
  return params.filter(kv => kv[1] !== '' && kv[1] != null && kv[1] !== false)
    .map(kv => kv[0] + '=' + urlEncode(kv[1] === true ? '1' : kv[1])).join('&');
}

/* Split an addr back into the server/port query pair (full-scheme addrs stay whole in server). */
function serverParams(addr) {
  const a = String(addr || '').trim();
  if (/^https?:\/\//i.test(a)) return [['server', a]];
  const m = a.match(/^(\[[0-9a-fA-F:]+\]|[^:]+)(?::(\d+))?$/);
  if (!m) return [['server', a]];
  return [['server', m[1]], ['port', m[2] || '']];
}

/* Build a fan-in account link (anet://connect?...). Pass `entries:[{addr,fp}]` (federation P2
   disaster set, primary first) to append entry/entryfp; a single-entry set stays parameter-free. */
function buildConnect(f) {
  const params = [
    ...serverParams(f.addr || f.server),
    ['account', f.account], ['password', f.password],
    ['fp', f.fp], ['insecure', !!f.insecure], ['admin', !!f.admin],
  ];
  const entries = (f.entries || []).filter(e => e && e.addr);
  if (entries.length > 1) {
    params.push(['entry', entries.map(e => e.addr).join(',')]);
    params.push(['entryfp', entries.map(e => e.fp || '').join(',')]);
  }
  if (f.ehint) params.push(['ehint', f.ehint]);
  if (f.en) params.push(['en', f.en]);
  if (f.emode === 'split') params.push(['emode', 'split']);
  if (f.eadmin) params.push(['eadmin', '1']);
  return 'anet://connect?' + qs(params);
}

/* Build a fan-out peer link (anet://fanout?...). */
function buildFanout(f) {
  return 'anet://fanout?' + qs([
    ...serverParams(f.addr || f.server),
    ['token', f.token], ['sni', f.sni], ['fp', f.fp], ['insecure', !!f.insecure],
  ]);
}

window.AgLink = { parse, buildConnect, buildFanout };
})();
