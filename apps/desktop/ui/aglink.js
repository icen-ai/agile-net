'use strict';
/* AgileNet unified link parser/builder (aglink):
   desktop loads via <script src="aglink.js">; admin UI serves it embedded via crates/node/src/ui/mod.rs at /ui/aglink.js
   (same mechanism as agutil.js / agchart.js). THE single parser shared by every form on both ends —
   paste-to-import must never fork a second implementation.
   Link shapes (three-piece set: entry address + credential + entry cert fingerprint):
     delegated credential: anet://connect?server=H&port=P&account=d:<label>&password=psk_...&fp=FP
                           (+ entry/entryfp disaster set, en entrust word, emode, eadmin, myname)
     fan-out peer:         anet://fanout?server=H&port=P&token=psk_...&sni=SNI&fp=FP&myname=NAME
   `server` may be a full `https://host[:port]` form (API behind a reverse proxy; the port param is then ignored).
   Only the `anet://` scheme is recognized — anything else is an error.
   Errors are returned as neutral codes ({ error: 'bad_prefix'|'bad_role'|'missing_params'|'bad_port' }) — the caller maps them to i18n. */
(function () {

const SCHEMES = ['anet://'];
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
   { role:'connect', server, addr, account, password, fp, insecure, delegated, label,
     entries[], entryFps[], en, emode, eadmin } |
   { role:'fanout',  server, addr, token, sni, fp, insecure } |
   { error }
   Connect links carry delegated credentials: the disaster set (entry/entryfp, comma-joined
   parallel lists; empty = single entry) and the `d:<label>` account mark. */
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
      fp: p.fp || '', insecure: truthy(p.insecure),
      delegated, label: delegated ? p.account.slice(2) : '',
      entries: entries.length ? entries : [sv.addr],
      entryFps: entries.length ? entryFps : [p.fp || ''],
      // entrust word (en_xxx opaque routing ID; every Open is E2E-sealed when set)
      en: p.en || '',
      // consumer tier: 'split' = E2E rule delivery (route selectively);
      // absent = dedicated 专线 (whole machine captured)
      emode: p.emode || '',
      // delegated admin capability hint (ticket pull via the E2E config channel)
      eadmin: truthy(p.eadmin),
      // self-declared display name suggestion ("我的名称", node.md M2)
      myname: p.myname || '',
    };
  }
  const sv = resolveServer(p, 54430);
  if (!sv) return { error: 'missing_params' };
  if (sv.error) return sv;
  if (!p.token) return { error: 'missing_params' };
  return {
    role: 'fanout', server: sv.server, addr: sv.addr,
    token: p.token, sni: p.sni || '', fp: p.fp || '', insecure: truthy(p.insecure),
    myname: p.myname || '',
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

/* Build a delegated-credential link (anet://connect?...). Pass `entries:[{addr,fp}]`
   (disaster set, primary first) to append entry/entryfp; a single-entry set stays parameter-free. */
function buildConnect(f) {
  const params = [
    ...serverParams(f.addr || f.server),
    ['account', f.account], ['password', f.password],
    ['fp', f.fp], ['insecure', !!f.insecure],
  ];
  const entries = (f.entries || []).filter(e => e && e.addr);
  if (entries.length > 1) {
    params.push(['entry', entries.map(e => e.addr).join(',')]);
    params.push(['entryfp', entries.map(e => e.fp || '').join(',')]);
  }
  if (f.en) params.push(['en', f.en]);
  if (f.emode === 'split') params.push(['emode', 'split']);
  if (f.eadmin) params.push(['eadmin', '1']);
  if (f.myname) params.push(['myname', f.myname]);
  return 'anet://connect?' + qs(params);
}

/* Build a fan-out peer link (anet://fanout?...). */
function buildFanout(f) {
  return 'anet://fanout?' + qs([
    ...serverParams(f.addr || f.server),
    ['token', f.token], ['sni', f.sni], ['fp', f.fp], ['insecure', !!f.insecure],
    ['myname', f.myname],
  ]);
}

window.AgLink = { parse, buildConnect, buildFanout };
})();
