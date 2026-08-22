'use strict';
/* AgileNet universal import wizard (blind-plug: one dialog accepts every credential carrier).
   desktop loads via <script src="agimport.js">; admin UI serves it embedded at /ui/agimport.js
   (same mechanism as aglink.js / aganet.js). Depends on AgI18n / AgIcon / AgLink / AgAnet / esc.

   Step 1 (input): one input + flush icon row — paste / .anet file / QR image (when the host
   supports it) / confirm. The confirm icon stays gray until the preview below parses valid,
   then turns green with a breathing halo. Parsed content renders under the input (type badge
   「扇入链接 / 扇出链接」+「来自 …」+ technical fields).
   Step 2 (details, fan-out only): local server-role check (GUI: one-click start when off) +
   name / remark fields. Fan-in confirms in place (connect now); an end may mark a role
   inapplicable (admin console: fan-in; web remote panel: fan-out) — the preview explains and
   the confirm icon stays gray.

   AgImport.open(cfg):
     context           'desktop' | 'admin' (label only)
     connectApplicable bool   — fan-in links importable here (default true)
     fanoutApplicable  bool   — fan-out links importable here (default true)
     pickAnetFile()    -> { name, content } | null        — .anet picker (null = cancelled)
     pickQrImage()     -> text | null                     — QR image pick+decode; omit = QR button hidden
     checkFanoutReady()-> { ready:true } | { ready:false, start() -> true | errorString }  (optional)
     applyConnect({ parsed, link })          -> true | errorString
     applyFanout({ parsed, link }, details)  -> true | errorString   (details: {name, remark, myname})
     onDone(role)      — after a successful import (refresh lists)
     toast(msg, kind)  — host toast
*/
(function () {

const T = (k, v) => AgI18n.t(k, v);

/* Shorten a cert fingerprint for display (full value in title). */
function fpShort(fp) {
  const f = String(fp || '');
  return f.length > 18 ? f.slice(0, 18) + '…' : f;
}

/* Host part of an entry addr (display "from" for bare links; full-scheme addrs keep the origin). */
function hostOf(addr) {
  const a = String(addr || '').trim();
  if (/^https?:\/\//i.test(a)) {
    try { return new URL(a).host; } catch (e) { return a; }
  }
  const m = a.match(/^(\[[0-9a-fA-F:]+\]|[^:]+)(?::\d+)?$/);
  return m ? m[1] : a;
}

function open(cfg) {
  cfg = cfg || {};
  const connectOk = cfg.connectApplicable !== false;
  const fanoutOk = cfg.fanoutApplicable !== false;
  const toast = cfg.toast || function () {};

  const st = {
    step: 'input',
    kind: null,        // 'link' | 'anet'
    parsed: null,      // AgLink.parse result of the effective link
    link: '',          // authoritative link (pasted / rebuilt from .anet payload)
    env: null,         // .anet envelope (kind === 'anet')
    fileName: '',
    payload: null,     // decrypted/plain .anet payload
    needPin: false,
    ready: false,
    err: '',
    clauseAccepted: false, // M4-T5: visibility clause card acknowledged
  };

  /* ---------- DOM skeleton ---------- */
  const mask = document.createElement('div');
  mask.className = 'agimp-mask';
  mask.innerHTML =
    '<div class="agimp" role="dialog" aria-modal="true">' +
      '<div class="agimp-head">' + AgIcon('link', 18) +
        '<span class="agimp-title">' + T('import.head') + '</span>' +
        '<button class="agimp-x" data-x>' + AgIcon('x', 16) + '</button>' +
      '</div>' +
      '<div class="agimp-body"></div>' +
    '</div>';
  document.body.appendChild(mask);
  const body = mask.querySelector('.agimp-body');

  function close() {
    mask.remove();
    document.removeEventListener('keydown', onKey, true);
  }
  function onKey(e) { if (e.key === 'Escape') { e.stopPropagation(); close(); } }
  document.addEventListener('keydown', onKey, true);
  mask.addEventListener('mousedown', (e) => { if (e.target === mask) close(); });
  mask.querySelector('[data-x]').onclick = close;

  /* ---------- applicability / readiness ---------- */
  function applicable(p) {
    if (!p || p.error) return false;
    if (p.role === 'connect') return connectOk;
    if (p.role === 'fanout') return fanoutOk;
    return false;
  }
  function nopeText(p) {
    return p.role === 'connect' ? T('import.connectNope') : T('import.fanoutNope');
  }

  function setReady(on) {
    st.ready = on;
    const ok = body.querySelector('.agimp-ok');
    if (ok) ok.classList.toggle('ready', on);
  }

  /* ---------- preview rendering ---------- */
  function badgesHtml(p) {
    const b = [];
    b.push('<span class="badge b-info">' + (p.role === 'fanout' ? T('import.roleFanout') : T('import.roleConnect')) + '</span>');
    if (p.role === 'connect' && p.en) b.push('<span class="badge b-warn">' + T('import.e2e') + '</span>');
    if (p.role === 'connect' && p.en) b.push('<span class="badge ' + (p.emode === 'split' ? 'b-info' : 'b-off') + '">' + (p.emode === 'split' ? T('import.split') : T('import.dedicated')) + '</span>');
    if (p.role === 'connect' && p.eadmin) b.push('<span class="badge b-warn">' + T('import.adminScope') + '</span>');
    // M4-T5: the topology-visibility clause is surfaced as a badge + a clause card before apply
    if (p.role === 'connect' && (p.visibility === 'disclose' || p.visibility === 'approve')) b.push('<span class="badge b-warn">' + T('import.visibility.badge') + '</span>');
    if (p.insecure) b.push('<span class="badge b-warn">' + T('import.insecure') + '</span>');
    return '<div class="agimp-badges">' + b.join(' ') + '</div>';
  }
  function row(k, v, mono) {
    if (!v) return '';
    return '<div class="agimp-row"><span class="agimp-k">' + k + '</span><span class="agimp-v' + (mono ? ' mono' : '') + '">' + v + '</span></div>';
  }
  function previewHtml() {
    const p = st.parsed;
    if (!p) return '<div class="agimp-hint">' + T('import.empty') + '</div>';
    let h = '<div class="agimp-kv">' + badgesHtml(p);
    if (st.env) {
      h += row(T('import.from'), esc(st.env.issuer || '-'));
      h += row(T('common.createdAt'), esc((st.env.created_at || '').replace('T', ' ').replace(/\..*$/, '')));
      if (st.env.note) h += row(T('common.remark'), esc(st.env.note));
      if (st.fileName) h += row(T('import.file'), esc(st.fileName), true);
    } else {
      h += row(T('import.from'), esc(hostOf(p.addr)));
    }
    if (p.role === 'connect') {
      h += row(T('import.entry'), '<span class="mono">' + esc(p.addr) + '</span>' +
        ((p.entries || []).length > 1 ? ' <span class="badge b-info">' + T('import.entries', { n: p.entries.length }) + '</span>' : ''));
      h += row(T('import.account'), esc(p.account), true);
      if (p.en) h += row(T('import.e2e'), '<span class="mono">' + esc(p.en) + '</span>');
      // 我的名称 suggestion from the link (M4-T6): previewed here, saved with the credential
      if (p.myname) h += row(T('import.myname'), esc(p.myname));
    } else {
      h += row(T('import.target'), '<span class="mono">' + esc(p.addr) + '</span>');
      if (p.sni) h += row('SNI', '<span class="mono">' + esc(p.sni) + '</span>');
    }
    if (p.fp) h += row(T('import.fp'), '<span class="mono" title="' + esc(p.fp) + '">' + esc(fpShort(p.fp)) + '</span>');
    h += '</div>';
    if (st.needPin && !st.payload) {
      h += '<div class="agimp-pin"><span class="agimp-hint" style="margin-top:0">' + T('import.pinNeed') + '</span>' +
        '<input class="mono" data-pin maxlength="4" inputmode="numeric" autocomplete="off"></div>';
    }
    if (!applicable(p)) h += '<div class="agimp-hint">' + nopeText(p) + '</div>';
    if (st.err) h += '<div class="agimp-err">' + esc(st.err) + '</div>';
    return '<div class="agimp-preview">' + h + '</div>';
  }

  /* ---------- step 1: input (the input row renders once; only the preview below re-renders,
     so typing never loses focus mid-debounce) ---------- */
  function renderInput() {
    st.step = 'input';
    body.innerHTML =
      '<div class="agimp-input-row">' +
        '<input data-in class="mono" placeholder="' + T('import.ph') + '" autocomplete="off" spellcheck="false">' +
        '<button class="agimp-ic" data-paste title="' + T('import.pasteTitle') + '">' + AgIcon('clipboard', 16) + '</button>' +
        '<button class="agimp-ic" data-file title="' + T('import.fileTitle') + '">' + AgIcon('file', 16) + '</button>' +
        (cfg.pickQrImage ? '<button class="agimp-ic" data-qr title="' + T('import.qrTitle') + '">' + AgIcon('qr-code', 16) + '</button>' : '') +
        '<button class="agimp-ic agimp-ok" data-ok title="' + T('import.confirmTitle') + '">' + AgIcon('check', 17) + '</button>' +
      '</div>' +
      '<div data-preview></div>';

    const input = body.querySelector('[data-in]');
    if (st.link) input.value = st.link;

    let deb = null;
    input.addEventListener('input', () => {
      clearTimeout(deb);
      deb = setTimeout(() => acceptText(input.value), 280);
    });
    input.addEventListener('paste', () => setTimeout(() => acceptText(input.value), 0));
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); acceptText(input.value); } });

    body.querySelector('[data-paste]').onclick = async () => {
      let text = '';
      try { text = await pasteText(); } catch (e) { toast(T('import.badLink'), 'err'); return; }
      input.value = String(text || '').trim();
      acceptText(input.value);
      input.focus();
    };
    body.querySelector('[data-file]').onclick = async () => {
      let f = null;
      try { f = await cfg.pickAnetFile(); } catch (e) { toast(String(e && e.message || e), 'err'); return; }
      if (!f) return;
      acceptFile(f.content, f.name);
    };
    const qr = body.querySelector('[data-qr]');
    if (qr) qr.onclick = async () => {
      qr.classList.add('busy');
      let text = null;
      try { text = await cfg.pickQrImage(); } catch (e) { toast(String(e && e.message || e), 'err'); }
      qr.classList.remove('busy');
      if (!text) return;
      input.value = String(text).trim();
      acceptText(input.value);
    };
    body.querySelector('[data-ok]').onclick = () => { if (st.ready) advance(); };

    updatePreview();
    if (st.needPin && !st.payload) {
      const pin = body.querySelector('[data-pin]');
      if (pin) pin.focus();
    } else {
      input.focus();
    }
  }

  /* Re-render only the preview area + confirm-icon state (pin input gets its handler re-bound). */
  function updatePreview() {
    const box = body.querySelector('[data-preview]');
    if (!box) return;
    box.innerHTML = previewHtml();
    setReady(st.ready);
    const pin = box.querySelector('[data-pin]');
    if (pin) {
      pin.addEventListener('input', () => {
        const v = pin.value.trim();
        if (!/^\d{4}$/.test(v)) return;
        tryPin(v);
      });
    }
  }

  /* Adopt a text candidate: link first, then .anet JSON (pasted file contents), else error. */
  function acceptText(raw) {
    raw = String(raw || '').trim();
    st.err = '';
    if (!raw) { st.kind = null; st.parsed = null; st.link = ''; st.env = null; st.payload = null; st.needPin = false; st.ready = false; updatePreview(); return; }
    const p = AgLink.parse(raw);
    if (!p.error) {
      st.kind = 'link'; st.parsed = p; st.link = raw; st.env = null; st.payload = null; st.needPin = false;
      st.ready = applicable(p);
      updatePreview();
      return;
    }
    if (raw.startsWith('{')) {
      let parsed = null;
      try { parsed = AgAnet.parse(raw); } catch (e) { /* not an envelope either */ }
      if (parsed) { adoptEnvelope(parsed, ''); updatePreview(); return; }
    }
    st.kind = null; st.parsed = null; st.link = raw;
    st.err = T('import.badLink');
    st.ready = false;
    updatePreview();
  }

  /* Adopt a picked .anet file. */
  function acceptFile(content, name) {
    st.err = '';
    let parsed = null;
    try { parsed = AgAnet.parse(content); } catch (e) { parsed = null; }
    if (!parsed) {
      st.err = T('import.badLink');
      st.ready = false;
      updatePreview();
      return;
    }
    adoptEnvelope(parsed, name || '');
    updatePreview();
  }

  function adoptEnvelope(parsed, fileName) {
    st.kind = 'anet';
    st.env = parsed.envelope;
    st.fileName = fileName;
    st.needPin = parsed.needPin;
    st.payload = null;
    st.parsed = null;
    st.err = '';
    st.ready = false;
    if (!parsed.needPin) adoptPayload(parsed.envelope.payload);
  }

  /* Envelope payload -> effective link -> parsed preview (uniform with the pasted-link path). */
  function adoptPayload(payload) {
    st.payload = payload || {};
    const link = st.payload.link ||
      (st.env.role === 'fanout' ? AgLink.buildFanout(st.payload) : AgLink.buildConnect(st.payload));
    const p = AgLink.parse(link);
    if (p.error) { st.err = T('import.badLink'); st.ready = false; return; }
    st.link = link;
    st.parsed = p;
    st.ready = applicable(p);
  }

  async function tryPin(pin) {
    try {
      const payload = await AgAnet.decrypt(st.env, pin);
      adoptPayload(payload);
    } catch (e) {
      st.err = T('import.pinBad');
      st.ready = false;
    }
    updatePreview();
  }

  /* ---------- confirm -> apply (connect) or step 2 (fan-out) ---------- */
  async function advance() {
    if (st.parsed.role === 'connect') {
      // M4-T5: a topology-visibility clause must be acknowledged before the import proceeds
      const v = st.parsed.visibility;
      if ((v === 'disclose' || v === 'approve') && !st.clauseAccepted) {
        renderClause(v);
        return;
      }
      const okBtn = body.querySelector('[data-ok]');
      if (okBtn) okBtn.classList.add('busy');
      const r = await cfg.applyConnect({ parsed: st.parsed, link: st.link });
      if (r === true) { close(); if (cfg.onDone) cfg.onDone('connect'); return; }
      st.err = typeof r === 'string' ? r : T('common.failed');
      if (okBtn) okBtn.classList.remove('busy');
      updatePreview();
      return;
    }
    renderDetails();
  }

  /* ---------- clause card (M4-T5): topology-visibility terms, acknowledged once ---------- */
  function renderClause(v) {
    st.step = 'clause';
    body.innerHTML =
      '<div class="agimp-preview">' +
        '<div class="agimp-kv">' + badgesHtml(st.parsed) + '</div>' +
        '<div class="agimp-clause">' +
          '<div class="agimp-clause-title">' + AgIcon('shield', 15) + '<span>' + T('import.visibility.title') + '</span></div>' +
          '<div class="agimp-hint" style="margin-top:6px">' + T('import.visibility.' + v) + '</div>' +
        '</div>' +
      '</div>' +
      '<div class="agimp-foot">' +
        '<button class="ghost" data-back>' + T('import.back') + '</button>' +
        '<button data-accept>' + T('import.visibility.accept') + '</button>' +
      '</div>';
    body.querySelector('[data-back]').onclick = renderInput;
    body.querySelector('[data-accept]').onclick = () => { st.clauseAccepted = true; advance(); };
  }

  /* ---------- step 2: fan-out details ---------- */
  function renderDetails() {
    st.step = 'details';
    const p = st.parsed;
    body.innerHTML =
      previewHtml() +
      '<div class="agimp-start" data-startrow style="display:none"></div>' +
      '<div class="agimp-field"><label>' + T('import.nameLabel') + '</label>' +
        '<input data-name maxlength="64" placeholder="' + esc(p.addr) + '"></div>' +
      '<div class="agimp-field"><label>' + T('import.myname') + '</label>' +
        '<input data-myname maxlength="64"></div>' +
      '<div class="agimp-field"><label>' + T('import.remarkLabel') + '</label>' +
        '<input data-remark maxlength="256"></div>' +
      '<div class="agimp-err" data-err style="display:none"></div>' +
      '<div class="agimp-foot">' +
        '<button class="ghost" data-back>' + T('import.back') + '</button>' +
        '<button data-finish disabled>' + T('import.finish') + '</button>' +
      '</div>';

    body.querySelector('[data-back]').onclick = renderInput;
    const finish = body.querySelector('[data-finish]');
    const errBox = body.querySelector('[data-err]');
    // 我的名称 suggestion from the link prefills the upload name (M4-T6)
    if (p.myname) body.querySelector('[data-myname]').value = p.myname;
    finish.onclick = async () => {
      finish.disabled = true;
      errBox.style.display = 'none';
      const details = {
        name: body.querySelector('[data-name]').value.trim(),
        remark: body.querySelector('[data-remark]').value.trim(),
        myname: body.querySelector('[data-myname]').value.trim(),
      };
      const r = await cfg.applyFanout({ parsed: st.parsed, link: st.link }, details);
      if (r === true) { close(); if (cfg.onDone) cfg.onDone('fanout'); return; }
      errBox.textContent = typeof r === 'string' ? r : T('common.failed');
      errBox.style.display = 'block';
      finish.disabled = false;
    };

    /* Local server-role gate (GUI): fan-out rides the embedded node — offer a one-click start. */
    (async () => {
      if (!cfg.checkFanoutReady) { finish.disabled = false; return; }
      let env = { ready: true };
      try { env = await cfg.checkFanoutReady(); } catch (e) { env = { ready: true }; }
      if (!env || env.ready !== false) { finish.disabled = false; return; }
      const row = body.querySelector('[data-startrow]');
      row.style.display = 'flex';
      row.innerHTML = AgIcon('info', 15) + '<span style="flex:1">' + T('import.serverOff') + '</span>' +
        '<button class="ghost small" data-start>' + T('import.serverStart') + '</button>';
      row.querySelector('[data-start]').onclick = async (e) => {
        const btn = e.target.closest('button');
        btn.disabled = true;
        const r = await env.start();
        if (r === true) {
          row.style.display = 'none';
          finish.disabled = false;
        } else {
          btn.disabled = false;
          errBox.textContent = T('import.serverStartFail', { msg: typeof r === 'string' ? r : '' });
          errBox.style.display = 'block';
        }
      };
    })();
  }

  renderInput();
}

window.AgImport = { open };
})();
