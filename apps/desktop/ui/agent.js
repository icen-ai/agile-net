'use strict';
/* Split from app.js: network AI assistant drawer (white-hat agent).
   The backend (src/agent.rs) owns the conversation and keeps running with the drawer closed —
   this file is a pure view: render from agent_get_state, apply live agent-ev events.
   No history management by design (functional tool, not a chat product); the user clears manually. */

/* ---- Mini markdown (subset: ``` fences / `inline` / **bold** / - lists / paragraphs; esc() first, zero deps) ----
   Code blocks and pre render in the logv texture; everything outputs into .ag-text. */
function mdRender(src) {
  const escHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const inline = (s) => escHtml(s)
    .replace(/`([^`]+)`/g, (m, c) => '<code>' + c + '</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  const blocks = String(src || '').split(/```/);
  let out = '';
  blocks.forEach((b, i) => {
    if (i % 2 === 1) {
      // fenced code: drop a leading language tag line
      const code = b.replace(/^[a-zA-Z0-9_-]*\n/, '').replace(/\n$/, '');
      out += '<pre class="ag-pre">' + escHtml(code) + '</pre>';
      return;
    }
    const lines = b.split('\n');
    let inList = false;
    const closeList = () => { if (inList) { out += '</ul>'; inList = false; } };
    let para = [];
    const flushPara = () => {
      if (!para.length) return;
      out += '<p>' + para.map(inline).join('<br>') + '</p>';
      para = [];
    };
    for (const ln of lines) {
      const t = ln.trimEnd();
      const li = /^[-•]\s+(.+)/.exec(t);
      if (li) { flushPara(); if (!inList) { out += '<ul>'; inList = true; } out += '<li>' + inline(li[1]) + '</li>'; continue; }
      const num = /^\d+[.、)]\s*(.+)/.exec(t);
      if (num) { flushPara(); if (!inList) { out += '<ul>'; inList = true; } out += '<li>' + inline(num[1]) + '</li>'; continue; }
      if (!t.trim()) { flushPara(); closeList(); continue; }
      closeList();
      para.push(t);
    }
    flushPara(); closeList();
  });
  return out;
}

const Agent = {
  items: [], running: false, pending: null, skills: [], config: null,
  _listen: false, follow: true,

  isOpen() { return $('agent-drawer').classList.contains('open'); },
  async open() {
    $('agent-drawer').classList.add('open');
    this.listen();
    await this.refresh();
  },
  close() { $('agent-drawer').classList.remove('open'); $('ag-skills-pop').hidden = true; },
  toggle() { this.isOpen() ? this.close() : this.open(); },

  async refresh() {
    let s;
    try { s = await invoke('agent_get_state'); } catch (e) { return; }
    this.items = s.items || [];
    this.running = !!s.running;
    this.pending = s.pending || null;
    this.skills = s.skills || [];
    this.config = s.config || null;
    this.renderAll();
  },

  listen() {
    if (this._listen || HTTP_MODE) return;
    this._listen = true;
    TAURI.event.listen('agent-ev', (ev) => this.onEvent(ev.payload || {}));
  },

  onEvent(p) {
    if (p.k === 'delta') {
      const last = this.items[this.items.length - 1];
      if (last && last.role === 'assistant') {
        last.text += p.t;
        const el = this.body().querySelector('.ag-msg.asst:last-child .ag-text');
        if (el) el.innerHTML = mdRender(last.text);
        this.scrollMaybe();
      }
      return;
    }
    if (p.k === 'tool') {
      const last = this.items[this.items.length - 1];
      if (last && last.role === 'assistant') {
        let t = last.tools.find((x) => x.id === p.id);
        if (!t) { t = { id: p.id, name: p.name, args: p.args || '', status: 'running', result: '' }; last.tools.push(t); }
        if (p.status) t.status = p.status;
        if (p.args) t.args = p.args;
        if (p.result !== undefined) t.result = p.result;
        this.renderLastAssistant();
        this.scrollMaybe();
      }
      return;
    }
    if (p.k === 'confirm') { this.pending = { id: p.id, name: p.name, args: p.args }; this.renderPending(); this.scrollMaybe(); return; }
    if (p.k === 'confirm_clear') { this.pending = null; this.renderPending(); return; }
    if (p.k === 'running') {
      this.running = !!p.v;
      this.renderComposer();
      // a finished turn may have produced no delta listener-side updates for tool-only ends; resync silently
      if (!p.v) this.refresh();
      return;
    }
    if (p.k === 'retry') { this.appendNote(AgI18n.t('agent.retry', { n: p.n })); return; }
    if (p.k === 'error') { this.appendNote(String(p.t || ''), true); this.refresh(); return; }
    if (p.k === 'cleared') { this.items = []; this.pending = null; this.renderAll(); }
  },

  body() { return $('ag-body'); },
  scrollMaybe() { if (this.follow) { const b = this.body(); b.scrollTop = b.scrollHeight; } },

  /* ---------- Rendering ---------- */
  renderAll() {
    setText('ag-model', this.config && this.config.model ? this.config.model : AgI18n.t('agent.keyEmpty'));
    const b = this.body();
    if (!this.items.length) {
      b.innerHTML = this.welcomeHtml();
    } else {
      b.innerHTML = this.items.map((it) => this.itemHtml(it)).join('');
    }
    this.renderPending();
    this.renderChips();
    this.renderComposer();
    AgIconHydrate(b);
    this.scrollMaybe();
  },

  welcomeHtml() {
    const noKey = this.config && !this.config.has_key;
    return '<div class="ag-welcome">' +
      '<div class="ag-logo"><i data-ic="sparkles" data-sz="26"></i></div>' +
      '<div class="ag-w-t">' + AgI18n.t('agent.welcomeTitle') + '</div>' +
      '<div class="ag-w-d">' + AgI18n.t('agent.welcomeDesc') + '</div>' +
      (noKey ? '<div class="ag-w-warn"><span>' + AgI18n.t('agent.noKey') + '</span><button class="small" id="ag-go-settings">' + AgI18n.t('agent.goSettings') + '</button></div>' : '') +
      '</div>';
  },

  itemHtml(it) {
    if (it.role === 'user') {
      return '<div class="ag-msg user"><div class="ag-bubble">' + esc(it.text) + '</div></div>';
    }
    return '<div class="ag-msg asst"><div class="ag-text">' + mdRender(it.text) + '</div>' +
      (it.tools || []).map((t) => this.toolHtml(t)).join('') + '</div>';
  },

  toolHtml(t) {
    const stKey = { running: 'agent.toolRunning', done: 'agent.toolDone', denied: 'agent.toolDenied', failed: 'agent.toolFailed' }[t.status] || 'agent.toolRunning';
    const pillCls = t.status === 'done' ? 'pill-ok' : (t.status === 'denied' || t.status === 'failed') ? 'pill-danger' : 'pill-dim';
    const spin = t.status === 'running' ? '<span class="ag-spin"></span>' : '';
    return '<div class="ag-tool" data-tid="' + esc(t.id) + '">' +
      '<div class="ag-tool-h" data-tool-toggle>' + spin + '<i data-ic="settings" data-sz="12"></i>' +
      '<span class="mono ag-tool-name">' + esc(t.name) + '</span>' +
      '<span class="pill ' + pillCls + '">' + AgI18n.t(stKey) + '</span>' +
      '<i class="ag-chev" data-ic="chevron-down" data-sz="12"></i></div>' +
      '<div class="ag-tool-b" hidden>' +
      (t.args && t.args !== '{}' ? '<pre class="ag-pre">' + esc(t.args) + '</pre>' : '') +
      (t.result ? '<pre class="ag-pre">' + esc(t.result) + '</pre>' : '') +
      '</div></div>';
  },

  renderLastAssistant() {
    const last = this.items[this.items.length - 1];
    if (!last || last.role !== 'assistant') return;
    const el = this.body().querySelector('.ag-msg.asst:last-child');
    if (!el) return this.renderAll();
    el.outerHTML = this.itemHtml(last);
    AgIconHydrate(this.body());
  },

  renderPending() {
    const old = $('ag-confirm-card');
    if (old) old.remove();
    if (!this.pending) return;
    const p = this.pending;
    const card = document.createElement('div');
    card.id = 'ag-confirm-card';
    card.className = 'ag-confirm';
    card.innerHTML = '<div class="ag-c-t">' + AgI18n.t('agent.confirmTitle') + '</div>' +
      '<div class="mono ag-c-name">' + esc(p.name) + '</div>' +
      (p.args && p.args !== '{}' ? '<pre class="ag-pre">' + esc(p.args) + '</pre>' : '') +
      '<div class="ag-c-row"><button class="small" id="ag-allow">' + AgI18n.t('agent.allow') + '</button>' +
      '<button class="ghost small" id="ag-deny">' + AgI18n.t('agent.deny') + '</button></div>';
    this.body().appendChild(card);
    card.querySelector('#ag-allow').onclick = () => this.answerConfirm(true);
    card.querySelector('#ag-deny').onclick = () => this.answerConfirm(false);
  },
  async answerConfirm(allow) {
    const card = $('ag-confirm-card');
    if (card) card.querySelectorAll('button').forEach((x) => (x.disabled = true));
    try { await invoke('agent_confirm', { allow }); } catch (err) { toast(friendlyError(err), 'err'); }
  },

  renderChips() {
    const bar = $('ag-chips');
    const list = this.skills.filter((s) => s.enabled);
    bar.innerHTML = list.map((s) =>
      '<button class="ag-chip" data-skill="' + esc(s.id) + '" title="' + esc(s.desc || s.name) + '">' + esc(s.name) + '</button>').join('');
  },

  renderComposer() {
    $('ag-send').hidden = this.running;
    $('ag-stop').hidden = !this.running;
    $('ag-input').disabled = false;
  },

  renderSkillsPop() {
    const list = $('ag-skills-list');
    list.innerHTML = this.skills.map((s) =>
      '<div class="ag-skill-row"><input type="checkbox" class="sw" data-skill-toggle="' + esc(s.id) + '"' + (s.enabled ? ' checked' : '') + '>' +
      '<div class="ag-skill-info"><b>' + esc(s.name) + '</b><span class="dim">' + esc(s.desc || '') + '</span></div>' +
      (s.builtin ? '<span class="pill pill-dim">' + AgI18n.t('agent.skillBuiltin') + '</span>'
        : '<button class="ghost small icon-btn" data-skill-del="' + esc(s.id) + '" title="' + AgI18n.t('common.delete') + '">' + AgIcon('trash-2', 12) + '</button>') +
      '</div>').join('');
  },

  appendNote(text, isErr) {
    const div = document.createElement('div');
    div.className = 'ag-note' + (isErr ? ' err' : '');
    div.textContent = text;
    this.body().appendChild(div);
    this.scrollMaybe();
  },

  async send(text) {
    text = (text || '').trim();
    if (!text || this.running) return;
    if (this.config && !this.config.has_key) { toast(AgI18n.t('agent.noKey'), 'err'); return; }
    const input = $('ag-input');
    input.value = '';
    input.style.height = 'auto';
    this.items.push({ role: 'user', text, tools: [] });
    this.renderAll();
    try { await invoke('agent_send', { text }); } catch (err) {
      this.items.pop();
      this.renderAll();
      toast(friendlyError(err), 'err');
    }
  },

  async stop() {
    try { await invoke('agent_stop'); } catch (err) { toast(friendlyError(err), 'err'); }
  },

  async clear() {
    if (!(await askConfirm({ title: AgI18n.t('agent.clear'), desc: AgI18n.t('agent.clearConfirm'), icon: 'trash-2', danger: true }))) return;
    try { await invoke('agent_clear'); } catch (err) { toast(friendlyError(err), 'err'); }
  },
};

/* ---------- Settings card (BYOK) ---------- */
const AgentSettings = {
  PRESETS: {}, // filled from agent_get_state via config view; static list mirrors llm.rs PRESETS ids
  routeHint(preset, route) {
    const custom = preset === 'custom';
    return AgI18n.t(route === 'proxy' ? 'agent.routeProxy' : 'agent.routeDirect') + (custom ? '' : '');
  },
  async load() {
    if (HTTP_MODE) return;
    let s;
    try { s = await invoke('agent_get_state'); } catch (e) { return; }
    const c = s.config || {};
    const sel = $('agent-preset');
    if (!sel) return;
    sel.value = c.preset || 'deepseek';
    agSelectRefresh(sel);
    $('agent-model').value = c.model || '';
    $('agent-base').value = c.base_url || '';
    $('agent-base-row').hidden = c.preset !== 'custom';
    setText('agent-route-hint', this.routeHint(c.preset, c.route));
    setText('agent-key-state', c.has_key ? AgI18n.t('agent.keySaved') : AgI18n.t('agent.keyEmpty'));
  },
  async save() {
    const preset = $('agent-preset').value;
    const base = ($('agent-base').value || '').trim();
    const model = ($('agent-model').value || '').trim();
    const key = ($('agent-key').value || '').trim();
    try {
      await invoke('agent_config_set', {
        preset,
        baseUrl: preset === 'custom' ? base : null,
        model: model || null,
        apiKey: key || null,
      });
      $('agent-key').value = '';
      toast(AgI18n.t('agent.saved'), 'ok');
      this.load();
      Agent.refresh(); // model pill / welcome noKey state
    } catch (err) { toast(friendlyError(err), 'err'); }
  },
};

function initAgent() {
  if (HTTP_MODE) return;
  $('btn-agent').onclick = () => Agent.toggle();
  $('ag-close').onclick = () => Agent.close();
  $('ag-clear').onclick = () => Agent.clear();
  $('ag-send').onclick = () => Agent.send($('ag-input').value);
  $('ag-stop').onclick = () => Agent.stop();
  const input = $('ag-input');
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); Agent.send(input.value); }
  });
  // auto-grow (3 rows cap)
  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 84) + 'px';
  });
  // follow-output tracking (same idea as the log view)
  Agent.body().addEventListener('scroll', () => {
    const b = Agent.body();
    Agent.follow = b.scrollTop + b.clientHeight >= b.scrollHeight - 30;
  });
  // playbook chips (delegation)
  $('ag-chips').addEventListener('click', (e) => {
    const chip = e.target.closest('[data-skill]');
    if (!chip) return;
    const s = Agent.skills.find((x) => x.id === chip.dataset.skill);
    if (s) Agent.send('【' + s.name + '】');
  });
  // welcome-state settings jump (delegation; the button only exists when no key)
  Agent.body().addEventListener('click', (e) => {
    if (e.target.closest('#ag-go-settings')) { Agent.close(); switchView('settings'); }
    const tg = e.target.closest('[data-tool-toggle]');
    if (tg) {
      const body = tg.parentElement.querySelector('.ag-tool-b');
      if (body) body.hidden = !body.hidden;
      tg.classList.toggle('open');
    }
  });
  // config: jump to settings → AI assistant card
  $('ag-config-btn').onclick = () => {
    const drawer = $('agent-drawer');
    if (drawer) drawer.classList.remove('open');
    if (typeof switchView === 'function') switchView('settings');
    const card = $('agent-card');
    if (card) { card.scrollIntoView({ behavior: 'smooth', block: 'center' }); card.style.transition = 'box-shadow .4s'; card.style.boxShadow = '0 0 0 2px var(--accent)'; setTimeout(() => { card.style.boxShadow = ''; }, 1200); }
  };
  // skills popover
  $('ag-skills-btn').onclick = () => {
    const pop = $('ag-skills-pop');
    pop.hidden = !pop.hidden;
    if (!pop.hidden) Agent.renderSkillsPop();
  };
  $('ag-skills-pop').addEventListener('change', async (e) => {
    const t = e.target.closest('[data-skill-toggle]');
    if (!t) return;
    try { await invoke('agent_skill_toggle', { id: t.dataset.skillToggle, enabled: t.checked }); await Agent.refresh(); Agent.renderSkillsPop(); }
    catch (err) { toast(friendlyError(err), 'err'); }
  });
  $('ag-skills-pop').addEventListener('click', async (e) => {
    const del = e.target.closest('[data-skill-del]');
    if (del) {
      try { await invoke('agent_skill_delete', { id: del.dataset.skillDel }); await Agent.refresh(); Agent.renderSkillsPop(); }
      catch (err) { toast(friendlyError(err), 'err'); }
      return;
    }
    if (e.target.closest('#ag-skill-add')) {
      const name = $('ag-skill-name').value.trim();
      const prompt = $('ag-skill-prompt').value.trim();
      if (!name || !prompt) { toast(AgI18n.t('app.err.fillAll'), 'err'); return; }
      try {
        await invoke('agent_skill_save', { id: null, name, desc: null, prompt });
        $('ag-skill-name').value = '';
        $('ag-skill-prompt').value = '';
        toast(AgI18n.t('agent.skillAdded'), 'ok');
        await Agent.refresh();
        Agent.renderSkillsPop();
      } catch (err) { toast(friendlyError(err), 'err'); }
    }
  });
  // settings card
  $('agent-preset').onchange = () => {
    const p = $('agent-preset').value;
    $('agent-base-row').hidden = p !== 'custom';
    const route = p === 'openai' ? 'proxy' : 'direct';
    setText('agent-route-hint', AgentSettings.routeHint(p, route));
  };
  $('agent-save').onclick = () => AgentSettings.save();
  AgentSettings.load();
  Agent.listen(); // events flow even with the drawer closed (defense keeps running; reopen shows live state)
  Agent.refresh();
}

/* Language switch: re-render dynamic regions (chips/welcome/tool labels carry locale) */
AgI18n.onChange(() => { if (!HTTP_MODE) { Agent.renderAll(); AgentSettings.load(); } });
