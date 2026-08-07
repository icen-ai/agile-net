'use strict';
/* AgTbl — implicit table enhancements + flicker-free row sync (shared component layer, AGENTS.md §6;
   desktop loads via <script src>; loaded after icons.js/agutil.js, before the app-*.js view files).

   - sync(tbody, items, opts): keyed row reconcile — row nodes PERSIST across polls; a changed row is
     patched in place (opts.patch) or swapped as a whole; order changes move the SAME node. No wholesale
     innerHTML rebuilds → no flicker, hover/focus/expansion survive. Foreign rows (no data-agk, e.g.
     detail expansions) are left untouched; the owning view re-anchors them after sync.
   - attach(table, opts): header chrome, all near-invisible until interaction —
       resize:  right-edge grip per column (drag; widths persist per table key)
       sort:    click a configured header cycles asc→desc→off (arrow only while active; persists)
       filter:  hover-revealed funnel per configured column; popover text query applies live (debounced)
     Header chrome is re-applied automatically after a language switch (data-i18n rehydration rewrites
     the header text nodes and would otherwise drop the glyphs).
   Dependencies: AgIcon (icons.js). esc (agutil.js) is used only for popover labels. */
const AgTbl = (() => {
  const registry = new Map();   // table key → { table, opts }

  /* ================= Row sync ================= */
  function makeRow(html, k, sig) {
    const t = document.createElement('template');
    t.innerHTML = html.trim();
    const tr = t.content.firstElementChild;
    tr.dataset.agk = k;
    tr._agsig = sig;
    return tr;
  }

  /* Keyed reconcile for any row-list container (tbody or div list). Element-agnostic:
     keyed children carry data-agk; a foreign child pinned to its anchor via el._agAfter (detail
     expansions) travels with it; unpinned foreign children (empty states) are removed. */
  function sync(container, items, opts) {
    const keyFn = opts.key, htmlFn = opts.html, patchFn = opts.patch || null;
    const sigFn = opts.sig || ((it) => JSON.stringify(it));
    const existing = new Map();
    for (const el of Array.from(container.children)) {
      if (el.dataset && el.dataset.agk) existing.set(el.dataset.agk, el);
      else if (!el._agAfter) el.remove(); // unpinned foreign rows (empty states) don't belong to the data set
    }
    const seen = new Set();
    // Reverse walk: placing each row before the previously placed one yields the exact item order;
    // the nextSibling check skips no-op moves so untouched rows never churn
    let before = null;
    for (let i = items.length - 1; i >= 0; i--) {
      const it = items[i];
      const k = keyFn(it);
      seen.add(k);
      let tr = existing.get(k);
      const sig = sigFn(it);
      if (tr && tr._agsig === sig) {
        // unchanged: keep the node (and its hover/expansion state) exactly as-is
      } else if (tr && patchFn && patchFn(tr, it)) {
        tr._agsig = sig;
      } else if (tr) {
        const fresh = makeRow(htmlFn(it), k, sig);
        tr.replaceWith(fresh);
        tr = fresh;
      } else {
        tr = makeRow(htmlFn(it), k, sig);
      }
      // a foreign row pinned to this one (open detail) travels as a unit
      const ns = tr.nextSibling;
      const tail = (ns && ns.nodeType === 1 && !ns.dataset.agk && ns._agAfter === tr) ? ns : null;
      const unit = tail || tr;
      if (unit.nextSibling !== before) {
        container.insertBefore(tr, before);
        if (tail) container.insertBefore(tail, before);
      }
      before = unit;
    }
    for (const [k, tr] of existing) if (!seen.has(k)) tr.remove();
  }

  /* ================= Header chrome (resize + sort + filter) ================= */
  // opts: { key, resize?: bool, sort?: {colIdx: sortId}, onSort?: (id, dir|null),
  //         filter?: {colIdx: {label}}, onFilter?: () }
  function attach(table, opts) {
    registry.set(opts.key, { table, opts });
    applyChrome(table, opts);
    if (opts.sort) restoreSort(table, opts);
  }

  function applyChrome(table, opts) {
    const row = table.tHead && table.tHead.rows[0];
    if (!row) return;
    const ths = row.cells;
    for (let i = 0; i < ths.length; i++) {
      const th = ths[i];
      if (opts.resize !== false && !th.querySelector('.th-grip')) {
        const grip = document.createElement('span');
        grip.className = 'th-grip';
        grip.addEventListener('mousedown', (e) => startDrag(e, table, opts.key, th));
        // a drag ending on the grip must not fall through to the sort click
        grip.addEventListener('click', (e) => e.stopPropagation());
        th.appendChild(grip);
      }
      if (opts.sort && opts.sort[i] !== undefined) {
        th.classList.add('th-sortable');
        if (!th._agSortBound) {
          th._agSortBound = true;
          th.addEventListener('click', (e) => {
            if (table._agResizing || e.target.closest('.th-grip') || e.target.closest('.th-f')) return;
            cycleSort(table, opts, i);
          });
        }
      }
      if (opts.filter && opts.filter[i] !== undefined && !th.querySelector('.th-f')) {
        const g = document.createElement('span');
        g.className = 'th-f';
        g.innerHTML = AgIcon('filter', 10);
        if (filterGet(opts.key, i)) g.classList.add('on');
        g.title = AgI18n.t('tbl.filter');
        g.addEventListener('click', (e) => { e.stopPropagation(); openPop(opts, i, th, g); });
        th.appendChild(g);
      }
    }
    if (opts.resize !== false) restoreWidths(table, opts.key);
    if (opts.sort) paintSort(table, opts);
  }

  /* ---------- column resize ---------- */
  function startDrag(e, table, key, th) {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startW = th.getBoundingClientRect().width;
    table._agResizing = true;
    th.classList.add('th-resizing');
    const move = (ev) => {
      const w = Math.max(44, Math.round(startW + ev.clientX - startX));
      th.style.width = w + 'px';
    };
    const up = () => {
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
      th.classList.remove('th-resizing');
      // swallow the click event that follows mouseup (it would toggle the sort)
      setTimeout(() => { table._agResizing = false; }, 0);
      const ths = table.tHead.rows[0].cells;
      const arr = [];
      for (let i = 0; i < ths.length; i++) arr.push(Math.round(ths[i].getBoundingClientRect().width));
      localStorage.setItem('agtbl-w-' + key, JSON.stringify(arr));
    };
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  }

  function restoreWidths(table, key) {
    let saved;
    try { saved = JSON.parse(localStorage.getItem('agtbl-w-' + key) || 'null'); } catch (e) { return; }
    if (!Array.isArray(saved)) return;
    const ths = table.tHead.rows[0].cells;
    for (let i = 0; i < ths.length && i < saved.length; i++) {
      if (saved[i]) ths[i].style.width = saved[i] + 'px';
    }
  }

  /* ---------- header sort ---------- */
  function sortState(key) {
    try { return JSON.parse(localStorage.getItem('agtbl-s-' + key) || 'null'); } catch (e) { return null; }
  }

  function cycleSort(table, opts, colIdx) {
    const id = opts.sort[colIdx];
    const cur = table._agSort || null;
    let next;
    if (!cur || cur.id !== id) next = { id, dir: 'asc' };
    else if (cur.dir === 'asc') next = { id, dir: 'desc' };
    else next = null;
    table._agSort = next;
    if (next) localStorage.setItem('agtbl-s-' + opts.key, JSON.stringify(next));
    else localStorage.removeItem('agtbl-s-' + opts.key);
    paintSort(table, opts);
    if (opts.onSort) opts.onSort(next ? next.id : null, next ? next.dir : null);
  }

  function paintSort(table, opts) {
    const ths = table.tHead.rows[0].cells;
    for (const [idxStr, id] of Object.entries(opts.sort)) {
      const th = ths[Number(idxStr)];
      if (!th) continue;
      const on = table._agSort && table._agSort.id === id;
      th.classList.toggle('th-on', !!on);
      let g = th.querySelector('.th-dir');
      if (on) {
        if (!g) { g = document.createElement('span'); g.className = 'th-dir'; th.appendChild(g); }
        g.textContent = table._agSort.dir === 'asc' ? '↑' : '↓';
      } else if (g) g.remove();
    }
  }

  function restoreSort(table, opts) {
    const st = sortState(opts.key);
    if (st && Object.values(opts.sort).includes(st.id)) {
      table._agSort = st;
      paintSort(table, opts);
      // the owning view reads AgTbl.sortState(key) itself when (re)fetching — no onSort replay here
    }
  }

  /* ---------- column filter (popover): text input or enum multi-select chips ---------- */
  const filterState = new Map(); // table key → { colIdx: string (text) | string[] (enum) }
  let popEl = null, popAway = null;

  /* Unset reads as '' — enum consumers should do `filterGet(k, i) || []`, text consumers `|| ''` */
  function filterGet(key, idx) {
    const m = filterState.get(key);
    if (!m || m[idx] === undefined) return '';
    return m[idx];
  }

  function filterSet(key, idx, v) {
    let m = filterState.get(key);
    if (!m) { m = {}; filterState.set(key, m); }
    const empty = Array.isArray(v) ? v.length === 0 : !v;
    if (empty) delete m[idx]; else m[idx] = v;
  }

  function closePop() {
    if (popEl) { popEl.remove(); popEl = null; }
    if (popAway) { document.removeEventListener('mousedown', popAway); popAway = null; }
  }

  function openPop(opts, idx, th, glyph) {
    closePop();
    const conf = opts.filter[idx];
    const rect = th.getBoundingClientRect();
    popEl = document.createElement('div');
    popEl.className = 'th-pop';
    if (conf.type === 'enum') {
      // business-value multi-select (OR): applies immediately on toggle
      const cur = new Set(filterGet(opts.key, idx) || []);
      popEl.innerHTML = '<div class="th-pop-vals">' + conf.options.map(o =>
        '<label class="th-pop-v"><input type="checkbox" value="' + esc(o.v) + '"' + (cur.has(o.v) ? ' checked' : '') +
        '><span>' + esc(AgI18n.t(o.label)) + '</span></label>').join('') + '</div>';
      popEl.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.addEventListener('change', () => {
        const sel = [];
        popEl.querySelectorAll('input[type="checkbox"]:checked').forEach(c => sel.push(c.value));
        filterSet(opts.key, idx, sel);
        glyph.classList.toggle('on', sel.length > 0);
        if (opts.onFilter) opts.onFilter();
      }));
    } else {
      popEl.innerHTML = '<input type="text" placeholder="' + esc(AgI18n.t(conf.label || '') || '') + '">';
      const input = popEl.firstChild;
      input.value = filterGet(opts.key, idx) || '';
      let deb = null;
      input.addEventListener('input', () => {
        clearTimeout(deb);
        deb = setTimeout(() => {
          const q = input.value.trim();
          filterSet(opts.key, idx, q);
          glyph.classList.toggle('on', !!q);
          if (opts.onFilter) opts.onFilter();
        }, 200);
      });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' || e.key === 'Enter') closePop();
        e.stopPropagation();
      });
    }
    document.body.appendChild(popEl);
    popEl.style.left = Math.max(8, Math.min(rect.left, window.innerWidth - popEl.offsetWidth - 8)) + 'px';
    popEl.style.top = (rect.bottom + 4) + 'px';
    const input = popEl.querySelector('input[type="text"]');
    if (input) input.focus();
    popAway = (ev) => { if (popEl && !popEl.contains(ev.target)) closePop(); };
    setTimeout(() => document.addEventListener('mousedown', popAway), 0);
  }

  /* Language switch: data-i18n rehydration rewrites header text nodes, dropping our glyphs —
     re-apply the chrome for every attached table (state lives outside the DOM, so nothing is lost) */
  if (window.AgI18n) {
    AgI18n.onChange(() => {
      closePop();
      for (const { table, opts } of registry.values()) applyChrome(table, opts);
    });
  }

  return { sync, attach, sortState, filterGet, closePop };
})();
