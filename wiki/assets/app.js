'use strict';
/* AgileNet docs site frontend: hash routing + Markdown rendering + outline nav + full-text search + theme toggle + bilingual (zh/en).
   No build chain: marked.min.js inlined locally; all events bound explicitly (CSP script-src 'self').
   Bilingual: nav titles are nav.json inline {zh,en}; body content is content/<path>.md per AgI18n.lang
   or the English mirror content/en/<path>.md (falls back to zh with console.warn when the mirror is missing). */

const $ = (id) => document.getElementById(id);
const CONTENT_BASE = 'content/';
let NAV = null;          // nav.json
let PAGES = [];          // flattened [{group, title, path}] (titles already resolved to the current language)
let currentPath = null;
let searchIndex = null;  // built lazily
let searchActive = 0;

/* ================= utils ================= */
function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
  }[c]));
}

/* ================= i18n (AgI18n) ================= */
// nav.json group/title are {zh, en} (plain strings tolerated)
function label(v) {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  return v[AgI18n.lang] || v.zh || '';
}

// en mode prefers the content/en/ mirror; falls back to zh when missing
async function fetchMd(path) {
  if (AgI18n.lang === 'en') {
    try {
      const resp = await fetch(CONTENT_BASE + 'en/' + path + '.md');
      if (resp.ok) return await resp.text();
      console.warn('[i18n] en mirror missing, fallback to zh:', path);
    } catch (e) {
      console.warn('[i18n] en mirror fetch failed, fallback to zh:', path, e);
    }
  }
  const resp = await fetch(CONTENT_BASE + path + '.md');
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  return resp.text();
}

// lang switch button: shows the target language name (zh page shows English, and vice versa)
function applyLangBtn() {
  $('btn-lang-label').textContent = AgI18n.t(AgI18n.lang === 'zh' ? 'lang.en' : 'lang.zh');
}

// data-i18n-title hydrates the title attribute; mirror it to aria-label (a11y)
function syncAria() {
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    if (el.title) el.setAttribute('aria-label', el.title);
  });
}

/* ================= theme ================= */
function applyTheme() {
  document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';
  $('btn-theme').innerHTML = AgIcon(document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon', 16);
}

/* ================= nav ================= */
async function loadNav() {
  const resp = await fetch(CONTENT_BASE + 'nav.json');
  NAV = await resp.json();
  PAGES = [];
  const navEl = $('nav');
  navEl.innerHTML = NAV.map(g => {
    const group = label(g.group);
    const items = g.items.map(it => {
      const title = label(it.title);
      PAGES.push({ group, title, path: it.path });
      return '<a class="nav-item" data-path="' + it.path + '" href="#/' + it.path + '">' +
        AgIcon(it.icon || 'file-text', 14) + '<span>' + esc(title) + '</span></a>';
    }).join('');
    return '<div class="nav-group"><div class="nav-group-title">' + AgIcon(g.icon || 'layers', 13) +
      ' ' + esc(group) + '</div>' + items + '</div>';
  }).join('');
}

function markActiveNav(path) {
  document.querySelectorAll('.nav-item').forEach(a => {
    a.classList.toggle('active', a.dataset.path === path);
  });
}

/* ================= routing & rendering ================= */
function routePath() {
  const h = location.hash.replace(/^#\/?/, '');
  return h || 'index';
}

async function loadPage() {
  const path = routePath();
  if (path === currentPath) return;
  currentPath = path;
  markActiveNav(path);
  closeSidebar();

  const content = $('content');
  let md;
  try {
    md = await fetchMd(path);
  } catch (e) {
    content.innerHTML = '<h1>' + esc(AgI18n.t('ui.pageNotFound')) + '</h1>' +
      '<p>' + AgI18n.t('ui.noDocForPath', { path: '<code>' + esc(path) + '</code>' }) + '</p>' +
      '<p><a href="#/">' + esc(AgI18n.t('ui.backHome')) + '</a></p>';
    buildToc();
    return;
  }

  // marked: GFM tables, strikethrough; headerIds off (anchors generated manually)
  marked.setOptions({ gfm: true, breaks: false, headerIds: false, mangle: false });
  content.innerHTML = marked.parse(md);
  postRender(content);
  buildToc();
  const page = PAGES.find(p => p.path === path);
  document.title = (page ? page.title + ' — ' : '') + AgI18n.t('ui.siteTitle');
  window.scrollTo(0, 0);
}

function postRender(root) {
  // heading anchors
  root.querySelectorAll('h2, h3').forEach(h => {
    if (!h.id) h.id = slugify(h.textContent);
  });
  // external links: new window + icon
  root.querySelectorAll('a[href^="http"]').forEach(a => {
    a.target = '_blank';
    a.rel = 'noopener';
  });
  // code block copy button
  root.querySelectorAll('pre').forEach(pre => {
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.innerHTML = AgIcon('copy', 12) + esc(AgI18n.t('ui.copy'));
    btn.addEventListener('click', async () => {
      const code = pre.querySelector('code');
      try {
        await navigator.clipboard.writeText(code ? code.textContent : pre.textContent);
        btn.innerHTML = AgIcon('check', 12) + esc(AgI18n.t('ui.copied'));
        setTimeout(() => { btn.innerHTML = AgIcon('copy', 12) + esc(AgI18n.t('ui.copy')); }, 1600);
      } catch (e) { /* clipboard unavailable: stay silent */ }
    });
    pre.appendChild(btn);
  });
}

function slugify(text) {
  return text.trim().toLowerCase()
    .replace(/[\s]+/g, '-')
    .replace(/[^\w一-龥-]/g, '')
    .slice(0, 64);
}

/* ================= right-side TOC ================= */
function buildToc() {
  const toc = $('toc');
  const heads = $('content').querySelectorAll('h2, h3');
  if (!heads.length) { toc.innerHTML = ''; return; }
  let html = '<div class="toc-title">' + esc(AgI18n.t('ui.tocTitle')) + '</div>';
  heads.forEach(h => {
    html += '<a href="#' + h.id + '" data-h="' + h.id + '" class="' + (h.tagName === 'H3' ? 'l3' : '') + '">' +
      esc(h.textContent) + '</a>';
  });
  toc.innerHTML = html;
  toc.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const el = document.getElementById(a.dataset.h);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      history.replaceState(null, '', location.pathname + location.search + '#/' + currentPath + '~' + a.dataset.h);
    });
  });
}

// scroll-spy: highlight the current section
let tocSpy = false;
function initTocSpy() {
  if (tocSpy) return;
  tocSpy = true;
  window.addEventListener('scroll', () => {
    const links = $('toc').querySelectorAll('a');
    if (!links.length) return;
    let active = links[0];
    links.forEach(a => {
      const el = document.getElementById(a.dataset.h);
      if (el && el.getBoundingClientRect().top < 96) active = a;
    });
    links.forEach(a => a.classList.toggle('active', a === active));
  }, { passive: true });
}

/* ================= sidebar (mobile drawer) ================= */
function closeSidebar() {
  $('sidebar').classList.remove('open');
  $('sidebar-mask').classList.remove('open');
}

/* ================= search ================= */
async function ensureSearchIndex() {
  if (searchIndex) return searchIndex;
  const pages = PAGES.map(p => p.path);
  const texts = await Promise.all(pages.map(async p => {
    try {
      return await fetchMd(p);
    } catch (e) { return ''; }
  }));
  searchIndex = texts.map((raw, i) => ({
    path: pages[i],
    title: (PAGES.find(p => p.path === pages[i]) || {}).title || pages[i],
    group: (PAGES.find(p => p.path === pages[i]) || {}).group || '',
    text: raw
      .replace(/```[\s\S]*?```/g, ' ')   // strip code blocks
      .replace(/[#>*`|\-[\]()]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim(),
  }));
  return searchIndex;
}

function doSearch(q) {
  const box = $('search-results');
  q = q.trim().toLowerCase();
  searchActive = 0;
  if (!q) { box.innerHTML = '<div class="search-empty">' + esc(AgI18n.t('ui.searchEmpty')) + '</div>'; return; }
  const terms = q.split(/\s+/);
  const hits = [];
  for (const doc of searchIndex) {
    const lower = doc.text.toLowerCase();
    if (terms.every(t => lower.includes(t))) {
      // context snippet around the first keyword
      const idx = lower.indexOf(terms[0]);
      const start = Math.max(0, idx - 40);
      const snip = (start > 0 ? '…' : '') + doc.text.slice(start, idx + 90) + '…';
      hits.push({ doc, snip });
    }
    if (hits.length >= 12) break;
  }
  if (!hits.length) {
    box.innerHTML = '<div class="search-empty">' + esc(AgI18n.t('ui.searchNoHit', { q })) + '</div>';
    return;
  }
  box.innerHTML = hits.map((h, i) =>
    '<a class="search-result" data-i="' + i + '" href="#/' + h.doc.path + '">' +
    '<div class="sr-title">' + highlight(h.doc.title, terms) + '</div>' +
    '<div class="sr-path">' + esc(h.doc.group) + ' · ' + esc(h.doc.path) + '</div>' +
    '<div class="sr-snip">' + highlight(h.snip, terms) + '</div></a>'
  ).join('');
  box.querySelectorAll('.search-result').forEach(a => {
    a.addEventListener('click', closeSearch);
  });
}

function highlight(text, terms) {
  let out = esc(text);
  for (const t of terms) {
    if (!t) continue;
    out = out.replace(new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'), '<mark>$1</mark>');
  }
  return out;
}

function openSearch() {
  $('search-mask').style.display = 'flex';
  $('search-input').value = '';
  doSearch('');
  $('search-input').focus();
  ensureSearchIndex();
}
function closeSearch() {
  $('search-mask').style.display = 'none';
}

/* ================= startup ================= */
window.addEventListener('DOMContentLoaded', async () => {
  hydrateIcons(document);
  AgI18n.hydrate(document);
  syncAria();
  applyLangBtn();
  applyTheme();
  $('btn-lang').addEventListener('click', () => {
    AgI18n.setLang(AgI18n.lang === 'zh' ? 'en' : 'zh');
  });
  // lang switch: setLang has already hydrated static chrome; here rebuild nav/body/search index
  AgI18n.onChange(async () => {
    applyLangBtn();
    syncAria();
    searchIndex = null;
    await loadNav();
    markActiveNav(currentPath);
    currentPath = null;   // force refetching the body in the new language
    await loadPage();
  });
  $('btn-theme').addEventListener('click', () => {
    localStorage.setItem('ag_theme', document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    applyTheme();
  });
  $('btn-menu').addEventListener('click', () => {
    $('sidebar').classList.toggle('open');
    $('sidebar-mask').classList.toggle('open');
  });
  $('sidebar-mask').addEventListener('click', closeSidebar);
  $('btn-search').addEventListener('click', openSearch);
  $('search-mask').addEventListener('click', (e) => { if (e.target === $('search-mask')) closeSearch(); });
  $('search-input').addEventListener('input', (e) => doSearch(e.target.value));
  $('search-input').addEventListener('keydown', (e) => {
    const results = $('search-results').querySelectorAll('.search-result');
    if (e.key === 'Enter' && results.length) { results[searchActive].click(); }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      searchActive = (searchActive + (e.key === 'ArrowDown' ? 1 : -1) + results.length) % Math.max(results.length, 1);
      results.forEach((a, i) => a.classList.toggle('active', i === searchActive));
    }
  });
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openSearch(); }
    if (e.key === 'Escape') closeSearch();
  });

  await loadNav();
  await loadPage();
  initTocSpy();
});
window.addEventListener('hashchange', loadPage);
