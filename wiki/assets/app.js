'use strict';
/* AgileNet 文档站前端：hash 路由 + Markdown 渲染 + 大纲导航 + 全文搜索 + 主题切换。
   无构建链：marked.min.js 本地内嵌，全部事件显式绑定（CSP script-src 'self'）。 */

const $ = (id) => document.getElementById(id);
const CONTENT_BASE = 'content/';
let NAV = null;          // nav.json
let PAGES = [];          // 展平的 [{group, title, path}]
let currentPath = null;
let searchIndex = null;  // 懒构建
let searchActive = 0;

/* ================= 工具 ================= */
function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
  }[c]));
}

/* ================= 主题 ================= */
function applyTheme() {
  document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';
  $('btn-theme').innerHTML = AgIcon(document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon', 16);
}

/* ================= 导航 ================= */
async function loadNav() {
  const resp = await fetch(CONTENT_BASE + 'nav.json');
  NAV = await resp.json();
  PAGES = [];
  const navEl = $('nav');
  navEl.innerHTML = NAV.map(g => {
    const items = g.items.map(it => {
      PAGES.push({ group: g.group, title: it.title, path: it.path });
      return '<a class="nav-item" data-path="' + it.path + '" href="#/' + it.path + '">' +
        AgIcon(it.icon || 'file-text', 14) + '<span>' + esc(it.title) + '</span></a>';
    }).join('');
    return '<div class="nav-group"><div class="nav-group-title">' + AgIcon(g.icon || 'layers', 13) +
      ' ' + esc(g.group) + '</div>' + items + '</div>';
  }).join('');
}

function markActiveNav(path) {
  document.querySelectorAll('.nav-item').forEach(a => {
    a.classList.toggle('active', a.dataset.path === path);
  });
}

/* ================= 路由与渲染 ================= */
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
    const resp = await fetch(CONTENT_BASE + path + '.md');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    md = await resp.text();
  } catch (e) {
    content.innerHTML = '<h1>页面不存在</h1><p>路径 <code>' + esc(path) + '</code> 没有对应文档。</p>' +
      '<p><a href="#/">返回首页</a></p>';
    buildToc();
    return;
  }

  // marked：GFM 表格、删除线；headerIds 关闭（自行生成锚点）
  marked.setOptions({ gfm: true, breaks: false, headerIds: false, mangle: false });
  content.innerHTML = marked.parse(md);
  postRender(content);
  buildToc();
  const page = PAGES.find(p => p.path === path);
  document.title = (page ? page.title + ' — ' : '') + 'AgileNet 文档';
  window.scrollTo(0, 0);
}

function postRender(root) {
  // 标题锚点
  root.querySelectorAll('h2, h3').forEach(h => {
    if (!h.id) h.id = slugify(h.textContent);
  });
  // 外链新窗口 + 图标
  root.querySelectorAll('a[href^="http"]').forEach(a => {
    a.target = '_blank';
    a.rel = 'noopener';
  });
  // 代码块复制按钮
  root.querySelectorAll('pre').forEach(pre => {
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.innerHTML = AgIcon('copy', 12) + '复制';
    btn.addEventListener('click', async () => {
      const code = pre.querySelector('code');
      try {
        await navigator.clipboard.writeText(code ? code.textContent : pre.textContent);
        btn.innerHTML = AgIcon('check', 12) + '已复制';
        setTimeout(() => { btn.innerHTML = AgIcon('copy', 12) + '复制'; }, 1600);
      } catch (e) { /* 剪贴板不可用时静默 */ }
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

/* ================= 右侧 TOC ================= */
function buildToc() {
  const toc = $('toc');
  const heads = $('content').querySelectorAll('h2, h3');
  if (!heads.length) { toc.innerHTML = ''; return; }
  let html = '<div class="toc-title">本页内容</div>';
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

// 滚动高亮当前小节
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

/* ================= 侧栏（移动端抽屉） ================= */
function closeSidebar() {
  $('sidebar').classList.remove('open');
  $('sidebar-mask').classList.remove('open');
}

/* ================= 搜索 ================= */
async function ensureSearchIndex() {
  if (searchIndex) return searchIndex;
  const pages = PAGES.map(p => p.path);
  const texts = await Promise.all(pages.map(async p => {
    try {
      const resp = await fetch(CONTENT_BASE + p + '.md');
      return resp.ok ? await resp.text() : '';
    } catch (e) { return ''; }
  }));
  searchIndex = texts.map((raw, i) => ({
    path: pages[i],
    title: (PAGES.find(p => p.path === pages[i]) || {}).title || pages[i],
    group: (PAGES.find(p => p.path === pages[i]) || {}).group || '',
    text: raw
      .replace(/```[\s\S]*?```/g, ' ')   // 去代码块
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
  if (!q) { box.innerHTML = '<div class="search-empty">输入关键字开始搜索</div>'; return; }
  const terms = q.split(/\s+/);
  const hits = [];
  for (const doc of searchIndex) {
    const lower = doc.text.toLowerCase();
    if (terms.every(t => lower.includes(t))) {
      // 取首个关键词的上下文片段
      const idx = lower.indexOf(terms[0]);
      const start = Math.max(0, idx - 40);
      const snip = (start > 0 ? '…' : '') + doc.text.slice(start, idx + 90) + '…';
      hits.push({ doc, snip });
    }
    if (hits.length >= 12) break;
  }
  if (!hits.length) {
    box.innerHTML = '<div class="search-empty">没有找到「' + esc(q) + '」相关内容</div>';
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

/* ================= 启动 ================= */
window.addEventListener('DOMContentLoaded', async () => {
  hydrateIcons(document);
  applyTheme();
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
