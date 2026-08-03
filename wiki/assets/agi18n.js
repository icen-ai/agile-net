// agi18n.js — AgileNet bilingual runtime (zh-CN / en-US), shared by desktop GUI and admin UI.
// Served to desktop via <script src>, to admin via include_str! (same as agchart.js/agutil.js).
// Dictionary is app-owned: each app registers its own entries via AgI18n.register().
// Static markup uses data-i18n (textContent), data-i18n-ph (placeholder), data-i18n-title (title).
// Dynamic JS strings use AgI18n.t(key, vars). Missing keys fall back to the key itself.
window.AgI18n = (() => {
  const STORE_KEY = 'ag-lang';
  const LANGS = ['zh', 'en'];
  let lang = localStorage.getItem(STORE_KEY) || ((navigator.language || 'zh').startsWith('zh') ? 'zh' : 'en');
  if (!LANGS.includes(lang)) lang = 'zh';
  let dict = Object.create(null);
  const listeners = [];

  // register({ 'menu.home': { zh: '首页', en: 'Home' }, ... })
  function register(d) { Object.assign(dict, d); }

  // t('common.deleted', { n: 3 }) -> '已删除 3 项' / 'Deleted 3 items'
  // Template placeholder: {name} in the source string.
  function t(key, vars) {
    const e = dict[key];
    let s = e ? (e[lang] ?? e.zh ?? key) : key;
    if (vars) for (const k in vars) s = s.replaceAll('{' + k + '}', String(vars[k]));
    return s;
  }

  function hydrate(root) {
    (root || document).querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
    (root || document).querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
    (root || document).querySelectorAll('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); });
  }

  function setLang(l) {
    if (!LANGS.includes(l) || l === lang) return;
    lang = l;
    localStorage.setItem(STORE_KEY, l);
    document.documentElement.lang = l === 'zh' ? 'zh-CN' : 'en';
    hydrate(document);
    listeners.forEach(f => f(l));
  }

  function onChange(f) { listeners.push(f); }

  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';

  return { register, t, hydrate, setLang, onChange, LANGS, get lang() { return lang; } };
})();
