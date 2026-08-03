// lang-switcher.js — language selector driver for the desktop main window.
// The control lives in index.html settings view: <select id="lang-select"> (options zh/en, lang.zh/lang.en keys).
// All logic stays here (CSP: no inline scripts / no inline event attributes); loaded before the app-*.js series.
(() => {
  // One-time migration from the legacy ag_lang key (pre-i18n s-lang) into the AgI18n store key.
  if (!localStorage.getItem('ag-lang') && localStorage.getItem('ag_lang') === 'en') AgI18n.setLang('en');

  // Delegated change handling: works regardless of enhancement timing (agSelectEnhance keeps the
  // original select as the value source, so a single document-level listener is enough).
  document.addEventListener('change', (e) => {
    const sel = e.target && e.target.id === 'lang-select' ? e.target : null;
    if (sel) AgI18n.setLang(sel.value);
  });

  document.addEventListener('DOMContentLoaded', () => {
    const sel = document.getElementById('lang-select');
    if (sel) sel.value = AgI18n.lang;
    AgI18n.hydrate(document);
  });
})();
