'use strict';
/* Float ball bubble (float-bubble window): backend creates the window and emits ag-bubble-text (payload=string);
   this page updates the text and resets the 4s timer; on timeout it adds the fade-out class (opacity/translateX 300ms) then close() itself.
   Dynamic text always written via textContent (equivalent to esc, injection-proof). */
/* Theme must run on the first line to prevent flash (this script loads synchronously in head, before first paint) */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

let hideT = 0;   // 4s timeout timer
let closeT = 0;  // close-window timer after fade-out ends

function showText(text) {
  const card = $('bb-card');
  card.textContent = text;
  card.hidden = false;
  clearTimeout(hideT);
  clearTimeout(closeT);
  card.classList.remove('out');
  card.classList.add('show');
  hideT = setTimeout(() => {
    card.classList.add('out');
    closeT = setTimeout(() => {
      try { TAURI.window.getCurrentWindow().close(); } catch (e) {}
    }, 320); // slightly over the 300ms fade duration
  }, 4000);
}

/* ---------------- Startup ---------------- */
window.addEventListener('DOMContentLoaded', () => {
  AgI18n.hydrate(document);
  if (!invoke) {
    $('bb-noenv').hidden = false;
    return;
  }
  if (TAURI.event && TAURI.event.listen) {
    TAURI.event.listen('ag-theme', e => { document.documentElement.dataset.theme = e.payload; }).catch(() => {});
    TAURI.event.listen('ag-bubble-text', e => {
      const t = String(e.payload ?? '');
      if (t) showText(t); // empty text does not reset the timer, so an empty bubble can't displace visible content
    }).catch(() => {});
  }
  // Once ready, proactively take the pending text (backend no longer emits the first one, avoiding a lost event before the listener attaches → stuck empty bubble)
  invoke('float_bubble_take').then(t => {
    if (t) showText(String(t));
    else { try { TAURI.window.getCurrentWindow().close(); } catch (e) {} } // no notification: close self immediately
  }).catch(() => {
    try { TAURI.window.getCurrentWindow().close(); } catch (e) {}
  });
});
