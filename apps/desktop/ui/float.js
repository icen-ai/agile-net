'use strict';
/* Float ball: 72×72 fully transparent always-on window (fixed size; frontend never grows it via setSize/setPosition).
   - In-ball live speed (↓ primary / ↑ secondary, 2s polling of sub_traffic; logo dot when no traffic)
   - Left-drag (>4px threshold → startDragging; dragging state scales .94 + deeper shadow; edge snap on release)
   - Single click plays boing animation (260ms timer tells it apart from double click; animation harmless, not suppressed by double click) / double click opens main window
   - Right click invoke float_open_menu() (backend creates/shows float-menu window next to the ball)
   Render discipline: sig-compare, no DOM touch when data unchanged; polling paused while window hidden. */
/* Theme must run on the first line to prevent flash (this script loads synchronously in head, before first paint) */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

let speedSig = '';         // speed sig
let dragging = false;
let clickTimer = 0;

function win() { return TAURI.window.getCurrentWindow(); }
function inv(cmd, args) { return invoke(cmd, args).catch(() => null); }

/* ---------------- Polling (2s): live speed ---------------- */
function fmtShort(b) {
  b = +b || 0;
  if (b >= 1048576) return (b / 1048576).toFixed(1) + 'M';
  if (b >= 1024) return b >= 102400 ? Math.round(b / 1024) + 'K' : (b / 1024).toFixed(1) + 'K';
  return String(Math.round(b));
}

async function tick() {
  let sig = 'x'; // default: no data → logo dot
  try {
    const tr = await invoke('sub_traffic');
    if (tr) {
      const d = +tr.down_rate || 0, u = +tr.up_rate || 0;
      sig = (d || u) ? d + '/' + u : 'idle';
      if (sig !== speedSig) {
        speedSig = sig;
        if (sig === 'idle') {
          $('ball-speed').hidden = true;
          $('ball-idle').hidden = false;
        } else {
          $('ball-idle').hidden = true;
          $('ball-speed').hidden = false;
          $('sp-down').textContent = fmtShort(d);
          $('sp-up').textContent = fmtShort(u);
        }
      }
      return;
    }
  } catch (e) { /* treat command failure as no data */ }
  if (sig !== speedSig) {
    speedSig = sig;
    $('ball-speed').hidden = true;
    $('ball-idle').hidden = false;
  }
}

let pollT = 0;
function startLoops() { if (!pollT && invoke) { tick(); pollT = setInterval(tick, 2000); } }
function stopLoops() { clearInterval(pollT); pollT = 0; }

/* ---------------- Single-click boing ---------------- */
function boing() {
  const ball = $('ball');
  if (ball.classList.contains('boing')) return; // no stacking on rapid clicks
  ball.classList.add('boing');
}

/* ---------------- Drag / click / double-click / right-click ---------------- */
let moveTimer = 0;

function endDrag() {
  if (!dragging) return;
  dragging = false;
  $('ball').classList.remove('dragging');
  snapEdge();
}

/* Edge snap: snap when within 24px of the left/right screen edge (silently skip without permission).
   Must use inner_* (client area): outer_* on Windows includes the DWM invisible border (72→170);
   mixing them computes the ball off-screen (real incident: after right-edge snap half the ball was clipped). */
async function snapEdge() {
  if (!TAURI || !TAURI.window) return;
  try {
    const w = win();
    const [opos, ipos, isize, sf] = await Promise.all([
      w.outerPosition(), w.innerPosition(), w.innerSize(), w.scaleFactor(),
    ]);
    const offX = opos.x - ipos.x; // outer frame offset vs client area (used when writing back outer)
    const ixL = ipos.x / sf;      // ball client-area top-left x (logical)
    const bwL = isize.width / sf; // ball client-area width (logical, 72)
    const sw = window.screen.width;
    let tx = null;
    if (ixL <= 24) tx = 0;
    else if (ixL + bwL >= sw - 24) tx = Math.max(0, sw - bwL);
    if (tx === null) return;
    await w.setPosition(new TAURI.window.PhysicalPosition(Math.round(tx * sf + offX), opos.y));
  } catch (e) {}
}

function bindBall() {
  const ball = $('ball');

  ball.addEventListener('animationend', (e) => {
    if (e.animationName === 'fl-boing') ball.classList.remove('boing');
  });

  ball.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    const sx = e.clientX, sy = e.clientY;
    let moved = false;
    const onMove = (ev) => {
      if (moved) return;
      if (Math.hypot(ev.clientX - sx, ev.clientY - sy) > 4) {
        moved = true;
        dragging = true;
        ball.classList.add('dragging');
        try { win().startDragging(); } catch (err) { endDrag(); }
        window.removeEventListener('mousemove', onMove);
      }
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      if (moved) endDrag();
      else tap();
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  });

  // webview gets no mouseup during native drag: use window move events with 180ms silence to decide drag end
  if (TAURI && TAURI.window) {
    try {
      win().listen('tauri://move', () => {
        if (!dragging) return;
        clearTimeout(moveTimer);
        moveTimer = setTimeout(endDrag, 180);
      }).catch(() => {});
    } catch (e) {}
  }

  // single click (260ms to distinguish from double click): play boing only; double click: open main window directly
  function tap() {
    if (clickTimer) {
      clearTimeout(clickTimer);
      clickTimer = 0;
      inv('tray_show_main');
      return;
    }
    clickTimer = setTimeout(() => { clickTimer = 0; boing(); }, 260);
  }

  // right click: backend positions/creates/shows the float-menu window next to the ball (toggle semantics)
  document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    inv('float_open_menu');
  });
}

/* ---------------- Startup ---------------- */
window.addEventListener('DOMContentLoaded', () => {
  AgI18n.hydrate(document);
  $('ball').setAttribute('aria-label', AgI18n.t('float.winTitle'));
  if (!invoke) {
    $('fl-noenv').hidden = false;
    return;
  }
  $('fl-root').hidden = false;
  if (TAURI.event && TAURI.event.listen) {
    TAURI.event.listen('ag-theme', e => { document.documentElement.dataset.theme = e.payload; }).catch(() => {});
  }
  document.addEventListener('visibilitychange', () => { document.hidden ? stopLoops() : startLoops(); });
  bindBall();
  startLoops();
  // one-time initial position fix: backend computes placement from the outer frame; the Windows invisible border pushes the client area off-screen
  snapEdge();
});
