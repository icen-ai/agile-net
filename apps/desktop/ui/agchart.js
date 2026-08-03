/* AgileNet shared chart component (agchart) — zero-dependency native SVG/JS, first shared JS component (AGENTS.md §6).
   Desktop loads via <script src="agchart.js">; admin UI serves it embedded via crates/node/src/ui/mod.rs at /ui/agchart.js.
   Colors always come from tokens.css var(--*); hardcoded color values forbidden, theme has no blue.
   Series colors (var(--*) strings) are resolved via getComputedStyle into real colors before being written to
   SVG presentation attributes (var() support inside presentation attributes is inconsistent across engines;
   grid/text colors go through CSS classes in components.css); theme switches take effect on the next draw.

   Two variants (API leaves room for extension):
   - AgChart.sparkline(el, series, opts)  minimal: trend line + gradient area only, no axes no labels
   - AgChart.line(el, cfg)                full: XY axis tick grid / multi-series / hover crosshair + per-point tooltip
     cfg = { x: [labels], series: [{name?, color?, values}], fmtX?, fmtY?, legend?, empty? }
     series may also be a plain value array [v,...] (single anonymous series)

   Behavior contract:
   - Repeated calls on the same element = idempotent update; no redraw while the data signature
     (x + series name/color/values) is unchanged
   - Data updates transition via rAF value interpolation (~400ms ease-out; equal-length point lists interpolate
     directly, unequal lists align by index with truncation, new points grow from the baseline);
     skipped under prefers-reduced-motion
   - Hover crosshair/tooltip follow by writing transform only, no reflow
   - ResizeObserver tracks container size (reflow lands on target values directly, data animation not replayed)
   Returns an instance { update, destroy }; all activity stops automatically once the element is removed. */
(function () {
'use strict';

var SVG_NS = 'http://www.w3.org/2000/svg';
/* Default series palette: primary --accent (near-black), secondary --dim2 (gray), then semantic colors (theme has no blue) */
var PALETTE = ['var(--accent)', 'var(--dim2)', 'var(--ok)', 'var(--warn)', 'var(--danger)'];
var DURATION = 400;
var uidSeq = 0;

function mk(tag, attrs, parent) {
  var n = document.createElementNS(SVG_NS, tag);
  if (attrs) for (var k in attrs) n.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(n);
  return n;
}

/* series normalization: accepts [v,...] or [{values, name?, color?},...] */
function normSeries(series) {
  if (!Array.isArray(series)) return [];
  if (!series.length) return [];
  if (typeof series[0] !== 'object' || series[0] === null) {
    return [{ name: '', values: series.map(function (v) { return +v || 0; }), color: '' }];
  }
  return series.map(function (s) {
    return {
      name: s.name || '',
      values: (s.values || []).map(function (v) { return +v || 0; }),
      color: s.color || '',
    };
  });
}

function sigOf(x, series) {
  return JSON.stringify([x || [], series.map(function (s) { return [s.name, s.color, s.values]; })]);
}

function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

/* Y-axis ceiling rounding (1/2/2.5/5×10^n steps, ~count tick levels) */
function niceMax(max, count) {
  if (!(max > 0)) return 1;
  var rough = max / count;
  var mag = Math.pow(10, Math.floor(Math.log10(rough)));
  var m = rough / mag;
  var step = (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * mag;
  return step * Math.ceil(max / step);
}

function defaultFmt(v) {
  v = +v || 0;
  var abs = Math.abs(v);
  if (abs >= 1e9) return (v / 1e9).toFixed(1) + 'G';
  if (abs >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (abs >= 1e3) return (v / 1e3).toFixed(1) + 'K';
  return String(Math.round(v * 100) / 100);
}

function num(v) { return Math.round(v * 100) / 100; }

/* Resolve var(--*) to a real color (for SVG presentation attributes; theme switches take effect on the next draw) */
function resolveColor(c) {
  var m = /^var\(\s*(--[\w-]+)\s*(?:,[^)]*)?\)$/.exec(c);
  if (m && typeof getComputedStyle === 'function') {
    var v = getComputedStyle(document.documentElement).getPropertyValue(m[1]);
    if (v) return v.trim();
  }
  return c;
}

/* Catmull-Rom smoothing to cubic bezier; control points clamped to the value range to avoid overshoot below the 0 baseline / above the ceiling */
function smoothPath(pts, yLo, yHi) {
  if (pts.length === 1) return 'M ' + num(pts[0][0]) + ' ' + num(pts[0][1]);
  var d = 'M ' + num(pts[0][0]) + ' ' + num(pts[0][1]);
  function clampY(y) { return Math.min(yLo, Math.max(yHi, y)); }
  for (var i = 0; i < pts.length - 1; i++) {
    var p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    var c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = clampY(p1[1] + (p2[1] - p0[1]) / 6);
    var c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = clampY(p2[1] - (p3[1] - p1[1]) / 6);
    d += ' C ' + num(c1x) + ' ' + num(c1y) + ' ' + num(c2x) + ' ' + num(c2y) + ' ' + num(p2[0]) + ' ' + num(p2[1]);
  }
  return d;
}

function Chart(el, kind) {
  this.el = el;
  this.kind = kind;
  this.id = ++uidSeq;
  this.cur = [];          // currently displayed series (animation intermediate state)
  this.data = null;       // target data
  this.sig = '';
  this.raf = 0;
  this.hover = -1;
  this.w = 0; this.h = 0;
  this.n = 0; this.ymax = 1;
  this.dots = [];
  this.gradColors = [];
  this.rcolors = [];      // resolved series colors (maintained by _resolveColors)
  this.tipKey = '';
  this._build();
  var self = this;
  this._ro = new ResizeObserver(function () { self._onResize(); });
  this._ro.observe(el);
}

Chart.prototype._build = function () {
  var self = this;
  this.el.classList.add('agchart');
  if (this.kind === 'line') {
    this.el.classList.add('agchart-line');
    this.legendEl = document.createElement('div');
    this.legendEl.className = 'agchart-legend';
    this.el.appendChild(this.legendEl);
    this.plot = document.createElement('div');
    this.plot.className = 'agchart-plot';
    this.el.appendChild(this.plot);
  } else {
    this.el.classList.add('agchart-spark');
    this.plot = this.el;
  }
  this.svg = mk('svg', { 'class': 'agchart-svg' }, this.plot);
  if (this.kind === 'line') {
    this.defs = mk('defs', null, this.svg);
    this.gGrid = mk('g', null, this.svg);
    this.gSeries = mk('g', null, this.svg);
    this.gCross = mk('g', { visibility: 'hidden' }, this.svg);
    this.crossLine = mk('line', { 'class': 'agc-cross', y1: 0, y2: 0 }, this.gCross);
    this.tip = document.createElement('div');
    this.tip.className = 'agchart-tip';
    this.tip.style.display = 'none';
    this.plot.appendChild(this.tip);
    this._onMove = function (e) { self._onPointer(e); };
    this._onLeave = function () { self.hover = -1; self._drawHover(); };
    this.plot.addEventListener('pointermove', this._onMove);
    this.plot.addEventListener('pointerleave', this._onLeave);
  } else {
    this.defs = mk('defs', null, this.svg);
    this.gSeries = mk('g', null, this.svg);
  }
};

/* ================= Layout ================= */
Chart.prototype._layout = function () {
  var w = this.plot.clientWidth, h = this.plot.clientHeight;
  if (w < 10 || h < 10 || !this.data) return false;
  this.w = w; this.h = h;
  if (this.kind === 'line') {
    this.padL = 64; this.padR = 14; this.padT = 10; this.padB = 22;
  } else {
    this.padL = 2; this.padR = 2; this.padT = 4; this.padB = 2;
  }
  var maxV = 0, n = this.kind === 'line' ? this.data.x.length : 0;
  this.data.series.forEach(function (s) {
    if (s.values.length > n) n = s.values.length;
    s.values.forEach(function (v) { if (v > maxV) maxV = v; });
  });
  this.n = n;
  /* full variant uses nice ticks; sparkline leaves 15% headroom at the top */
  this.ymax = this.kind === 'line' ? niceMax(maxV, 4) : (maxV > 0 ? maxV * 1.15 : 1);
  return true;
};
Chart.prototype._x = function (i) {
  var iw = this.w - this.padL - this.padR;
  return this.padL + (this.n <= 1 ? iw / 2 : i * iw / (this.n - 1));
};
Chart.prototype._y = function (v) {
  var ih = this.h - this.padT - this.padB;
  return this.padT + ih - (Math.max(0, v) / this.ymax) * ih;
};

/* ================= Data entry (signature change detection) ================= */
Chart.prototype._setData = function (cfg) {
  var series = normSeries(cfg.series);
  var sig = sigOf(cfg.x, series);
  if (sig === this.sig) return;
  this.sig = sig;
  this.data = {
    x: cfg.x || [],
    series: series,
    fmtX: cfg.fmtX || null,
    fmtY: cfg.fmtY || null,
    empty: cfg.empty || '暂无数据',
    legend: cfg.legend !== false,
  };
  this._resolveColors();
  /* Alignment: old values truncated by index, new points grow from baseline 0 */
  var cur = this.cur;
  var from = series.map(function (s, i) {
    var old = cur[i] ? cur[i].values : [];
    return s.values.map(function (v, j) { return j < old.length ? old[j] : 0; });
  });
  if (!this._layout()) { this._setCur(series); return; }
  this._drawAxes();
  this._drawLegend();
  this._animate(from);
};

Chart.prototype._setCur = function (series) {
  this.cur = series.map(function (s) { return { name: s.name, color: s.color, values: s.values.slice() }; });
};
Chart.prototype._curVals = function () {
  return this.cur.map(function (s) { return s.values; });
};

/* ================= Animation (rAF value interpolation) ================= */
Chart.prototype._animate = function (from) {
  var self = this;
  cancelAnimationFrame(this.raf);
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) {
    this._setCur(this.data.series);
    this._drawSeries(this._curVals());
    this._drawHover();
    return;
  }
  var start = -1;
  function frame(ts) {
    if (!self.el.isConnected) return;
    if (start < 0) start = ts;
    var t = Math.min(1, (ts - start) / DURATION);
    var e = easeOutCubic(t);
    self.cur = self.data.series.map(function (s, i) {
      return {
        name: s.name, color: s.color,
        values: s.values.map(function (v, j) {
          var f = from[i] && j < from[i].length ? from[i][j] : 0;
          return f + (v - f) * e;
        }),
      };
    });
    self._drawSeries(self._curVals());
    if (self.hover >= 0) self._drawHover();
    if (t < 1) self.raf = requestAnimationFrame(frame);
  }
  this.raf = requestAnimationFrame(frame);
};

/* ================= Drawing ================= */
/* Series color resolution: var(--*) → getComputedStyle real color (refreshed on _setData/_onResize; signature mechanism unchanged) */
Chart.prototype._resolveColors = function () {
  this.rcolors = this.data.series.map(function (s, i) {
    return resolveColor(s.color || PALETTE[i % PALETTE.length]);
  });
};

Chart.prototype._seriesColor = function (i) {
  return this.rcolors[i] || PALETTE[i % PALETTE.length];
};

Chart.prototype._drawAxes = function () {
  if (this.kind !== 'line') return;
  var g = this.gGrid;
  while (g.firstChild) g.removeChild(g.firstChild);
  var fmtY = this.data.fmtY || defaultFmt;
  if (!this.n) {
    var t = mk('text', {
      'class': 'agc-empty', x: this.w / 2, y: this.h / 2, 'text-anchor': 'middle',
    }, g);
    t.textContent = this.data.empty;
    return;
  }
  var levels = 4;
  for (var i = 0; i <= levels; i++) {
    var v = this.ymax * i / levels;
    var y = this._y(v);
    mk('line', { 'class': 'agc-grid', x1: this.padL, y1: y, x2: this.w - this.padR, y2: y }, g);
    var lbl = mk('text', { 'class': 'agc-lbl', x: this.padL - 8, y: y + 4, 'text-anchor': 'end' }, g);
    lbl.textContent = fmtY(v);
  }
  var iw = this.w - this.padL - this.padR;
  var maxLbl = Math.max(2, Math.floor(iw / 72));
  var step = Math.max(1, Math.ceil(this.n / maxLbl));
  for (var j = 0; j < this.n; j += step) {
    var raw = this.data.x[j];
    var xt = mk('text', { 'class': 'agc-lbl', x: this._x(j), y: this.h - 6, 'text-anchor': 'middle' }, g);
    xt.textContent = this.data.fmtX ? this.data.fmtX(raw, j) : String(raw == null ? '' : raw);
  }
};

Chart.prototype._drawLegend = function () {
  if (this.kind !== 'line') return;
  var el = this.legendEl;
  el.textContent = '';
  var named = this.data.series.filter(function (s) { return s.name; });
  if (!this.data.legend || named.length < 1) { el.style.display = 'none'; return; }
  el.style.display = '';
  var fmtY = this.data.fmtY || defaultFmt;
  this.data.series.forEach(function (s, i) {
    if (!s.name) return;
    var item = document.createElement('span');
    item.className = 'agchart-legend-item';
    var chip = document.createElement('span');
    chip.className = 'c';
    chip.style.background = s.color || PALETTE[i % PALETTE.length];
    item.appendChild(chip);
    var total = s.values.reduce(function (a, b) { return a + b; }, 0);
    item.appendChild(document.createTextNode(s.name + ' ' + fmtY(total)));
    el.appendChild(item);
  });
};

Chart.prototype._drawSeries = function (values2d) {
  var g = this.gSeries;
  while (g.firstChild) g.removeChild(g.firstChild);
  var yBase = this._y(0), yTop = this._y(this.ymax);
  for (var i = 0; i < this.data.series.length; i++) {
    var vals = values2d[i] || [];
    if (!vals.length) continue;
    var color = this._seriesColor(i);
    var pts = [];
    for (var j = 0; j < vals.length; j++) pts.push([this._x(j), this._y(vals[j])]);
    if (pts.length === 1) {
      mk('circle', { cx: pts[0][0], cy: pts[0][1], r: 3, fill: color }, g);
      continue;
    }
    var d = smoothPath(pts, yBase, yTop);
    if (this.kind !== 'line') {
      /* gradient area: series color 22% → fully transparent (stop-opacity avoids color-mix) */
      var gid = 'agc-grad-' + this.id + '-' + i;
      if (this.gradColors[i] !== color) {
        this.gradColors[i] = color;
        var old = this.defs.querySelector('#' + gid);
        if (old) old.remove();
        var grad = mk('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 }, this.defs);
        mk('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': 0.22 }, grad);
        mk('stop', { offset: '100%', 'stop-color': color, 'stop-opacity': 0 }, grad);
      }
      var area = d + ' L ' + num(pts[pts.length - 1][0]) + ' ' + num(yBase) + ' L ' + num(pts[0][0]) + ' ' + num(yBase) + ' Z';
      mk('path', { d: area, fill: 'url(#' + gid + ')', stroke: 'none' }, g);
    }
    mk('path', {
      d: d, fill: 'none', stroke: color,
      'stroke-width': this.kind === 'line' ? 2 : 1.8,
      'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    }, g);
  }
};

/* ================= hover (crosshair + tooltip, transform-follow without reflow) ================= */
Chart.prototype._onPointer = function (e) {
  if (!this.n) return;
  var rect = this.plot.getBoundingClientRect();
  var px = e.clientX - rect.left;
  var iw = this.w - this.padL - this.padR;
  var i = this.n <= 1 ? 0 : Math.round((px - this.padL) * (this.n - 1) / iw);
  i = Math.max(0, Math.min(this.n - 1, i));
  if (i !== this.hover) { this.hover = i; this.tipKey = ''; }
  this._drawHover();
};

Chart.prototype._drawHover = function () {
  if (this.kind !== 'line') return;
  var i = this.hover;
  if (i < 0 || !this.n || !this.data) {
    this.gCross.setAttribute('visibility', 'hidden');
    this.tip.style.display = 'none';
    return;
  }
  var x = this._x(i);
  this.gCross.setAttribute('visibility', 'visible');
  this.gCross.setAttribute('transform', 'translate(' + num(x) + ' 0)');
  this.crossLine.setAttribute('y1', this.padT);
  this.crossLine.setAttribute('y2', this.h - this.padB);
  /* one value dot per series (positioned at animated values) */
  var cur = this._curVals();
  while (this.dots.length < this.data.series.length) {
    this.dots.push(mk('circle', { 'class': 'agc-dot', r: 3.5 }, this.gCross));
  }
  for (var s = 0; s < this.dots.length; s++) {
    var dot = this.dots[s];
    if (s >= this.data.series.length || !cur[s] || cur[s][i] == null) { dot.setAttribute('visibility', 'hidden'); continue; }
    dot.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', 0);
    dot.setAttribute('cy', this._y(cur[s][i]));
    dot.setAttribute('stroke', this._seriesColor(s));
  }
  /* tooltip content rebuilt only when the hovered point or data changes; following only updates transform */
  var key = this.sig + '|' + i;
  if (this.tipKey !== key) {
    this.tipKey = key;
    this.tip.textContent = '';
    var title = document.createElement('div');
    title.className = 't';
    var raw = this.data.x[i];
    title.textContent = raw == null ? '' : String(raw);
    this.tip.appendChild(title);
    var fmtY = this.data.fmtY || defaultFmt;
    for (var k = 0; k < this.data.series.length; k++) {
      var sv = this.data.series[k];
      if (!sv.values.length) continue;
      var row = document.createElement('div');
      row.className = 'r';
      var chip = document.createElement('span');
      chip.className = 'c';
      chip.style.background = this._seriesColor(k);
      row.appendChild(chip);
      var nm = document.createElement('span');
      nm.className = 'n';
      nm.textContent = sv.name || '值';
      row.appendChild(nm);
      var vv = document.createElement('span');
      vv.className = 'v';
      vv.textContent = fmtY(sv.values[i] != null ? sv.values[i] : 0);
      row.appendChild(vv);
      this.tip.appendChild(row);
    }
  }
  this.tip.style.display = '';
  var flip = x > this.w * 0.62;
  var tx = flip ? x - 10 : x + 10;
  var ty = Math.max(4, this.padT + 2);
  this.tip.style.transform = 'translate(' + num(tx) + 'px,' + num(ty) + 'px)' + (flip ? ' translateX(-100%)' : '');
};

/* ================= Size tracking ================= */
Chart.prototype._onResize = function () {
  if (!this.data || !this.el.isConnected) return;
  if (!this._layout()) return;
  cancelAnimationFrame(this.raf);
  this._setCur(this.data.series);
  this._resolveColors();
  this._drawAxes();
  this._drawSeries(this._curVals());
  this._drawHover();
};

Chart.prototype.update = function (cfg) { this._setData(cfg); };

Chart.prototype.destroy = function () {
  cancelAnimationFrame(this.raf);
  if (this._ro) this._ro.disconnect();
  if (this.kind === 'line') {
    this.plot.removeEventListener('pointermove', this._onMove);
    this.plot.removeEventListener('pointerleave', this._onLeave);
  }
  this.el.textContent = '';
  this.el.classList.remove('agchart', 'agchart-line', 'agchart-spark');
  if (this.el.__agchart === this) this.el.__agchart = null;
};

function mount(el, kind, cfg) {
  if (!el) return null;
  var inst = el.__agchart;
  if (inst && inst.kind !== kind) { inst.destroy(); inst = null; }
  if (!inst) { inst = new Chart(el, kind); el.__agchart = inst; }
  inst._setData(cfg);
  return inst;
}

window.AgChart = {
  sparkline: function (el, series, opts) {
    opts = opts || {};
    return mount(el, 'spark', { series: series, empty: opts.empty });
  },
  line: function (el, cfg) {
    return mount(el, 'line', cfg || {});
  },
};
})();
