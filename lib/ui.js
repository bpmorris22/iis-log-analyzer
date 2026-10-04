/* IIS Log Analyzer - ui.js
 * DOM helpers (text-node only for evidence data), virtualized grid, SVG charts,
 * dialogs, context menus, progress panel, toasts.
 * SECURITY: evidence-derived strings must only ever reach the DOM through
 * text nodes / textContent / setAttribute. Never innerHTML.
 */
(function (NS) {
  'use strict';
  var U = NS.util, UI = NS.ui = {};
  var SVGNS = 'http://www.w3.org/2000/svg';

  /* ---------- element builder ---------- */
  /* h('div', {className:'x', style:{...}, onclick:fn, title:'..'}, [children | 'text']) */
  UI.h = function (tag, attrs, kids) {
    var e = document.createElement(tag), k, v;
    if (attrs) {
      for (k in attrs) {
        if (!attrs.hasOwnProperty(k)) { continue; }
        v = attrs[k];
        if (v === null || v === undefined || v === false) { continue; }
        if (k === 'style' && typeof v === 'object') { UI.css(e, v); } else if (k.substr(0, 2) === 'on' && typeof v === 'function') { e[k] = v; } else if (k === 'className') { e.className = v; } else if (k === 'text') { e.textContent = U.stripCtl(v); } else if (k === 'value') { e.value = v; } else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'readOnly') { e[k] = !!v; } else { e.setAttribute(k, '' + v); }
      }
    }
    UI.append(e, kids);
    return e;
  };
  UI.append = function (e, kids) {
    if (kids === null || kids === undefined) { return e; }
    if (!(kids instanceof Array)) { kids = [kids]; }
    var i, c;
    for (i = 0; i < kids.length; i++) {
      c = kids[i];
      if (c === null || c === undefined || c === false) { continue; }
      if (typeof c === 'string' || typeof c === 'number') { e.appendChild(document.createTextNode(U.stripCtl('' + c))); } else if (c instanceof Array) { UI.append(e, c); } else { e.appendChild(c); }
    }
    return e;
  };
  /* ---------- UI scaling ----------
   * mshta renders HTML at 100% even when Windows runs at 150-200% DPI, so the app scales
   * itself: every px value in app.css is multiplied by UI.scale, and JS-sized elements
   * (grid rows, column widths, charts, dialog widths) go through UI.px(). */
  UI.scale = 1;
  UI.px = function (n) { return Math.round(n * UI.scale); };
  UI.dpiScale = function () {
    var d = 96;
    try { d = screen.deviceXDPI || screen.logicalXDPI || 96; } catch (e) { }
    return Math.max(1, Math.min(3, d / 96));
  };
  var baseCss = null;
  UI.applyScale = function (s) {
    UI.scale = Math.max(0.6, Math.min(4, s));
    var link = UI.$('appcss'), out = UI.$('appcss-scaled');
    if (baseCss === null) {
      if (link && link.tagName === 'LINK') { baseCss = NS.io.resource('lib/app.css') || ''; } else if (link) { baseCss = link.textContent || (link.styleSheet ? link.styleSheet.cssText : ''); }
      if (!baseCss) { return; }
    }
    var scaled = baseCss.replace(/(\d*\.?\d+)px/g, function (m, n) { var v = parseFloat(n) * UI.scale; return (v < 1 && v > 0 ? 1 : Math.round(v * 10) / 10) + 'px'; });
    if (!out) { out = document.createElement('style'); out.id = 'appcss-scaled'; document.getElementsByTagName('head')[0].appendChild(out); }
    try { out.textContent = scaled; } catch (e) { out.styleSheet.cssText = scaled; }
    if (link) { try { link.disabled = true; } catch (e2) { } if (link.tagName === 'STYLE') { link.media = 'not all'; } }
  };
  var SCALE_KEYS = { width: 1, height: 1, minWidth: 1, maxWidth: 1, minHeight: 1, maxHeight: 1 };
  UI.css = function (e, st) {
    var k, v, m;
    for (k in st) {
      if (!st.hasOwnProperty(k)) { continue; }
      v = st[k];
      if (SCALE_KEYS[k] === 1 && typeof v === 'string' && (m = /^(\d+(?:\.\d+)?)px$/.exec(v))) { v = UI.px(+m[1]) + 'px'; }
      try { e.style[k] = v; } catch (x) { }
    }
    return e;
  };
  UI.clear = function (e) { while (e && e.firstChild) { e.removeChild(e.firstChild); } return e; };
  UI.text = function (e, s) { e.textContent = U.stripCtl(s === null || s === undefined ? '' : '' + s); return e; };
  UI.$ = function (id) { return document.getElementById(id); };
  UI.btn = function (label, onclick, cls, title) { return UI.h('button', { className: 'btn ' + (cls || ''), onclick: onclick, title: title, type: 'button' }, label); };
  /* Vertical traffic light: state 'red' | 'amber' | 'green' lights one lamp. */
  UI.trafficLight = function (state, title) {
    var lamps = ['red', 'amber', 'green'].map(function (c) { return UI.h('span', { className: 'tl-l ' + c + (c === state ? ' on' : '') }); });
    return UI.h('span', { className: 'tl', title: title || '', role: 'img', 'aria-label': title || state }, lamps);
  };
  UI.link = function (label, onclick, title) {
    return UI.h('a', { href: '#', className: 'lnk', title: title, onclick: function (ev) { (ev || window.event).preventDefault(); onclick(ev); return false; } }, label);
  };
  UI.select = function (options, value, onchange, attrs) {
    var s = UI.h('select', attrs || {}), i, o;
    for (i = 0; i < options.length; i++) {
      o = options[i] instanceof Array ? options[i] : [options[i], options[i]];
      s.appendChild(UI.h('option', { value: o[0], selected: '' + o[0] === '' + value }, o[1]));
    }
    if (onchange) { s.onchange = function () { onchange(s.value); }; }
    return s;
  };
  UI.input = function (value, attrs) { var a = U.extend({ type: 'text', value: value === undefined ? '' : value }, attrs || {}); return UI.h('input', a); };
  UI.field = function (label, control, hint) {
    return UI.h('label', { className: 'field' }, [UI.h('span', { className: 'field-l' }, label), control, hint ? UI.h('span', { className: 'hint' }, hint) : null]);
  };
  UI.kv = function (rows) {
    var t = UI.h('table', { className: 'kv' }), i;
    for (i = 0; i < rows.length; i++) {
      if (!rows[i]) { continue; }
      t.appendChild(UI.h('tr', null, [UI.h('th', null, rows[i][0]), UI.h('td', { className: rows[i][2] || '' }, rows[i][1])]));
    }
    return t;
  };
  UI.card = function (title, value, sub, cls, onclick) {
    return UI.h('div', { className: 'card ' + (cls || '') + (onclick ? ' clickable' : ''), onclick: onclick }, [
      UI.h('div', { className: 'card-t' }, title), UI.h('div', { className: 'card-v' }, value), sub ? UI.h('div', { className: 'card-s' }, sub) : null]);
  };
  UI.section = function (title, kids, tools) {
    return UI.h('div', { className: 'section' }, [UI.h('div', { className: 'section-h' }, [UI.h('span', null, title), tools ? UI.h('span', { className: 'section-tools' }, tools) : null]), UI.h('div', { className: 'section-b' }, kids)]);
  };
  UI.sevBadge = function (sev) { return UI.h('span', { className: 'sev sev-' + sev }, sev); };
  UI.table = function (headers, rows, opts) {
    opts = opts || {};
    var t = UI.h('table', { className: 'tbl ' + (opts.className || '') }), tr = UI.h('tr'), i, j, r, td;
    for (i = 0; i < headers.length; i++) { tr.appendChild(UI.h('th', null, headers[i])); }
    t.appendChild(UI.h('thead', null, tr));
    var tb = UI.h('tbody');
    for (i = 0; i < rows.length; i++) {
      r = rows[i]; tr = UI.h('tr', { className: opts.rowClass ? opts.rowClass(i) : '' });
      if (opts.onRow) { tr.className += ' clickable'; tr.onclick = (function (ix) { return function (e) { opts.onRow(ix, e || window.event); }; }(i)); }
      for (j = 0; j < r.length; j++) { td = UI.h('td'); UI.append(td, r[j]); tr.appendChild(td); }
      tb.appendChild(tr);
    }
    t.appendChild(tb);
    return t;
  };

  /* ---------- toasts ---------- */
  UI.toast = function (msg, kind, ms) {
    var host = UI.$('toasts'); if (!host) { return; }
    var t = UI.h('div', { className: 'toast ' + (kind || 'info') }, msg);
    host.appendChild(t);
    setTimeout(function () { if (t.parentNode) { t.parentNode.removeChild(t); } }, ms || (kind === 'error' ? 9000 : 4000));
  };

  /* ---------- dialogs ---------- */
  UI.dialog = function (opts) {
    var ov = UI.h('div', { className: 'overlay' }), box = UI.h('div', { className: 'dialog', style: { width: (opts.width || 560) + 'px' } }), i;
    var foot = UI.h('div', { className: 'dialog-f' });
    var dlg = { el: ov, close: function () { if (ov.parentNode) { ov.parentNode.removeChild(ov); } document.onkeydown = prevKey; if (opts.onClose) { opts.onClose(); } } };
    box.appendChild(UI.h('div', { className: 'dialog-h' }, [UI.h('span', null, opts.title || ''), UI.h('span', { className: 'x', title: 'Close (Esc)', onclick: function () { dlg.close(); } }, '\u00d7')]));
    box.appendChild(UI.h('div', { className: 'dialog-b', style: opts.height ? { height: opts.height + 'px' } : null }, opts.body));
    var bs = opts.buttons || [{ label: 'Close' }];
    for (i = 0; i < bs.length; i++) {
      (function (b) {
        foot.appendChild(UI.btn(b.label, function () { var keep = b.onClick ? b.onClick(dlg) : undefined; if (keep !== false) { dlg.close(); } }, b.primary ? 'primary' : ''));
      }(bs[i]));
    }
    box.appendChild(foot);
    ov.appendChild(box);
    document.body.appendChild(ov);
    var prevKey = document.onkeydown;
    document.onkeydown = function (e) {
      e = e || window.event;
      if (e.keyCode === 27) { dlg.close(); return false; }
      if (e.keyCode === 13 && opts.enterButton !== undefined && (e.target || e.srcElement).tagName !== 'TEXTAREA') {
        var b = bs[opts.enterButton]; var keep = b.onClick ? b.onClick(dlg) : undefined; if (keep !== false) { dlg.close(); } return false;
      }
      return true;
    };
    setTimeout(function () { var f = box.querySelector('input,textarea,select'); if (f) { try { f.focus(); } catch (x) { } } }, 30);
    return dlg;
  };
  UI.alert = function (title, msg) { UI.dialog({ title: title, body: UI.h('div', { className: 'pre-wrap' }, msg), buttons: [{ label: 'OK', primary: true }], enterButton: 0 }); };
  UI.confirm = function (title, msg, onYes, yesLabel) {
    UI.dialog({ title: title, body: UI.h('div', { className: 'pre-wrap' }, msg), buttons: [{ label: yesLabel || 'OK', primary: true, onClick: function () { onYes(); } }, { label: 'Cancel' }] });
  };
  UI.prompt = function (title, label, value, onOk, multiline) {
    var inp = multiline ? UI.h('textarea', { rows: 6, style: { width: '100%' } }) : UI.input(value, { style: { width: '100%' } });
    if (multiline) { inp.value = value || ''; }
    UI.dialog({ title: title, body: [UI.h('div', { className: 'mb' }, label), inp], enterButton: multiline ? undefined : 0,
      buttons: [{ label: 'OK', primary: true, onClick: function () { return onOk(inp.value); } }, { label: 'Cancel' }] });
  };

  /* ---------- progress ---------- */
  UI.progress = function (title, onCancel) {
    var bar = UI.h('div', { className: 'pbar-fill' }), info = UI.h('div', { className: 'pinfo' }, 'Starting...'), cur = UI.h('div', { className: 'pcur' }, '');
    var body = UI.h('div', null, [UI.h('div', { className: 'pbar' }, bar), info, cur]);
    var cancelled = false;
    var dlg = UI.dialog({ title: title, body: body, width: 520, buttons: onCancel ? [{ label: 'Cancel', onClick: function () { cancelled = true; UI.text(info, 'Cancelling...'); onCancel(); return false; } }] : [] });
    return {
      update: function (p) {
        var frac = p.bytesTotal ? p.bytesDone / p.bytesTotal : (p.files ? p.file / p.files : 0);
        bar.style.width = Math.max(0, Math.min(100, frac * 100)).toFixed(1) + '%';
        if (cancelled) { return; }
        UI.text(info, (p.files ? 'File ' + Math.min(p.file + 1, p.files) + ' / ' + p.files + '  \u00b7  ' : '') +
          (p.rows !== undefined ? U.fmtNum(p.rows) + ' rows  \u00b7  ' : '') + (p.rate ? U.fmtNum(p.rate) + ' rows/s  \u00b7  ' : '') +
          (p.bytesTotal ? U.fmtBytes(p.bytesDone) + ' / ' + U.fmtBytes(p.bytesTotal) + '  \u00b7  ' : '') + (p.eta ? 'ETA ' + U.fmtDuration(p.eta * 1000) : '') + (p.msg || ''));
        UI.text(cur, p.current || '');
      },
      close: function () { dlg.close(); }
    };
  };

  /* ---------- context menu ---------- */
  UI.menu = function (x, y, items) {
    UI.closeMenu();
    var m = UI.h('div', { className: 'menu', id: 'ctxmenu' }), i;
    for (i = 0; i < items.length; i++) {
      (function (it) {
        if (!it) { return; }
        if (it.sep) { m.appendChild(UI.h('div', { className: 'menu-sep' })); return; }
        if (it.header) { m.appendChild(UI.h('div', { className: 'menu-h' }, it.header)); return; }
        m.appendChild(UI.h('div', { className: 'menu-i' + (it.disabled ? ' disabled' : ''), onclick: function () { UI.closeMenu(); if (!it.disabled) { it.onClick(); } } }, it.label));
      }(items[i]));
    }
    document.body.appendChild(m);
    var W = document.documentElement.clientWidth, H = document.documentElement.clientHeight;
    var mw = m.offsetWidth, mh = m.offsetHeight;
    m.style.left = Math.max(0, Math.min(x, W - mw - 4)) + 'px';
    m.style.top = Math.max(0, Math.min(y, H - mh - 4)) + 'px';
    setTimeout(function () { document.onmousedown = function (e) { var t = (e || window.event).target; while (t) { if (t.id === 'ctxmenu') { return; } t = t.parentNode; } UI.closeMenu(); }; }, 0);
  };
  UI.closeMenu = function () { var m = UI.$('ctxmenu'); if (m) { m.parentNode.removeChild(m); } document.onmousedown = null; };

  /* ---------- clipboard ---------- */
  UI.copy = function (text) {
    try { window.clipboardData.setData('Text', text); UI.toast('Copied ' + U.fmtNum(text.length) + ' characters'); return true; } catch (e) { UI.toast('Clipboard unavailable: ' + e.message, 'error'); return false; }
  };

  /* ---------- virtualized grid ---------- */
  var MAXH = 1000000;
  /* opts: columns [{key,label,w,num}], count(), cell(row,key)->string, rowClass(row), onSelect(row), onActivate(row),
   *       onContext(row,key,x,y), onSort(key), sortKey, sortDesc, rowH, onColumns(cols) */
  UI.VGrid = function (host, opts) {
    var self = this;
    this.o = opts; this.pinned = opts.pinned || 0; this.rh = opts.rowH || UI.px(20); this.cols = UI.scaleCols(opts.columns); this.first = 0; this.sel = -1; this.anchor = -1; this.multi = {}; this.multiN = 0;
    this.root = UI.h('div', { className: 'vg', tabIndex: 0 });
    this.head = UI.h('div', { className: 'vg-head' });
    this.headIn = UI.h('div', { className: 'vg-head-in' });
    this.head.appendChild(this.headIn);
    this.body = UI.h('div', { className: 'vg-body' });
    this.spacer = UI.h('div', { className: 'vg-spacer' });
    this.layer = UI.h('div', { className: 'vg-layer' });
    this.body.appendChild(this.spacer); this.body.appendChild(this.layer);
    this.empty = UI.h('div', { className: 'vg-empty' }, opts.emptyText || 'No rows');
    this.root.appendChild(this.head); this.root.appendChild(this.body); this.root.appendChild(this.empty);
    UI.clear(host); host.appendChild(this.root);
    this.pool = [];
    this.body.onscroll = function () {
      self.headIn.style.marginLeft = -self.body.scrollLeft + 'px';
      self.applyPins();
      if (self.ignoreScroll) { self.ignoreScroll = false; return; }
      self.firstFromScroll(); self.render();
    };
    var wheel = function (e) {
      e = e || window.event;
      if (!self.scaled) { return true; }
      var d = e.wheelDelta ? -e.wheelDelta / 40 : (e.deltaY || 0) / 33;
      self.scrollTo(self.first + Math.round(d));
      if (e.preventDefault) { e.preventDefault(); } e.returnValue = false; return false;
    };
    this.body.onmousewheel = wheel;
    this.root.onkeydown = function (e) { return self.key(e || window.event); };
    this.layer.onmousedown = function (e) {
      e = e || window.event;
      var r = self.rowAt(e); if (r < 0) { return; }
      self.root.focus();
      if (e.button === 2) { if (!self.multi[r]) { self.select(r, false, false); } return; }
      self.select(r, e.ctrlKey, e.shiftKey);
    };
    this.layer.ondblclick = function (e) { var r = self.rowAt(e || window.event); if (r >= 0 && self.o.onActivate) { self.o.onActivate(r); } };
    this.layer.oncontextmenu = function (e) {
      e = e || window.event;
      var r = self.rowAt(e); if (r < 0 || !self.o.onContext) { return true; }
      var key = self.colAt(e);
      self.o.onContext(r, key, e.clientX, e.clientY);
      if (e.preventDefault) { e.preventDefault(); } return false;
    };
    this.renderHead();
    this.refresh();
  };
  /* Column widths in view code are given at 100%; the grid works in scaled pixels. */
  UI.scaleCols = function (cols) { var out = [], i; for (i = 0; i < cols.length; i++) { out.push(U.extend({}, cols[i], { w: UI.px(cols[i].w) })); } return out; };
  UI.unscaleCols = function (cols) { var out = [], i; for (i = 0; i < cols.length; i++) { out.push(U.extend({}, cols[i], { w: Math.round(cols[i].w / UI.scale) })); } return out; };
  UI.VGrid.prototype.totalW = function () { var w = 0, i; for (i = 0; i < this.cols.length; i++) { w += this.cols[i].w; } return w; };
  UI.VGrid.prototype.renderHead = function () {
    var self = this, i, x = 0;
    UI.clear(this.headIn);
    this.headIn.style.width = (this.totalW() + 30) + 'px';
    for (i = 0; i < this.cols.length; i++) {
      (function (c, left) {
        var arrow = self.o.sortKey === c.key ? (self.o.sortDesc ? ' \u25bc' : ' \u25b2') : '';
        var cell = UI.h('div', { className: 'vg-hc' + (c.num ? ' num' : ''), title: (c.title || c.label) + (self.o.onSort ? ' (click to sort)' : '') }, c.label + arrow);
        cell.style.left = left + 'px'; cell.style.width = (c.w - 1) + 'px';
        cell.onclick = function (e) { if (self.resizing) { return; } if (self.o.onSort) { self.o.onSort(c.key); } };
        var grip = UI.h('div', { className: 'vg-grip' });
        grip.onmousedown = function (e) {
          e = e || window.event; self.resizing = true;
          var sx = e.clientX, sw = c.w;
          document.onmousemove = function (ev) { ev = ev || window.event; c.w = Math.max(UI.px(30), sw + ev.clientX - sx); self.renderHead(); self.layoutRows(); self.render(); };
          document.onmouseup = function () { document.onmousemove = null; document.onmouseup = null; setTimeout(function () { self.resizing = false; }, 50); if (self.o.onColumns) { self.o.onColumns(UI.unscaleCols(self.cols)); } };
          if (e.stopPropagation) { e.stopPropagation(); } e.cancelBubble = true; return false;
        };
        cell.appendChild(grip);
        self.headIn.appendChild(cell);
      }(this.cols[i], x));
      x += this.cols[i].w;
    }
    this.applyPins();
  };
  /* Keeps the first `pinned` columns in place during horizontal scrolling. */
  UI.VGrid.prototype.applyPins = function () {
    if (!this.pinned) { return; }
    var sl = this.body ? this.body.scrollLeft : 0, x = 0, j, i, hc = this.headIn.childNodes;
    for (j = 0; j < this.pinned && j < this.cols.length; j++) {
      if (hc[j]) { hc[j].style.left = (x + sl) + 'px'; hc[j].className = hc[j].className.replace(/ pin/g, '') + ' pin'; }
      for (i = 0; i < this.pool.length; i++) { var c = this.pool[i].cells[j]; c.style.left = (x + sl) + 'px'; if (c.className.indexOf(' pin') < 0) { c.className += ' pin'; } }
      x += this.cols[j].w;
    }
  };
  UI.VGrid.prototype.setColumns = function (cols) { this.cols = UI.scaleCols(cols); this.pool = []; UI.clear(this.layer); this.renderHead(); this.refresh(); };
  UI.VGrid.prototype.layoutRows = function () {
    var i, j, row, x, tw = this.totalW();
    this.layer.style.width = tw + 'px';
    this.spacer.style.width = tw + 'px';
    for (i = 0; i < this.pool.length; i++) {
      row = this.pool[i]; row.el.style.width = tw + 'px'; x = 0;
      for (j = 0; j < this.cols.length; j++) { row.cells[j].style.left = x + 'px'; row.cells[j].style.width = (this.cols[j].w - 1) + 'px'; x += this.cols[j].w; }
    }
    this.applyPins();
  };
  UI.VGrid.prototype.visibleCount = function () { return Math.max(1, Math.ceil((this.body.clientHeight || 400) / this.rh)); };
  UI.VGrid.prototype.refresh = function (keepPos) {
    var n = this.o.count();
    this.n = n;
    var full = n * this.rh;
    this.scaled = full > MAXH;
    this.spacer.style.height = Math.min(full, MAXH) + 'px';
    this.empty.style.display = n ? 'none' : 'block';
    if (!keepPos) { this.first = 0; this.sel = Math.min(this.sel, n - 1); this.ignoreScroll = true; this.body.scrollTop = 0; }
    if (this.first > Math.max(0, n - 1)) { this.first = Math.max(0, n - this.visibleCount()); }
    this.ensurePool();
    this.render();
  };
  UI.VGrid.prototype.ensurePool = function () {
    var need = this.visibleCount() + 2, i, j, el, cells, c;
    if (this.pool.length >= need && this.pool.length && this.pool[0].cells.length === this.cols.length) { return; }
    if (this.pool.length && this.pool[0].cells.length !== this.cols.length) { this.pool = []; UI.clear(this.layer); }
    for (i = this.pool.length; i < need; i++) {
      el = UI.h('div', { className: 'vg-row' }); cells = [];
      for (j = 0; j < this.cols.length; j++) { c = UI.h('div', { className: 'vg-c' + (this.cols[j].num ? ' num' : '') }); el.appendChild(c); cells.push(c); }
      el.style.top = (i * this.rh) + 'px'; el.style.height = this.rh + 'px';
      this.layer.appendChild(el); this.pool.push({ el: el, cells: cells, row: -2 });
    }
    this.layoutRows();
  };
  UI.VGrid.prototype.firstFromScroll = function () {
    var st = this.body.scrollTop, vis = this.visibleCount();
    if (!this.scaled) { this.first = Math.floor(st / this.rh); } else {
      var maxS = Math.max(1, MAXH - this.body.clientHeight);
      this.first = Math.round(st / maxS * Math.max(0, this.n - vis + 1));
    }
    this.first = Math.max(0, Math.min(this.first, Math.max(0, this.n - 1)));
  };
  UI.VGrid.prototype.scrollTo = function (row) {
    var vis = this.visibleCount();
    row = Math.max(0, Math.min(row, Math.max(0, this.n - vis + 1)));
    this.first = row;
    this.ignoreScroll = true;
    if (!this.scaled) { this.body.scrollTop = row * this.rh; } else {
      var maxS = Math.max(1, MAXH - this.body.clientHeight);
      this.body.scrollTop = Math.round(row / Math.max(1, this.n - vis + 1) * maxS);
    }
    this.render();
  };
  UI.VGrid.prototype.render = function () {
    this.ensurePool();
    var i, j, r, p, top, cls, st = this.body.scrollTop;
    top = this.scaled ? st : this.first * this.rh;
    this.layer.style.top = top + 'px';
    for (i = 0; i < this.pool.length; i++) {
      p = this.pool[i]; r = this.first + i;
      if (r >= this.n) { p.el.style.display = 'none'; p.row = -1; continue; }
      p.el.style.display = 'block';
      cls = 'vg-row' + (r % 2 ? ' odd' : '') + (r === this.sel || this.multi[r] ? ' sel' : '');
      if (this.o.rowClass) { cls += ' ' + (this.o.rowClass(r) || ''); }
      p.el.className = cls;
      p.row = r;
      for (j = 0; j < this.cols.length; j++) {
        var v = this.o.cell(r, this.cols[j].key);
        v = v === null || v === undefined ? '' : '' + v;
        if (v.length > 2000) { v = v.substr(0, 2000) + '\u2026'; }
        p.cells[j].textContent = U.stripCtl(v);
      }
    }
  };
  UI.VGrid.prototype.rowAt = function (e) {
    var t = e.target || e.srcElement, i;
    while (t && t !== this.layer && (' ' + t.className + ' ').indexOf(' vg-row ') < 0) { t = t.parentNode; }
    if (!t || t === this.layer) { return -1; }
    for (i = 0; i < this.pool.length; i++) { if (this.pool[i].el === t) { return this.pool[i].row; } }
    return -1;
  };
  UI.VGrid.prototype.colAt = function (e) {
    var t = e.target || e.srcElement, row, i, j;
    for (i = 0; i < this.pool.length; i++) { row = this.pool[i]; for (j = 0; j < row.cells.length; j++) { if (row.cells[j] === t) { return this.cols[j].key; } } }
    return null;
  };
  UI.VGrid.prototype.select = function (r, ctrl, shift) {
    if (r < 0 || r >= this.n) { return; }
    var i;
    if (shift && this.anchor >= 0) {
      this.multi = {}; this.multiN = 0;
      var a = Math.min(this.anchor, r), b = Math.max(this.anchor, r);
      if (b - a > 200000) { b = a + 200000; }
      for (i = a; i <= b; i++) { this.multi[i] = 1; this.multiN++; }
    } else if (ctrl) {
      if (this.multi[r]) { delete this.multi[r]; this.multiN--; } else { this.multi[r] = 1; this.multiN++; }
      this.anchor = r;
    } else { this.multi = {}; this.multiN = 0; this.anchor = r; }
    this.sel = r;
    var vis = this.visibleCount();
    if (r < this.first) { this.scrollTo(r); } else if (r >= this.first + vis - 1) { this.scrollTo(r - vis + 2); } else { this.render(); }
    if (this.o.onSelect) { this.o.onSelect(r); }
  };
  UI.VGrid.prototype.selection = function () {
    var out = [], k;
    for (k in this.multi) { out.push(+k); }
    if (!out.length && this.sel >= 0) { out.push(this.sel); }
    out.sort(function (a, b) { return a - b; });
    return out;
  };
  UI.VGrid.prototype.key = function (e) {
    var k = e.keyCode, vis = this.visibleCount(), s = this.sel < 0 ? 0 : this.sel;
    var move = null;
    if (k === 40) { move = s + 1; } else if (k === 38) { move = s - 1; } else if (k === 34) { move = s + vis - 1; } else if (k === 33) { move = s - vis + 1; } else if (k === 36 && e.ctrlKey) { move = 0; } else if (k === 35 && e.ctrlKey) { move = this.n - 1; }
    if (move !== null) { this.select(Math.max(0, Math.min(this.n - 1, move)), false, e.shiftKey); return false; }
    if (k === 13 && this.sel >= 0 && this.o.onActivate) { this.o.onActivate(this.sel); return false; }
    if (k === 65 && e.ctrlKey && this.n <= 200000) { this.multi = {}; this.multiN = 0; for (var i = 0; i < this.n; i++) { this.multi[i] = 1; this.multiN++; } this.render(); return false; }
    if (k === 67 && e.ctrlKey && this.o.onCopy) { this.o.onCopy(this.selection(), e.shiftKey); return false; }
    if (k === 93 && this.sel >= 0 && this.o.onContext) { this.o.onContext(this.sel, null, 200, 200); return false; }
    return true;
  };

  /* ---------- SVG charts ---------- */
  function svg(tag, attrs, parent) {
    var e = document.createElementNS(SVGNS, tag), k;
    for (k in attrs) { if (attrs.hasOwnProperty(k)) { e.setAttribute(k, '' + attrs[k]); } }
    if (parent) { parent.appendChild(e); }
    return e;
  }
  function svgTitle(e, text) { var t = svg('title', {}, e); t.textContent = U.stripCtl(text); return e; }
  UI.svg = svg;
  function niceMax(v) {
    if (v <= 0) { return 1; }
    var p = Math.pow(10, Math.floor(Math.log(v) / Math.LN10)), m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
  }
  /* opts: { labels[], series:[{name, values[], color}], stacked, height, width, onBrush(i0,i1), onClick(i), markers:[{i, color, title}], log } */
  UI.barChart = function (host, opts) {
    UI.clear(host);
    var W = opts.width || Math.max(UI.px(300), host.clientWidth || UI.px(800)), H = UI.px(opts.height || 180), padL = UI.px(52), padR = UI.px(10), padT = UI.px(10), padB = UI.px(30);
    var n = opts.labels.length, s, i, max = 0, sum;
    for (i = 0; i < n; i++) {
      if (opts.stacked) { sum = 0; for (s = 0; s < opts.series.length; s++) { sum += opts.series[s].values[i] || 0; } max = Math.max(max, sum); } else { for (s = 0; s < opts.series.length; s++) { max = Math.max(max, opts.series[s].values[i] || 0); } }
    }
    var useLog = !!opts.log, top = useLog ? Math.log(max + 1) / Math.LN10 : niceMax(max);
    if (useLog) { top = Math.ceil(top) || 1; }
    var root = svg('svg', { width: W, height: H, 'class': 'chart' }), plotW = W - padL - padR, plotH = H - padT - padB;
    host.appendChild(root);
    function yv(v) { var x = useLog ? Math.log(v + 1) / Math.LN10 : v; return padT + plotH - (x / top) * plotH; }
    var ticks = 4, t, yy;
    for (t = 0; t <= ticks; t++) {
      var val = useLog ? Math.pow(10, top * t / ticks) - 1 : top * t / ticks;
      yy = padT + plotH - plotH * t / ticks;
      svg('line', { x1: padL, x2: W - padR, y1: yy, y2: yy, 'class': 'grid' }, root);
      var tl = svg('text', { x: padL - UI.px(4), y: yy + UI.px(4), 'text-anchor': 'end', 'class': 'axis' }, root); tl.textContent = val >= 1000 ? U.fmtNum(Math.round(val / 1000)) + 'k' : '' + Math.round(val);
    }
    var bw = plotW / Math.max(1, n), gap = bw > 4 ? 1 : 0;
    for (i = 0; i < n; i++) {
      var x = padL + i * bw, base = 0, tip = opts.labels[i];
      if (opts.markers) {
        for (var mk = 0; mk < opts.markers.length; mk++) {
          if (opts.markers[mk].i === i) { svgTitle(svg('rect', { x: x, y: padT, width: Math.max(1, bw - gap), height: plotH, fill: opts.markers[mk].color, opacity: 0.18 }, root), opts.markers[mk].title); }
        }
      }
      for (s = 0; s < opts.series.length; s++) {
        var v = opts.series[s].values[i] || 0; tip += '\n' + opts.series[s].name + ': ' + U.fmtNum(v);
        if (!v) { continue; }
        var y0, y1;
        if (opts.stacked) { y1 = yv(base + v); y0 = yv(base); base += v; } else { y1 = yv(v); y0 = yv(0); }
        var bx = opts.stacked ? x : x + (bw - gap) * s / opts.series.length, bwid = opts.stacked ? Math.max(1, bw - gap) : Math.max(1, (bw - gap) / opts.series.length);
        svg('rect', { x: bx, y: y1, width: bwid, height: Math.max(0.5, y0 - y1), fill: opts.series[s].color }, root);
      }
      var hit = svg('rect', { x: x, y: padT, width: Math.max(1, bw), height: plotH, fill: 'transparent', 'class': 'hit', 'data-i': i }, root);
      svgTitle(hit, tip);
    }
    var maxLab = 0; for (i = 0; i < n; i++) { var lb = opts.shortLabels ? opts.shortLabels[i] : opts.labels[i]; if (lb && lb.length > maxLab) { maxLab = lb.length; } }
    var every = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(plotW / ((maxLab * 6.2 + 14) * UI.scale)))));
    for (i = 0; i < n; i += every) {
      var lt = svg('text', { x: padL + i * bw + 1, y: H - padB + UI.px(14), 'class': 'axis' }, root); lt.textContent = opts.shortLabels ? opts.shortLabels[i] : opts.labels[i];
    }
    // legend
    var lx = padL;
    for (s = 0; s < opts.series.length; s++) {
      svg('rect', { x: lx, y: H - UI.px(11), width: UI.px(9), height: UI.px(9), fill: opts.series[s].color }, root);
      var lg = svg('text', { x: lx + UI.px(12), y: H - UI.px(3), 'class': 'axis' }, root); lg.textContent = opts.series[s].name;
      lx += UI.px(22 + opts.series[s].name.length * 6.5);
    }
    // brushing
    var brush = null, b0 = -1;
    function idxAt(ev) { var r = root.getBoundingClientRect(), xx = ev.clientX - r.left - padL; return Math.max(0, Math.min(n - 1, Math.floor(xx / bw))); }
    root.onmousedown = function (ev) {
      ev = ev || window.event; if (!opts.onBrush && !opts.onClick) { return; }
      b0 = idxAt(ev);
      brush = svg('rect', { x: padL + b0 * bw, y: padT, width: bw, height: plotH, 'class': 'brush' }, root);
      document.onmousemove = function (e2) { e2 = e2 || window.event; var b1 = idxAt(e2), a = Math.min(b0, b1), b = Math.max(b0, b1); brush.setAttribute('x', padL + a * bw); brush.setAttribute('width', (b - a + 1) * bw); };
      document.onmouseup = function (e2) {
        e2 = e2 || window.event; document.onmousemove = null; document.onmouseup = null;
        var b1 = idxAt(e2), a = Math.min(b0, b1), b = Math.max(b0, b1);
        if (brush && brush.parentNode) { brush.parentNode.removeChild(brush); }
        if (a === b && opts.onClick) { opts.onClick(a); } else if (opts.onBrush) { opts.onBrush(a, b); }
      };
      if (ev.preventDefault) { ev.preventDefault(); } return false;
    };
    return root;
  };
  /* opts: { rows[], cols[], values[r][c], onClick(r,c), color } */
  UI.heatmap = function (host, opts) {
    UI.clear(host);
    var cw = UI.px(opts.cellW || 34), ch = UI.px(opts.cellH || 18), padL = UI.px(48), padT = UI.px(18), r, c, max = 0;
    for (r = 0; r < opts.rows.length; r++) { for (c = 0; c < opts.cols.length; c++) { max = Math.max(max, opts.values[r][c] || 0); } }
    var W = padL + cw * opts.cols.length + 10, H = padT + ch * opts.rows.length + 4;
    var root = svg('svg', { width: W, height: H, 'class': 'chart' });
    host.appendChild(root);
    for (c = 0; c < opts.cols.length; c++) { var t = svg('text', { x: padL + c * cw + cw / 2, y: UI.px(12), 'text-anchor': 'middle', 'class': 'axis' }, root); t.textContent = opts.cols[c]; }
    for (r = 0; r < opts.rows.length; r++) {
      var rl = svg('text', { x: padL - UI.px(6), y: padT + r * ch + ch / 2 + UI.px(4), 'text-anchor': 'end', 'class': 'axis' }, root); rl.textContent = opts.rows[r];
      for (c = 0; c < opts.cols.length; c++) {
        var v = opts.values[r][c] || 0, a = v ? 0.12 + 0.88 * Math.log(v + 1) / Math.log(max + 1) : 0;
        var rect = svg('rect', { x: padL + c * cw + 1, y: padT + r * ch + 1, width: cw - 2, height: ch - 2, fill: v ? (opts.color || '#2b6cb0') : '#eef1f5', 'fill-opacity': v ? a.toFixed(3) : 1, 'class': opts.onClick ? 'hit' : '' }, root);
        svgTitle(rect, opts.rows[r] + ' ' + opts.cols[c] + ': ' + U.fmtNum(v));
        if (opts.onClick) { rect.onclick = (function (rr, cc) { return function () { opts.onClick(rr, cc); }; }(r, c)); }
      }
    }
    return root;
  };
  UI.sparkline = function (host, values, w, h, color) {
    w = UI.px(w); h = UI.px(h);
    var root = svg('svg', { width: w, height: h, 'class': 'spark' }), max = 0, i;
    for (i = 0; i < values.length; i++) { max = Math.max(max, values[i]); }
    var bw = w / Math.max(1, values.length);
    for (i = 0; i < values.length; i++) {
      if (!values[i]) { continue; }
      var bh = Math.max(1, values[i] / max * (h - 1));
      svg('rect', { x: i * bw, y: h - bh, width: Math.max(1, bw - (bw > 3 ? 1 : 0)), height: bh, fill: color || '#2b6cb0' }, root);
    }
    host.appendChild(root);
    return root;
  };
  UI.COLORS = { s2: '#38a169', s3: '#718096', s4: '#dd6b20', s5: '#c53030', ext: '#2b6cb0', int: '#a0aec0', hits: '#805ad5', lb: '#cbd5e0',
    series: ['#2b6cb0', '#c53030', '#38a169', '#805ad5', '#dd6b20', '#319795'] };
}(IISLA));
