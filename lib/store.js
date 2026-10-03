/* IIS Log Analyzer - store.js
 * Columnar row store (typed arrays + interned strings), load pass,
 * sorting, sessions and Top-N aggregation over loaded rows.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io, P = NS.parser, R = NS.rules, St = NS.store = {};

  /* ---------- string table ---------- */
  St.StrTable = function (numericIp) { this.map = U.newMap(); this.vals = []; this.rk = null; this.ip = !!numericIp; };
  St.StrTable.prototype.id = function (s) {
    var v = this.map[s];
    if (v === undefined) { v = this.vals.length; s = U.own(s); this.map[s] = v; this.vals.push(s); this.rk = null; }
    return v;
  };
  St.StrTable.prototype.find = function (s) { var v = this.map[s]; return v === undefined ? -1 : v; };
  function ipSortKey(s) {
    var n = U.parseIPv4(s);
    if (n >= 0) { return '4' + ('0000000000' + n).slice(-10); }
    var h = U.expandIPv6(s);
    return h ? '6' + h : '9' + s;
  }
  /* rank[id] = position of the value in sorted order (for fast sorting by string columns) */
  St.StrTable.prototype.ranks = function () {
    if (this.rk && this.rk.length === this.vals.length) { return this.rk; }
    var n = this.vals.length, ids = new Array(n), i, vals = this.vals, keys = new Array(n);
    for (i = 0; i < n; i++) { ids[i] = i; keys[i] = this.ip ? ipSortKey(vals[i]) : vals[i].toLowerCase(); }
    ids.sort(function (a, b) { return keys[a] < keys[b] ? -1 : (keys[a] > keys[b] ? 1 : 0); });
    var rk = new Int32Array(n);
    for (i = 0; i < n; i++) { rk[ids[i]] = i; }
    this.rk = rk;
    return rk;
  };

  /* ---------- store ---------- */
  var F_PUB = 1, F_EXEC = 2, F_STAT = 4, F_DECERR = 8, F_NONASCII = 16, F_HITS = 32, F_INTERNAL = 64;
  St.FLAGS = { PUB: F_PUB, EXEC: F_EXEC, STAT: F_STAT, DECERR: F_DECERR, NONASCII: F_NONASCII, HITS: F_HITS, INTERNAL: F_INTERNAL };

  St.Store = function (maxRows, keepRaw) {
    this.max = maxRows; this.n = 0; this.cap = 0; this.keepRaw = !!keepRaw; this.capped = false; this.failed = []; this.incomplete = false;
    this.t = { ip: new St.StrTable(true), method: new St.StrTable(), stem: new St.StrTable(), query: new St.StrTable(), ua: new St.StrTable(),
      user: new St.StrTable(), ref: new St.StrTable(), host: new St.StrTable(), hits: new St.StrTable(), reason: new St.StrTable() };
    this.t.hits.id('');
    this.raw = keepRaw ? [] : null;
    // exact raw export: original line where UTF-8/BOM handling changed it, and non-CRLF terminators (sparse, by row)
    this.rawOrig = keepRaw ? {} : null; this.rawEol = keepRaw ? {} : null;
    this.stemInfo = []; this.uaInfo = []; this.ipCls = []; this.qInfo = [];
    this.files = []; // fileId -> {name, path}
    this.grow(Math.min(maxRows, 131072));
  };
  var NUMCOLS = [['ts', Float64Array], ['file', Int32Array], ['line', Int32Array], ['status', Int16Array], ['sub', Int16Array], ['win32', Float64Array],
    ['taken', Int32Array], ['scb', Float64Array], ['csb', Float64Array], ['port', Int32Array], ['flags', Uint8Array],
    ['sip', Int32Array], ['cip', Int32Array], ['eip', Int32Array], ['method', Int32Array], ['stem', Int32Array], ['query', Int32Array], ['ua', Int32Array],
    ['user', Int32Array], ['ref', Int32Array], ['host', Int32Array], ['hits', Int32Array]];
  St.Store.prototype.grow = function (newCap) {
    newCap = Math.min(newCap, this.max);
    if (newCap <= this.cap) { return false; }
    var i, name, T, old, nw;
    for (i = 0; i < NUMCOLS.length; i++) {
      name = NUMCOLS[i][0]; T = NUMCOLS[i][1]; old = this[name];
      nw = new T(newCap);
      if (old) { nw.set(old.subarray(0, this.n)); }
      this[name] = nw;
    }
    this.cap = newCap;
    return true;
  };
  /* Adds the current row (with evaluator context). Returns false when the cap is reached. */
  St.Store.prototype.push = function (r, ev) {
    if (this.n >= this.cap) {
      if (!this.grow(this.cap * 2)) { this.capped = true; return false; }
    }
    var i = this.n, c = ev.ctx, T = this.t, id;
    this.ts[i] = r.ts; this.file[i] = r.fileId; this.line[i] = r.lineNo; this.status[i] = r.status; this.sub[i] = r.sub;
    this.win32[i] = r.win32; this.taken[i] = r.taken; this.scb[i] = r.scBytes; this.csb[i] = r.csBytes; this.port[i] = r.port;
    this.sip[i] = T.ip.id(r.sip); this.cip[i] = T.ip.id(r.cip);
    id = T.ip.id(r.eip); this.eip[i] = id; if (this.ipCls[id] === undefined) { this.ipCls[id] = c.cls; }
    this.method[i] = T.method.id(r.method);
    id = T.stem.id(r.stem); this.stem[i] = id; if (this.stemInfo[id] === undefined) { this.stemInfo[id] = c.si; }
    id = T.query.id(r.query); this.query[i] = id; if (this.qInfo[id] === undefined) { this.qInfo[id] = c.qi; }
    id = T.ua.id(r.ua); this.ua[i] = id; if (this.uaInfo[id] === undefined) { this.uaInfo[id] = c.ui; }
    this.user[i] = T.user.id(r.user); this.ref[i] = T.ref.id(r.referer); this.host[i] = T.host.id(r.host);
    this.hits[i] = ev.n ? T.hits.id(ev.hitString()) : 0;
    var fl = 0;
    if (c.pub) { fl |= F_PUB; } if (c.si.exec) { fl |= F_EXEC; } if (c.si.stat) { fl |= F_STAT; }
    if (c.si.decErr || c.qi.decErr) { fl |= F_DECERR; } if (r.nonAscii) { fl |= F_NONASCII; } if (ev.n) { fl |= F_HITS; }
    if (U.isInternalClass(c.cls)) { fl |= F_INTERNAL; }
    this.flags[i] = fl;
    if (this.raw) { this.raw[i] = U.own(r.raw); if (r.rawOrig) { this.rawOrig[i] = U.own(r.rawOrig); } if (r.eol) { this.rawEol[i] = r.eol; } }
    this.n++;
    return true;
  };
  St.Store.prototype.pop = function () { if (this.n > 0) { this.n--; if (this.raw) { this.raw.length = this.n; delete this.rawOrig[this.n]; delete this.rawEol[this.n]; } } };
  St.Store.prototype.bytesEstimate = function () {
    var b = this.cap * (8 * 4 + 4 * 15 + 2 * 2 + 1), k, t;
    for (k in this.t) { t = this.t[k]; b += t.vals.length * 48; }
    for (k = 0; k < this.t.query.vals.length; k++) { b += this.t.query.vals[k].length * 2; }
    if (this.raw) { b += this.n * 260; }
    return b;
  };

  /* ---------- column definitions ---------- */
  function sv(tab, col) { return function (s, i) { return s.t[tab].vals[s[col][i]]; }; }
  function num(col, empty) { return function (s, i) { var v = s[col][i]; return v < 0 ? (empty || '') : '' + v; }; }
  St.COLUMNS = [
    { key: 'ts', label: 'Time (UTC)', w: 140, get: function (s, i) { return U.fmtTs(s.ts[i]); }, sort: 'ts' },
    { key: 'tsl', label: 'Time (local)', w: 140, get: function (s, i) { return U.fmtTs(s.ts[i], St.tz); }, sort: 'ts', hidden: true },
    { key: 'cip', label: 'Client IP', w: 120, get: sv('ip', 'cip'), sort: 'cip', tab: 'ip' },
    { key: 'cls', label: 'IP class', w: 70, get: function (s, i) { return s.ipCls[s.eip[i]]; } },
    { key: 'eip', label: 'Effective IP', w: 120, get: sv('ip', 'eip'), sort: 'eip', tab: 'ip', hidden: true },
    { key: 'method', label: 'Method', w: 60, get: sv('method', 'method'), sort: 'method', tab: 'method' },
    { key: 'stem', label: 'URI stem', w: 330, get: sv('stem', 'stem'), sort: 'stem', tab: 'stem' },
    { key: 'query', label: 'Query', w: 220, get: sv('query', 'query'), sort: 'query', tab: 'query' },
    { key: 'queryDec', label: 'Query (decoded)', w: 220, get: function (s, i) { var q = s.qInfo[s.query[i]]; return q ? q.dec : ''; }, hidden: true },
    { key: 'status', label: 'Status', w: 58, get: function (s, i) { return s.status[i] < 0 ? '' : s.status[i] + '.' + (s.sub[i] < 0 ? 0 : s.sub[i]); }, sort: 'status' },
    { key: 'win32', label: 'Win32', w: 50, get: num('win32'), sort: 'win32' },
    { key: 'taken', label: 'Taken ms', w: 70, get: num('taken'), sort: 'taken', num: true },
    { key: 'scb', label: 'sc-bytes', w: 70, get: num('scb'), sort: 'scb', num: true, hidden: true },
    { key: 'csb', label: 'cs-bytes', w: 70, get: num('csb'), sort: 'csb', num: true, hidden: true },
    { key: 'ua', label: 'User agent', w: 260, get: function (s, i) { var u = s.uaInfo[s.ua[i]]; return u ? u.dec : ''; }, sort: 'ua', tab: 'ua' },
    { key: 'uaRaw', label: 'User agent (raw)', w: 260, get: sv('ua', 'ua'), sort: 'ua', tab: 'ua', hidden: true },
    { key: 'fam', label: 'UA family', w: 80, get: function (s, i) { var u = s.uaInfo[s.ua[i]]; return u ? u.fam : ''; } },
    { key: 'user', label: 'Username', w: 90, get: sv('user', 'user'), sort: 'user', tab: 'user', hidden: true },
    { key: 'ref', label: 'Referer', w: 200, get: sv('ref', 'ref'), sort: 'ref', tab: 'ref', hidden: true },
    { key: 'host', label: 'Host', w: 120, get: sv('host', 'host'), sort: 'host', tab: 'host', hidden: true },
    { key: 'sip', label: 'Server IP', w: 100, get: sv('ip', 'sip'), sort: 'sip', tab: 'ip', hidden: true },
    { key: 'port', label: 'Port', w: 45, get: num('port'), sort: 'port', hidden: true },
    { key: 'ext', label: 'Ext', w: 50, get: function (s, i) { var si = s.stemInfo[s.stem[i]]; return si ? si.ext : ''; }, hidden: true },
    { key: 'hits', label: 'Rule hits', w: 150, get: sv('hits', 'hits'), sort: 'hits', tab: 'hits' },
    { key: 'tags', label: 'Tags', w: 100, get: function (s, i) { return St.tagText ? St.tagText(s, i) : ''; } },
    { key: 'file', label: 'Source file', w: 110, get: function (s, i) { var f = s.files[s.file[i]]; return f ? f.name : ''; }, sort: 'file' },
    { key: 'line', label: 'Line', w: 60, get: function (s, i) { return '' + s.line[i]; }, sort: 'line', num: true },
    { key: 'raw', label: 'Raw line', w: 600, get: function (s, i) { return s.raw ? s.raw[i] : ''; }, hidden: true }
  ];
  St.colByKey = {};
  (function () { var i; for (i = 0; i < St.COLUMNS.length; i++) { St.colByKey[St.COLUMNS[i].key] = St.COLUMNS[i]; } }());
  St.tz = 0;

  /* ---------- sort ---------- */
  /* Sorts an index array (plain Array or Int32Array) by column key. Stable on ts, then file/line. */
  St.sortView = function (store, view, key, desc) {
    var col = St.colByKey[key], sk = col && col.sort ? col.sort : null, arr = [], i, n = view.length;
    for (i = 0; i < n; i++) { arr.push(view[i]); }
    var ts = store.ts, file = store.file, line = store.line, primary = null, rk = null;
    if (sk) {
      if (col.tab) { rk = store.t[col.tab].ranks(); primary = store[sk]; } else { primary = store[sk]; }
    }
    var dir = desc ? -1 : 1;
    arr.sort(function (a, b) {
      var d = 0;
      if (primary) {
        var va = rk ? rk[primary[a]] : primary[a], vb = rk ? rk[primary[b]] : primary[b];
        if (key === 'status') { va = va * 1000 + store.sub[a]; vb = vb * 1000 + store.sub[b]; }
        d = va < vb ? -1 : (va > vb ? 1 : 0);
        if (d) { return d * dir; }
      }
      d = ts[a] - ts[b]; if (d) { return d; }
      d = file[a] - file[b]; if (d) { return d; }
      return line[a] - line[b];
    });
    var out = new Int32Array(n);
    for (i = 0; i < n; i++) { out[i] = arr[i]; }
    return out;
  };

  /* ---------- load pass ---------- */
  /* opts: { site, fileIds[], from, to, prefilter (compiled fn(A)), settings, ruleset, lists, index, maxRows, keepRaw, onProgress, token } */
  St.load = function (opts, done) {
    var files = opts.site.files, ids = opts.fileIds, k = 0, rd = null, fp = null, row = P.newRow();
    var store = new St.Store(opts.maxRows, opts.keepRaw), D = new P.Deriver(opts.lists), ev = new R.Evaluator(opts.ruleset, D);
    var from = opts.from || -Infinity, to = opts.to || Infinity, pre = opts.prefilter || null;
    var A = NS.filter ? NS.filter.rowAccessor(row, ev) : null;
    if (opts.index) {
      ev.userFirst = {};
      for (var u in opts.index.users) { ev.userFirst[u] = opts.index.users[u].fFile + ':' + opts.index.users[u].fLine; }
    }
    var i, bytesTotal = 0, bytesDone = 0, t0 = Date.now(), lastProg = 0, scanned = 0, stop = false;
    for (i = 0; i < files.length; i++) { store.files[i] = { name: files[i].name, path: files[i].path }; }
    for (i = 0; i < ids.length; i++) { bytesTotal += files[ids[i]].size; }
    // Files that could not be opened are recorded, never silently dropped: the load is then marked incomplete
    // and the caller reports the omission (UI, audit log and export metadata).
    store.failed = [];
    function step() {
      if (stop) { return true; }
      if (!rd) {
        if (k >= ids.length) { return true; }
        var f = files[ids[k]];
        try { rd = new IO.LineReader(f.path, opts.settings.chunkChars, f.size, opts.settings); } catch (e) {
          store.failed.push({ fileId: ids[k], name: f.name, path: f.path, error: (e && e.message) || ('' + e) });
          bytesDone += f.size; k++; return false;
        }
        fp = new P.FileParser(ids[k]);
      }
      var lines, j, code;
      try { lines = rd.next(); } catch (e2) { throw new Error('Reading ' + files[ids[k]].name + ' failed: ' + ((e2 && e2.message) || e2)); }
      if (lines === null) { bytesDone += files[ids[k]].size; rd = null; k++; return false; }
      var exc = rd ? rd.eolExc : null;
      for (j = 0; j < lines.length; j++) {
        code = fp.line(lines[j], row);
        if (code !== 1) { continue; }
        row.eol = exc && exc[j] ? exc[j] : '';
        scanned++;
        ev.evaluate(row);
        if (row.ts < from || row.ts > to) { continue; }
        if (pre && !pre(A)) { continue; }
        if (!store.push(row, ev)) { stop = true; break; }
      }
      if (rd.done) { bytesDone += files[ids[k]].size; rd = null; k++; }
      var now = Date.now();
      if (opts.onProgress && now - lastProg > 250) {
        lastProg = now;
        var el = (now - t0) / 1000, bd = bytesDone + (rd ? rd.charsRead : 0);
        opts.onProgress({ file: k, files: ids.length, current: files[ids[Math.min(k, ids.length - 1)]].name, rows: store.n, scanned: scanned,
          rate: el > 0 ? scanned / el : 0, bytesDone: bd, bytesTotal: bytesTotal, eta: bd > 0 ? (bytesTotal - bd) * el / bd : 0 });
      }
      return stop;
    }
    IO.runSliced(step, function (err, cancelled) {
      if (rd) { rd.close(); }
      store.loadMs = Date.now() - t0; store.scanned = scanned; store.cancelled = !!cancelled;
      store.incomplete = store.failed.length > 0;
      done(err, store);
    }, opts.settings.sliceMs || 25, opts.token);
  };

  /* ---------- sessions ---------- */
  St.sessions = function (store, view, idleMin) {
    var n = view ? view.length : store.n, arr = new Array(n), i;
    for (i = 0; i < n; i++) { arr[i] = view ? view[i] : i; }
    var eip = store.eip, ua = store.ua, ts = store.ts;
    arr.sort(function (a, b) { return (eip[a] - eip[b]) || (ua[a] - ua[b]) || (ts[a] - ts[b]) || (a - b); });
    var idle = (idleMin || 30) * 60000, out = [], cur = null, j, ix;
    function close() {
      if (!cur) { return; }
      cur.stems = U.countKeys(cur._st); cur._st = null;
      out.push(cur); cur = null;
    }
    for (j = 0; j < n; j++) {
      ix = arr[j];
      if (!cur || eip[ix] !== cur.eipId || ua[ix] !== cur.uaId || ts[ix] - cur.end > idle) {
        close();
        cur = { eipId: eip[ix], uaId: ua[ix], start: ts[ix], end: ts[ix], rows: 0, s2: 0, s3: 0, s4: 0, s5: 0, execPost: 0, hits: 0, idx: [], _st: {} };
      }
      cur.end = ts[ix]; cur.rows++; cur.idx.push(ix);
      var sc = Math.floor(store.status[ix] / 100);
      if (sc === 2) { cur.s2++; } else if (sc === 3) { cur.s3++; } else if (sc === 4) { cur.s4++; } else if (sc === 5) { cur.s5++; }
      if ((store.flags[ix] & F_EXEC) && store.t.method.vals[store.method[ix]] === 'POST') { cur.execPost++; }
      if (store.flags[ix] & F_HITS) { cur.hits++; }
      cur._st[store.stem[ix]] = 1;
    }
    close();
    for (j = 0; j < out.length; j++) {
      var s = out[j];
      s.ip = store.t.ip.vals[s.eipId]; s.cls = store.ipCls[s.eipId];
      var ui = store.uaInfo[s.uaId]; s.ua = ui ? ui.dec : ''; s.fam = ui ? ui.fam : '';
      s.duration = s.end - s.start;
    }
    out.sort(function (a, b) { return a.start - b.start; });
    for (j = 0; j < out.length; j++) { out[j].id = j + 1; }
    return out;
  };

  /* ---------- Top-N over loaded rows ---------- */
  St.DIMENSIONS = [
    ['cip', 'Client IP'], ['eip', 'Effective IP'], ['cls', 'IP class'], ['stem', 'URI stem'], ['dir', 'Directory'], ['ext', 'Extension'],
    ['query', 'Query'], ['ua', 'User agent'], ['fam', 'UA family'], ['status', 'Status'], ['method', 'Method'], ['user', 'Username'],
    ['sport', 'Server IP:port'], ['hour', 'Hour of day (local)'], ['dow', 'Day of week (local)'], ['day', 'Day (UTC)'], ['file', 'Source file'], ['rule', 'Rule hit']
  ];
  var DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  St.keyFn = function (store, dim) {
    var T = store.t;
    switch (dim) {
      case 'cip': return function (i) { return T.ip.vals[store.cip[i]]; };
      case 'eip': return function (i) { return T.ip.vals[store.eip[i]]; };
      case 'cls': return function (i) { return store.ipCls[store.eip[i]]; };
      case 'stem': return function (i) { return T.stem.vals[store.stem[i]]; };
      case 'dir': return function (i) { return store.stemInfo[store.stem[i]].dir; };
      case 'ext': return function (i) { return store.stemInfo[store.stem[i]].ext || '(none)'; };
      case 'query': return function (i) { return T.query.vals[store.query[i]]; };
      case 'ua': return function (i) { return store.uaInfo[store.ua[i]].dec || '(empty)'; };
      case 'fam': return function (i) { return store.uaInfo[store.ua[i]].fam; };
      case 'status': return function (i) { return store.status[i] + '.' + Math.max(0, store.sub[i]); };
      case 'method': return function (i) { return T.method.vals[store.method[i]]; };
      case 'user': return function (i) { return T.user.vals[store.user[i]]; };
      case 'sport': return function (i) { return T.ip.vals[store.sip[i]] + ':' + store.port[i]; };
      case 'hour': return function (i) { return U.p2(new Date(store.ts[i] + U.tzOff(St.tz, store.ts[i]) * 60000).getUTCHours()); };
      case 'dow': return function (i) { var d = new Date(store.ts[i] + U.tzOff(St.tz, store.ts[i]) * 60000).getUTCDay(); return d + ' ' + DOW[d]; };
      case 'day': return function (i) { return U.dayKey(store.ts[i]); };
      case 'file': return function (i) { return store.files[store.file[i]].name; };
      case 'rule': return null;
    }
    return null;
  };
  St.topN = function (store, view, dim, limit) {
    var n = view ? view.length : store.n, groups = U.newMap(), list = [], j, i, k, g, keyf = St.keyFn(store, dim);
    function add(key, i) {
      g = groups[key];
      if (!g) { g = groups[key] = { key: key, rows: 0, ips: {}, ipN: 0, stems: {}, stN: 0, s4: 0, s5: 0, post: 0, takenSum: 0, takenN: 0, takenMax: 0, bytes: 0, first: store.ts[i], last: store.ts[i], hits: 0 }; list.push(g); }
      g.rows++;
      var ip = store.eip[i], st = store.stem[i], s = store.status[i], tk = store.taken[i];
      if (g.ipN < 5000 && g.ips[ip] === undefined) { g.ips[ip] = 1; g.ipN++; }
      if (g.stN < 5000 && g.stems[st] === undefined) { g.stems[st] = 1; g.stN++; }
      if (s >= 400 && s < 500) { g.s4++; } else if (s >= 500) { g.s5++; }
      if (store.t.method.vals[store.method[i]] === 'POST') { g.post++; }
      if (tk >= 0) { g.takenSum += tk; g.takenN++; if (tk > g.takenMax) { g.takenMax = tk; } }
      if (store.scb[i] > 0) { g.bytes += store.scb[i]; }
      if (store.ts[i] < g.first) { g.first = store.ts[i]; } if (store.ts[i] > g.last) { g.last = store.ts[i]; }
      if (store.flags[i] & F_HITS) { g.hits++; }
    }
    for (j = 0; j < n; j++) {
      i = view ? view[j] : j;
      if (dim === 'rule') {
        var hs = store.t.hits.vals[store.hits[i]];
        if (!hs) { continue; }
        var parts = hs.split(',');
        for (k = 0; k < parts.length; k++) { add(parts[k], i); }
      } else { add(keyf(i), i); }
    }
    for (j = 0; j < list.length; j++) {
      g = list[j]; g.ips = null; g.stems = null; g.avgTaken = g.takenN ? g.takenSum / g.takenN : 0;
    }
    return list;
  };
}(IISLA));
