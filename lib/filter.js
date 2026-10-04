/* IIS Log Analyzer - filter.js
 * Filter model, quick-filter mini-language, and compilation into predicates
 * that run either over the columnar store or over rows during a load pass.
 */
(function (NS) {
  'use strict';
  var U = NS.util, F = NS.filter = {};
  var VALID = {}; (function () { var i; for (i = 0; i < U.METHODS_VALID.length; i++) { VALID[U.METHODS_VALID[i]] = 1; } }());

  /* ---------- accessors ---------- */
  F.storeAccessor = function (s) {
    var T = s.t, A = { i: 0, store: s };
    A.ts = function () { return s.ts[A.i]; };
    A.cip = function () { return T.ip.vals[s.cip[A.i]]; };
    A.eip = function () { return T.ip.vals[s.eip[A.i]]; };
    A.sip = function () { return T.ip.vals[s.sip[A.i]]; };
    A.cls = function () { return s.ipCls[s.eip[A.i]]; };
    A.method = function () { return T.method.vals[s.method[A.i]]; };
    A.status = function () { return s.status[A.i]; };
    A.sub = function () { return s.sub[A.i]; };
    A.win32 = function () { return s.win32[A.i]; };
    A.taken = function () { return s.taken[A.i]; };
    A.scb = function () { return s.scb[A.i]; };
    A.stem = function () { return T.stem.vals[s.stem[A.i]]; };
    A.si = function () { return s.stemInfo[s.stem[A.i]]; };
    A.query = function () { return T.query.vals[s.query[A.i]]; };
    A.qi = function () { return s.qInfo[s.query[A.i]]; };
    A.ua = function () { return T.ua.vals[s.ua[A.i]]; };
    A.ui = function () { return s.uaInfo[s.ua[A.i]]; };
    A.user = function () { return T.user.vals[s.user[A.i]]; };
    A.fileId = function () { return s.file[A.i]; };
    A.line = function () { return s.line[A.i]; };
    A.hits = function () { return T.hits.vals[s.hits[A.i]]; };
    A.hitSevs = function () { return T.hsev.vals[s.hsev[A.i]]; };
    A.port = function () { return s.port[A.i]; };
    A.raw = function () {
      if (s.raw) { return s.raw[A.i]; }
      return A.cip() + ' ' + A.method() + ' ' + A.stem() + ' ' + A.query() + ' ' + A.ua() + ' ' + A.status();
    };
    return A;
  };
  F.rowAccessor = function (r, ev) {
    var c = ev.ctx, A = { r: r };
    A.ts = function () { return r.ts; };
    A.cip = function () { return r.cip; };
    A.eip = function () { return r.eip; };
    A.sip = function () { return r.sip; };
    A.cls = function () { return c.cls; };
    A.method = function () { return r.method; };
    A.status = function () { return r.status; };
    A.sub = function () { return r.sub; };
    A.win32 = function () { return r.win32; };
    A.taken = function () { return r.taken; };
    A.scb = function () { return r.scBytes; };
    A.stem = function () { return r.stem; };
    A.si = function () { return c.si; };
    A.query = function () { return r.query; };
    A.qi = function () { return c.qi; };
    A.ua = function () { return r.ua; };
    A.ui = function () { return c.ui; };
    A.user = function () { return r.user; };
    A.fileId = function () { return r.fileId; };
    A.line = function () { return r.lineNo; };
    A.hits = function () { return ev.n ? ev.hitString() : ''; };
    A.hitSevs = function () { return ev.n ? ev.hitSevString() : ''; };
    A.port = function () { return r.port; };
    A.raw = function () { return r.raw; };
    return A;
  };

  /* ---------- helpers ---------- */
  function memo(test) {
    var cache = U.newMap(), n = 0;
    return function (s) {
      var v = cache[s];
      if (v !== undefined) { return v; }
      v = !!test(s);
      if (n++ > 200000) { cache = U.newMap(); n = 0; }
      cache[s] = v;
      return v;
    };
  }
  function lowerList(v) { var out = [], i; v = [].concat(v); for (i = 0; i < v.length; i++) { out.push(('' + v[i]).toLowerCase()); } return out; }
  function setOf(v, lower) { var m = {}, i; v = [].concat(v); for (i = 0; i < v.length; i++) { m[lower ? ('' + v[i]).toLowerCase() : v[i]] = 1; } return m; }
  function strTester(op, v) {
    var vals = lowerList(v), res = [], i;
    if (op === 'regex') { for (i = 0; i < vals.length; i++) { res.push(new RegExp([].concat(v)[i], 'i')); } return function (s) { for (var j = 0; j < res.length; j++) { if (res[j].test(s)) { return true; } } return false; }; }
    if (op === 'glob') { for (i = 0; i < vals.length; i++) { res.push(U.globToRegex(vals[i])); } return function (s) { for (var j = 0; j < res.length; j++) { if (res[j].test(s)) { return true; } } return false; }; }
    return function (s) {
      s = s.toLowerCase();
      for (var j = 0; j < vals.length; j++) {
        if (op === 'contains' && s.indexOf(vals[j]) >= 0) { return true; }
        if (op === 'starts' && s.substr(0, vals[j].length) === vals[j]) { return true; }
        if (op === 'ends' && U.endsWith(s, vals[j])) { return true; }
        if (op === 'eq' && s === vals[j]) { return true; }
      }
      return false;
    };
  }
  function ipTester(op, v) {
    if (op === 'cidr') {
      var cs = [], i, list = [].concat(v), c;
      for (i = 0; i < list.length; i++) { c = U.parseCidr(list[i]); if (c) { cs.push(c); } }
      return memo(function (ip) { for (var j = 0; j < cs.length; j++) { if (U.cidrMatch(cs[j], ip)) { return true; } } return false; });
    }
    if (op === 'regex') { return memo(strTester('regex', v)); }
    if (op === 'contains') { return memo(strTester('contains', v)); }
    var m = setOf(v, true);
    return function (ip) { return m[ip.toLowerCase()] === 1; };
  }
  function statusTester(v) {
    var list = [].concat(v), tests = [], i;
    for (i = 0; i < list.length; i++) {
      (function (t) {
        t = ('' + t).toLowerCase();
        var m;
        if (/^\dxx$/.test(t)) { var cl = +t.charAt(0); tests.push(function (s) { return Math.floor(s / 100) === cl; }); } else if ((m = /^(\d+)-(\d+)$/.exec(t))) { var lo = +m[1], hi = +m[2]; tests.push(function (s) { return s >= lo && s <= hi; }); } else if ((m = /^(\d+)\.(\d+)$/.exec(t))) { var a = +m[1], b = +m[2]; tests.push(function (s, sub) { return s === a && sub === b; }); } else if (/^\d+$/.test(t)) { var e = +t; tests.push(function (s) { return s === e; }); }
      }(list[i]));
    }
    return function (s, sub) { for (var j = 0; j < tests.length; j++) { if (tests[j](s, sub)) { return true; } } return false; };
  }

  /* ---------- compile ---------- */
  /* env: { tz, tagsOf(A) -> [names], iocTest(A) -> bool, index, ruleSev{id:sev}, fileName(fileId) } */
  F.compileCond = function (c, env) {
    var f = c.f, op = c.op, v = c.v, fn = null, t;
    env = env || {};
    switch (f) {
      case 'time':
        var a = v[0] === null || v[0] === undefined || isNaN(v[0]) ? -Infinity : v[0], b = v[1] === null || v[1] === undefined || isNaN(v[1]) ? Infinity : v[1];
        fn = function (A) { var x = A.ts(); return x >= a && x <= b; }; break;
      case 'hour':
        var hs = setOf(v), tzh = env.tz || 0;
        fn = function (A) { var x = A.ts(); x += U.tzOff(tzh, x) * 60000; return hs[Math.floor(((x % 86400000) + 86400000) % 86400000 / 3600000)] === 1; }; break;
      case 'dow':
        var ds = setOf(v), tzd = env.tz || 0;
        fn = function (A) { var x = A.ts(); return ds[new Date(x + U.tzOff(tzd, x) * 60000).getUTCDay()] === 1; }; break;
      case 'cip': case 'eip': case 'sip':
        if (op === 'class') {
          var cls = setOf(v), ccache = memo(function () { return false; });
          if (f === 'eip' || f === 'cip') { fn = function (A) { return cls[A.cls()] === 1; }; } else { var cm = U.newMap(); fn = function (A) { var ip = A.sip(), k = cm[ip]; if (k === undefined) { k = cm[ip] = U.classifyIp(ip); } return cls[k] === 1; }; }
          ccache = null;
        } else {
          t = ipTester(op, v);
          fn = f === 'cip' ? function (A) { return t(A.cip()) || (A.eip() !== A.cip() && t(A.eip())); } : (f === 'eip' ? function (A) { return t(A.eip()); } : function (A) { return t(A.sip()); });
        }
        break;
      case 'method':
        if (op === 'invalid') { fn = function (A) { return VALID[A.method().toUpperCase()] !== 1; }; } else { var ms = setOf(lowerList(v).map(function (x) { return x.toUpperCase(); })); fn = function (A) { return ms[A.method().toUpperCase()] === 1; }; }
        break;
      case 'status':
        t = statusTester(v); fn = function (A) { return t(A.status(), A.sub() < 0 ? 0 : A.sub()); }; break;
      case 'win32':
        var ws = setOf(v); fn = function (A) { return ws[A.win32()] === 1; }; break;
      case 'stem':
        if (op === 'ext') { var es = setOf(lowerList(v).map(function (x) { return x === '(none)' ? '' : (x.charAt(0) === '.' ? x : '.' + x); })); fn = function (A) { return es[A.si().ext] === 1; }; } else if (op === 'dir') { var dl = lowerList(v); fn = function (A) { var d = A.si().dir; for (var j = 0; j < dl.length; j++) { if (d.substr(0, dl[j].length) === dl[j]) { return true; } } return false; }; } else if (op === 'exec') { fn = function (A) { return A.si().exec; }; } else if (op === 'static') { fn = function (A) { return A.si().stat; }; } else if (op === 'firstSeenAfter') {
          var idx = env.index, fsa = v;
          fn = function (A) { var s = idx && idx.stems[A.si().key]; return !!s && s.first >= fsa; };
        } else {
          t = memo(strTester(op, v));
          fn = function (A) { var si = A.si(); return t(si.dec) || (A.stem() !== si.dec && t(A.stem())); };
        }
        break;
      case 'query':
        if (op === 'lenGte') { var ql = +v; fn = function (A) { return A.qi().len >= ql; }; } else if (op === 'decErr') { fn = function (A) { return A.qi().decErr || A.si().decErr; }; } else if (op === 'empty') { fn = function (A) { return A.qi().empty; }; } else {
          t = memo(strTester(op, v));
          fn = function (A) { var q = A.qi(); return !q.empty && (t(q.dec) || t(A.query())); };
        }
        break;
      case 'ua':
        if (op === 'family') { var fs = setOf(lowerList(v)); fn = function (A) { return fs[A.ui().fam] === 1; }; } else if (op === 'empty') { fn = function (A) { return A.ui().empty; }; } else {
          t = memo(strTester(op, v)); fn = function (A) { return t(A.ui().dec); };
        }
        break;
      case 'user':
        if (op === 'present') { fn = function (A) { var u = A.user(); return u !== '-' && u !== ''; }; } else { t = memo(strTester(op, v)); fn = function (A) { return t(A.user()); }; }
        break;
      case 'taken':
        var tv = +v; fn = op === 'lte' ? function (A) { var x = A.taken(); return x >= 0 && x <= tv; } : function (A) { return A.taken() >= tv; }; break;
      case 'bytes':
        var bv = +v; fn = op === 'lte' ? function (A) { var x = A.scb(); return x >= 0 && x <= bv; } : function (A) { return A.scb() >= bv; }; break;
      case 'port':
        var ps = setOf([].concat(v).map(function (x) { return +x; })); fn = function (A) { return ps[A.port()] === 1; }; break;
      case 'file':
        if (op === 'glob') {
          var gr = [].concat(v).map(function (x) { return U.globToRegex(x); }), fcache = {};
          fn = function (A) {
            var id = A.fileId(), r = fcache[id];
            if (r === undefined) { var nm = env.fileName ? env.fileName(id) : ''; r = false; for (var j = 0; j < gr.length; j++) { if (gr[j].test(nm)) { r = true; } } fcache[id] = r; }
            return r;
          };
        } else { var fsid = setOf(v); fn = function (A) { return fsid[A.fileId()] === 1; }; }
        break;
      case 'rule':
        if (op === 'any') { fn = function (A) { return A.hits() !== ''; }; } else if (op === 'sev') {
          // severity of each hit as graded for this row (outcome-graded rules drop for failed requests)
          var sevs = setOf(lowerList(v)), hc = U.newMap();
          fn = function (A) {
            var h = A.hitSevs(); if (!h) { return false; }
            var r = hc[h]; if (r !== undefined) { return r; }
            var parts = h.split(','); r = false;
            for (var j = 0; j < parts.length; j++) { if (sevs[parts[j]] === 1) { r = true; } }
            hc[h] = r; return r;
          };
        } else {
          // Each rule id in the row's comma-separated hit list is tested on its own; wildcard ids are compiled once.
          var ids = [].concat(v).map(function (x) { return ('' + x).toUpperCase(); }), exact = U.newMap(), globs = [], hc2 = U.newMap(), gi;
          for (gi = 0; gi < ids.length; gi++) { if (/[*?]/.test(ids[gi])) { globs.push(U.globToRegex(ids[gi])); } else { exact[ids[gi]] = 1; } }
          fn = function (A) {
            var h = A.hits(); if (!h) { return false; }
            var r = hc2[h]; if (r !== undefined) { return r; }
            var parts = h.split(','), k, g;
            r = false;
            for (k = 0; k < parts.length && !r; k++) {
              if (exact[parts[k]] === 1) { r = true; break; }
              for (g = 0; g < globs.length; g++) { if (globs[g].test(parts[k])) { r = true; break; } }
            }
            hc2[h] = r; return r;
          };
        }
        break;
      case 'tag':
        var tg = lowerList(v);
        if (op === 'none') { fn = function (A) { return !(env.tagsOf && env.tagsOf(A).length); }; } else if (op === 'any') { fn = function (A) { return !!(env.tagsOf && env.tagsOf(A).length); }; } else {
          fn = function (A) {
            var tags = env.tagsOf ? env.tagsOf(A) : [], j;
            for (j = 0; j < tags.length; j++) { if (tg.indexOf(tags[j].toLowerCase()) >= 0) { return true; } }
            return false;
          };
        }
        break;
      case 'ioc':
        fn = function (A) { return !!(env.iocTest && env.iocTest(A)); }; break;
      case 'text':
        var tl = lowerList(v); fn = function (A) { var s = A.raw().toLowerCase(); for (var j = 0; j < tl.length; j++) { if (s.indexOf(tl[j]) >= 0) { return true; } } return false; }; break;
      case 'words':
        var wl = lowerList(v);
        fn = function (A) { var s = (A.si().dec + ' ' + A.qi().lower).toLowerCase(), j; for (j = 0; j < wl.length; j++) { if (s.indexOf(wl[j]) < 0) { return false; } } return true; }; break;
      case 'ptr':
        var pm = setOf(v); fn = function (A) { return pm[A.fileId() + ':' + A.line()] === 1; }; break;
      case 'flag':
        if (op === 'nonAscii') { fn = function (A) { return A.store ? !!(A.store.flags[A.i] & 16) : !!A.r.nonAscii; }; }
        break;
    }
    if (!fn) { throw new Error('Unsupported filter: ' + f + ' ' + op); }
    if (c.neg) { var inner = fn; fn = function (A) { return !inner(A); }; }
    return fn;
  };
  F.compile = function (model, env) {
    if (!model || !model.conds || !model.conds.length) { return null; }
    var fns = [], i;
    for (i = 0; i < model.conds.length; i++) { if (!model.conds[i].off) { fns.push(F.compileCond(model.conds[i], env)); } }
    if (!fns.length) { return null; }
    if (fns.length === 1) { return fns[0]; }
    return function (A) { for (var j = 0; j < fns.length; j++) { if (!fns[j](A)) { return false; } } return true; };
  };
  /* Builds a view (Int32Array of store indices) for a compiled predicate. */
  F.apply = function (store, pred) {
    var n = store.n, out = new Int32Array(n), k = 0, i, A = F.storeAccessor(store);
    if (!pred) { for (i = 0; i < n; i++) { out[i] = i; } return out; }
    for (i = 0; i < n; i++) { A.i = i; if (pred(A)) { out[k++] = i; } }
    return out.subarray(0, k);
  };

  /* ---------- quick filter language ---------- */
  F.FIELD_ALIASES = { ip: 'cip', client: 'cip', c: 'cip', server: 'sip', s: 'stem', uri: 'stem', path: 'stem', q: 'query', agent: 'ua', fam: 'family', family: 'family',
    m: 'method', st: 'status', u: 'user', t: 'taken' };
  F.HELP = [
    ['cip:1.2.3.4,5.6.7.8', 'client IP (also matches effective IP); CIDR allowed: cip:10.0.0.0/8; regex: cip:/^45\\./'],
    ['class:public', 'IP class: public, rfc1918, internal, loopback, linklocal, cgnat, bogon'],
    ['sip:10.0.0.5 port:443', 'server IP / port'],
    ['method:POST  method:invalid', 'HTTP method or any non-standard method'],
    ['status:4xx  status:404.8  status:500-599', 'status class, status.substatus, range'],
    ['stem:login  stem:*.aspx  stem:=/exact  stem:^/portal  stem:/regex/', 'URI stem: contains, glob, exact, starts with, regex'],
    ['ext:.aspx,.php  dir:/uploads/  exec:yes  static:no  new:2026-09-01', 'extension, directory prefix, executable/static flags, stem first seen on/after date'],
    ['query:cmd=  query:/regex/  qlen:>500  decerr:yes', 'query contains / regex / length / decode errors'],
    ['ua:python  family:scanner  ua:empty', 'user agent contains / family / empty'],
    ['user:any  user:admin', 'username present / contains'],
    ['taken:>1000  bytes:>1000000', 'time-taken ms / sc-bytes'],
    ['after:2026-09-10  before:"2026-09-11 12:00"  hour:0-6  dow:0,6', 'time range in display TZ (append Z for UTC), local hour and weekday'],
    ['rule:any  rule:R-EXP-001  rule:R-EXP-*  sev:high', 'rule hits'],
    ['tag:Attacker  tag:any  tag:none  ioc:any', 'tags and IOC matches'],
    ['file:u_ex2609*  text:"exact phrase"', 'source file glob, raw-line substring'],
    ['-field:value', 'prefix any term with - to negate it; bare words must all appear in stem or query']
  ];

  function tokenize(s) {
    var out = [], re = /(-?)([A-Za-z]+):("(?:[^"]*)"|\S+)|"([^"]*)"|(\S+)/g, m;
    while ((m = re.exec(s))) {
      if (m[2]) { out.push({ neg: m[1] === '-', field: m[2].toLowerCase(), value: m[3].charAt(0) === '"' ? m[3].slice(1, -1) : m[3], text: m[0] }); } else { out.push({ neg: false, field: '', value: m[4] !== undefined ? m[4] : m[5], text: m[0] }); }
    }
    return out;
  }
  function yes(v) { return /^(yes|y|true|1|on)$/i.test(v); }
  function splitList(v) { return v.split(',').filter(function (x) { return x !== ''; }); }

  /* Parses quick-filter text into conds. tz = display offset minutes. Throws on syntax errors. */
  F.parse = function (text, tz) {
    var toks = tokenize(text || ''), conds = [], words = [], i, t, f, v, m, c;
    for (i = 0; i < toks.length; i++) {
      t = toks[i]; f = F.FIELD_ALIASES[t.field] || t.field; v = t.value; c = null;
      if (!f) { if (t.value.charAt(0) === '-' && t.value.length > 1) { c = { f: 'words', op: 'contains', v: [t.value.substr(1)], neg: true }; } else { words.push(t.value); } }
      else if (f === 'cip' || f === 'sip' || f === 'eip') {
        if (/^\/.+\/$/.test(v)) { c = { f: f, op: 'regex', v: [v.slice(1, -1)] }; } else if (v.indexOf('/') >= 0) { c = { f: f, op: 'cidr', v: splitList(v) }; } else if (v.indexOf('*') >= 0) { c = { f: f, op: 'regex', v: splitList(v).map(function (x) { return U.globToRegexSrc(x); }) }; } else { c = { f: f, op: 'eq', v: splitList(v) }; }
      } else if (f === 'class') { c = { f: 'eip', op: 'class', v: splitList(v.toLowerCase()) }; }
      else if (f === 'method') { c = v.toLowerCase() === 'invalid' ? { f: 'method', op: 'invalid' } : { f: 'method', op: 'in', v: splitList(v) }; }
      else if (f === 'status') { c = { f: 'status', op: 'in', v: splitList(v) }; }
      else if (f === 'win32') { c = { f: 'win32', op: 'eq', v: splitList(v).map(Number) }; }
      else if (f === 'stem' || f === 'query' || f === 'user' || (f === 'ua' && !/^empty$/i.test(v))) {
        if (f === 'user' && /^any$/i.test(v)) { c = { f: 'user', op: 'present' }; }
        else if (/^\/.+\/$/.test(v)) { c = { f: f, op: 'regex', v: [v.slice(1, -1)] }; }
        else if (v.charAt(0) === '=') { c = { f: f, op: 'eq', v: [v.substr(1)] }; }
        else if (v.charAt(0) === '^') { c = { f: f, op: 'starts', v: [v.substr(1)] }; }
        else if (/[*?]/.test(v)) { c = { f: f, op: 'glob', v: splitList(v) }; }
        else { c = { f: f, op: 'contains', v: splitList(v) }; }
      }
      else if (f === 'ua') { c = { f: 'ua', op: 'empty' }; }
      else if (f === 'family') { c = { f: 'ua', op: 'family', v: splitList(v) }; }
      else if (f === 'ext') { c = { f: 'stem', op: 'ext', v: splitList(v) }; }
      else if (f === 'dir') { c = { f: 'stem', op: 'dir', v: splitList(v) }; }
      else if (f === 'exec') { c = { f: 'stem', op: 'exec', neg: !yes(v) }; }
      else if (f === 'static') { c = { f: 'stem', op: 'static', neg: !yes(v) }; }
      else if (f === 'new') { var nt = U.parseDateInput(v, tz); if (isNaN(nt)) { throw new Error('Bad date in ' + t.text); } c = { f: 'stem', op: 'firstSeenAfter', v: nt }; }
      else if (f === 'qlen') { c = { f: 'query', op: 'lenGte', v: +(v.replace(/^>=?/, '')) }; }
      else if (f === 'decerr') { c = { f: 'query', op: 'decErr', neg: !yes(v) }; }
      else if (f === 'taken' || f === 'bytes') {
        m = /^(<=?|>=?)?(\d+)$/.exec(v); if (!m) { throw new Error('Expected number in ' + t.text); }
        c = { f: f, op: m[1] && m[1].charAt(0) === '<' ? 'lte' : 'gte', v: +m[2] };
      }
      else if (f === 'port') { c = { f: 'port', op: 'in', v: splitList(v) }; }
      else if (f === 'after' || f === 'before' || f === 'on') {
        var ms = U.parseDateInput(v, tz); if (isNaN(ms)) { throw new Error('Bad date in ' + t.text + ' (use YYYY-MM-DD[ HH:MM[:SS]][Z])'); }
        var dayOnly = /^\d{4}-\d{2}-\d{2}$/.test(v);
        if (f === 'after') { c = { f: 'time', op: 'between', v: [ms, null] }; } else if (f === 'before') { c = { f: 'time', op: 'between', v: [null, ms - 1] }; } else { c = { f: 'time', op: 'between', v: [ms, ms + (dayOnly ? 86400000 : 60000) - 1] }; }
      }
      else if (f === 'hour' || f === 'dow') {
        var hl = [], parts = splitList(v), j, k;
        for (j = 0; j < parts.length; j++) { m = /^(\d+)-(\d+)$/.exec(parts[j]); if (m) { for (k = +m[1]; k <= +m[2]; k++) { hl.push(k); } } else { hl.push(+parts[j]); } }
        c = { f: f, op: 'in', v: hl };
      }
      else if (f === 'rule') { c = /^any$/i.test(v) ? { f: 'rule', op: 'any' } : { f: 'rule', op: 'id', v: splitList(v) }; }
      else if (f === 'sev') { c = { f: 'rule', op: 'sev', v: splitList(v) }; }
      else if (f === 'tag') { c = /^any$/i.test(v) ? { f: 'tag', op: 'any' } : (/^none$/i.test(v) ? { f: 'tag', op: 'none' } : { f: 'tag', op: 'has', v: splitList(v) }); }
      else if (f === 'ioc') { c = { f: 'ioc', op: 'any' }; }
      else if (f === 'file') { c = { f: 'file', op: 'glob', v: splitList(v) }; }
      else if (f === 'text') { c = { f: 'text', op: 'contains', v: [v] }; }
      else if (f === 'nonascii') { c = { f: 'flag', op: 'nonAscii', neg: !yes(v) }; }
      else { throw new Error('Unknown field "' + t.field + '" in ' + t.text); }
      if (c) { if (t.neg) { c.neg = !c.neg; } c.text = t.text; conds.push(c); }
    }
    if (words.length) { conds.push({ f: 'words', op: 'contains', v: words, text: words.join(' ') }); }
    // validate regexes eagerly
    for (i = 0; i < conds.length; i++) { F.compileCond(conds[i], { tz: tz }); }
    return { conds: conds };
  };
  F.describe = function (c) {
    if (c.text) { return c.text; }
    var v = c.v === undefined ? '' : (Array.isArray(c.v) ? c.v.join(',') : '' + c.v);
    return (c.neg ? '-' : '') + c.f + ':' + (c.op && c.op !== 'in' && c.op !== 'eq' && c.op !== 'contains' ? c.op + ' ' : '') + v;
  };
  F.toText = function (model) {
    if (!model || !model.conds) { return ''; }
    return model.conds.map(F.describe).join(' ');
  };

  F.PRESETS = [
    { name: 'External clients only', q: 'class:public' },
    { name: 'Exclude static assets', q: 'static:no' },
    { name: 'Exclude loopback / scheduler noise', q: '-class:loopback' },
    { name: 'External POST 200 to executable handlers', q: 'class:public method:POST status:200 exec:yes' },
    { name: 'Server errors (5xx)', q: 'status:5xx' },
    { name: 'Any rule hit', q: 'rule:any' },
    { name: 'High / critical rule hits', q: 'sev:high,critical' },
    { name: 'Scanner and library user agents', q: 'family:scanner,library,empty' },
    { name: 'External 200 responses', q: 'class:public status:200' },
    { name: 'Request filtering blocks (404.x)', q: 'status:404.7,404.8,404.11,404.12,404.13,404.14,404.15,404.18,404.19' },
    { name: 'Slow requests (> 30 s)', q: 'taken:>30000' },
    { name: 'Tagged rows', q: 'tag:any' },
    { name: 'IOC matches', q: 'ioc:any' }
  ];
}(IISLA));
