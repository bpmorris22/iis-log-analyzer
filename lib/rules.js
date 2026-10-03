/* IIS Log Analyzer - rules.js
 * Rule set loading, row-scope evaluation (shared by scan / load / sweep),
 * custom JSON rule compilation and finding construction.
 */
(function (NS) {
  'use strict';
  var U = NS.util, P = NS.parser, R = NS.rules = {};

  R.SEV = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  R.SEV_NAMES = ['critical', 'high', 'medium', 'low', 'info'];
  R.maxSev = function (a, b) { return (R.SEV[a] || 0) >= (R.SEV[b] || 0) ? a : b; };
  R.EXPLOIT_RULES = { 'R-EXP-001': 1, 'R-EXP-002': 1, 'R-EXP-003': 1, 'R-EXP-004': 1, 'R-EXP-005': 1, 'R-EXP-006': 1 };

  /* Simple FNV-1a 32-bit hash, used to fingerprint the rule set text. */
  R.fnv = function (s) {
    var h = 0x811c9dc5, i;
    for (i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0; }
    return ('00000000' + h.toString(16)).slice(-8);
  };

  R.loadRuleset = function (text, overrides) {
    var o = JSON.parse(text), rs = { version: o.version, rules: [], byId: {}, textHash: R.fnv(text), hash: '', enabledIds: [], disabledIds: [] }, i, r;
    for (i = 0; i < o.rules.length; i++) {
      r = o.rules[i];
      r.params = r.params || {};
      if (overrides && overrides[r.id] !== undefined) { r.enabled = !!overrides[r.id]; }
      rs.rules.push(r); rs.byId[r.id] = r;
      (r.enabled ? rs.enabledIds : rs.disabledIds).push(r.id);
    }
    // The fingerprint covers the rule text AND which rules are enabled (per-case and default overrides),
    // so an index or report always identifies the exact rule set that produced it.
    rs.hash = R.fnv(text + '\n#enabled:' + rs.enabledIds.join(','));
    return rs;
  };

  /* ---------- custom rule compiler ---------- */
  function strCond(spec, getter) {
    if (spec === undefined) { return null; }
    if (typeof spec === 'string') { spec = { contains: spec }; }
    var re = null;
    if (spec.regex) { re = new RegExp(spec.regex, 'i'); } else if (spec.glob) { re = U.globToRegex(spec.glob); } else if (spec.contains) { re = new RegExp(U.reEscape(spec.contains), 'i'); } else if (spec.equals) { re = new RegExp('^' + U.reEscape(spec.equals) + '$', 'i'); }
    if (!re) { return null; }
    return function (c) { return re.test(getter(c)); };
  }
  function listCond(arr, getter, upper) {
    if (!arr) { return null; }
    var m = {}, i;
    for (i = 0; i < arr.length; i++) { m[upper ? ('' + arr[i]).toUpperCase() : '' + arr[i]] = 1; }
    return function (c) { return m[getter(c)] === 1; };
  }
  R.compileMatch = function (match) {
    var conds = [], f, cidrs, i;
    f = listCond(match.method, function (c) { return c.r.method.toUpperCase(); }, true); if (f) { conds.push(f); }
    f = strCond(match.stem, function (c) { return c.si.dec; }); if (f) { conds.push(f); }
    f = strCond(match.query, function (c) { return c.qi.dec; }); if (f) { conds.push(f); }
    f = strCond(match.ua, function (c) { return c.ui.dec; }); if (f) { conds.push(f); }
    f = strCond(match.user, function (c) { return c.r.user; }); if (f) { conds.push(f); }
    f = strCond(match.raw, function (c) { return c.r.raw; }); if (f) { conds.push(f); }
    f = listCond(match.ipClass, function (c) { return c.cls; }); if (f) { conds.push(f); }
    f = listCond(match.uaFamily, function (c) { return c.ui.fam; }); if (f) { conds.push(f); }
    f = listCond(match.ext, function (c) { return c.si.ext; }); if (f) { conds.push(f); }
    if (match.status) {
      var st = [].concat(match.status);
      conds.push(function (c) {
        var j, s;
        for (j = 0; j < st.length; j++) {
          s = '' + st[j];
          if (/^\dxx$/i.test(s)) { if (Math.floor(c.r.status / 100) === +s.charAt(0)) { return true; } } else if (s.indexOf('.') > 0) { if (c.r.status + '.' + c.r.sub === s) { return true; } } else if (c.r.status === +s) { return true; }
        }
        return false;
      });
    }
    if (match.cip) {
      cidrs = [];
      var src = [].concat(match.cip);
      for (i = 0; i < src.length; i++) { var cd = U.parseCidr(src[i]); if (cd) { cidrs.push(cd); } }
      conds.push(function (c) { for (var j = 0; j < cidrs.length; j++) { if (U.cidrMatch(cidrs[j], c.ip)) { return true; } } return false; });
    }
    if (match.minTaken !== undefined) { conds.push(function (c) { return c.r.taken >= match.minTaken; }); }
    if (match.exec !== undefined) { conds.push(function (c) { return c.si.exec === !!match.exec; }); }
    if (!conds.length) { return function () { return false; }; }
    return function (c) { for (var j = 0; j < conds.length; j++) { if (!conds[j](c)) { return false; } } return true; };
  };

  /* ---------- built-in row rules ---------- */
  function setOf(arr) { var m = {}, i; for (i = 0; i < (arr || []).length; i++) { m[arr[i]] = 1; } return m; }
  var VALID = setOf(U.METHODS_VALID);

  R.ROW_BUILTINS = {
    'R-SCAN-002': function (c) {
      if (c.si.sens) { return (c.r.status === 200 && c.pub) ? 'high' : true; }
      return c.si.probe && c.r.status === 404;
    },
    'R-SCAN-003': function (c, p) {
      if (c.ui.scanner && !(p.excludeInternal && U.isInternalClass(c.cls))) { return true; }
      return !!(p.emptyUaFromPublic && c.ui.empty && c.pub);
    },
    'R-SCAN-004': function (c) { return VALID[c.r.method.toUpperCase()] !== 1 || c.r.status === 405 || c.r.status === 501; },
    'R-SCAN-005': function (c, p) { return c.r.status === 404 && p._sub[c.r.sub] === 1; },
    'R-SCAN-006': function (c, p) { return c.r.status === 403 && p._sub[c.r.sub] === 1; },
    'R-SCAN-008': function (c) { return c.pub && c.qi.phpinfo; },
    'R-EXP-001': function (c) { return c.qi.exp001 || c.si.exp001; },
    'R-EXP-002': function (c) { return c.si.trav || c.qi.trav; },
    'R-EXP-003': function (c, p) { return c.qi.sqli === 2 ? true : (p.includeMedium && c.qi.sqli === 1 ? 'medium' : false); },
    'R-EXP-004': function (c) { return c.qi.cmdi || c.si.cmdi; },
    'R-EXP-005': function (c) {
      return c.si.dotnetProbe || (c.si.axd && c.qi.hasD && c.r.status === 500) || (c.si.svc && c.qi.wsdl && c.r.status === 500);
    },
    'R-EXP-006': function (c, p) { return c.si.exPath ? (p._esc[c.r.status] === 1 ? 'high' : true) : false; },
    'R-EXP-007': function (c, p, ev) {
      if (c.r.status !== 500) { return false; }
      var w = ev.expWin[c.ip];
      return !!(w && c.r.ts - w.ts <= p.windowMinutes * 60000 && w.stems[c.si.key] === 1);
    },
    'R-EXP-008': function (c, p) {
      if (c.r.stem.length >= p.stemLen || c.qi.len >= p.queryLen) { return true; }
      if (c.qi.len >= p.entropyMinLen) {
        if (c.qi.ent === undefined) { c.qi.ent = U.entropy(c.r.query); }
        return c.qi.ent >= p.entropy;
      }
      return false;
    },
    'R-EXP-009': function (c, p) {
      return (c.pub && p._st[c.r.status] === 1) || (p._w32[c.r.win32] === 1 && c.r.method === 'POST' && c.si.exec);
    },
    'R-WS-004': function (c) { return c.si.shellName || c.qi.shellParam || c.ui.shellUa; },
    'R-WS-005': function (c) {
      return c.si.ws005 && c.pub && c.r.status === 200 && (c.r.method === 'POST' || (!c.qi.empty && !c.qi.versionOnly));
    },
    'R-AUTH-003': function (c, p) {
      if (c.r.user === '-' || c.r.user === '') { return false; }
      return c.newUser || c.pub || p._names.test(c.r.user);
    },
    'R-EXF-001': function (c) {
      if (!(c.pub && c.r.method === 'GET' && c.r.status === 200 && c.si.exf && !c.si.pubDl)) { return false; }
      return c.si.exfHigh ? 'high' : true;
    },
    'R-EXF-002': function (c, p) { return c.pub && c.r.status === 200 && ((c.r.scBytes >= p.bytes) || c.r.taken >= p.takenMs); },
    'R-EXF-003': function (c) { return c.pub && c.si.dlEp; }
  };
  R.AGG_BUILTINS = ['R-SCAN-001', 'R-SCAN-007', 'R-SCAN-009', 'R-WS-001', 'R-WS-002', 'R-WS-003', 'R-WS-006', 'R-WS-007',
    'R-AUTH-001', 'R-AUTH-002', 'R-AUTH-004', 'R-AUTH-005', 'R-EXF-004',
    'R-INF-001', 'R-INF-002', 'R-INF-003', 'R-INF-004', 'R-INF-005', 'R-INF-006', 'R-INF-007'];

  function prepParams(rule) {
    var p = U.extend({}, rule.params || {});
    if (rule.id === 'R-SCAN-005' || rule.id === 'R-SCAN-006') { p._sub = setOf(p.substatus); }
    if (rule.id === 'R-EXP-006') { p._esc = setOf(p.escalateStatuses || [200, 500]); }
    if (rule.id === 'R-EXP-007') { p.windowMinutes = p.windowMinutes || 10; }
    if (rule.id === 'R-EXP-008') {
      p.stemLen = p.stemLen || 1024; p.queryLen = p.queryLen || 2048; p.entropy = p.entropy || 5.5; p.entropyMinLen = p.entropyMinLen || 200;
    }
    if (rule.id === 'R-EXP-009') { p._st = setOf(p.statuses || [400, 413, 414, 431]); p._w32 = setOf(p.win32 || [1236, 995]); }
    if (rule.id === 'R-AUTH-003') { p._names = P.buildMatcher([p.names || 're:^admin$']); }
    if (rule.id === 'R-EXF-002') { p.bytes = p.bytes || 52428800; p.takenMs = p.takenMs || 60000; }
    return p;
  };

  /* ---------- evaluator ---------- */
  /* Evaluates enabled row rules for a row. Maintains the per-client exploit window for R-EXP-007. */
  R.Evaluator = function (ruleset, deriver) {
    this.rs = ruleset; this.D = deriver;
    this.list = [];
    this.expWin = U.newMap();
    this.users = U.newMap();
    this.userFirst = null; // optional map user -> "fileId:line" for load-pass first-seen
    var i, r, fn;
    for (i = 0; i < ruleset.rules.length; i++) {
      r = ruleset.rules[i];
      if (!r.enabled || (r.scope !== 'row')) { continue; }
      fn = R.ROW_BUILTINS[r.id];
      if (!fn && r.match) { fn = (function (m) { var f = R.compileMatch(m); return function (c) { return f(c); }; }(r.match)); }
      if (!fn) { continue; }
      this.list.push({ id: r.id, sev: r.severity, fn: fn, p: prepParams(r), exploit: R.EXPLOIT_RULES[r.id] === 1 });
    }
    this.ctx = { r: null, si: null, qi: null, ui: null, cls: '', pub: false, ip: '', newUser: false };
    this.hits = [];
    this.hitSev = [];
  };
  /* Returns number of hits; ids in this.hits[0..n-1], severities in this.hitSev. */
  R.Evaluator.prototype.evaluate = function (r) {
    var c = this.ctx, D = this.D, i, res, n = 0, L = this.list, anyExp = false;
    c.r = r; c.ip = r.eip; c.si = D.stem(r.stem); c.qi = D.query(r.query); c.ui = D.ua(r.ua);
    c.cls = D.ipClass(r.eip); c.pub = c.cls === 'public';
    c.newUser = false;
    if (r.user !== '-' && r.user !== '') {
      if (this.userFirst) { c.newUser = this.userFirst[r.user] === r.fileId + ':' + r.lineNo; } else if (!this.users[r.user]) { this.users[r.user] = 1; c.newUser = true; }
    }
    for (i = 0; i < L.length; i++) {
      res = L[i].fn(c, L[i].p, this);
      if (res) {
        this.hits[n] = L[i].id;
        this.hitSev[n] = typeof res === 'string' ? res : L[i].sev;
        n++;
        if (L[i].exploit) { anyExp = true; }
      }
    }
    if (anyExp) {
      var w = this.expWin[c.ip];
      if (!w || r.ts - w.ts > 600000) { w = this.expWin[c.ip] = { ts: r.ts, stems: U.newMap() }; }
      w.ts = r.ts; w.stems[c.si.key] = 1;
    }
    this.n = n;
    return n;
  };
  R.Evaluator.prototype.hitString = function () {
    return this.n ? this.hits.slice(0, this.n).join(',') : '';
  };

  /* ---------- findings ---------- */
  R.newFinding = function (rule, entity, key, sev) {
    return {
      id: '', ruleId: rule.id, name: rule.name, category: rule.category, severity: sev || rule.severity,
      attack: rule.attack || [], entity: entity, key: key, count: 0, first: 0, last: 0,
      ips: [], stems: [], examples: [], detail: '', description: rule.description, falsePositives: rule.falsePositives
    };
  };
  R.findingSig = function (f) { return f.ruleId + '|' + f.entity + '|' + f.key; };
  R.sortFindings = function (list) {
    list.sort(function (a, b) {
      return (R.SEV[b.severity] || 0) - (R.SEV[a.severity] || 0) || (a.first || 0) - (b.first || 0) || (a.ruleId < b.ruleId ? -1 : 1);
    });
    var i;
    for (i = 0; i < list.length; i++) { list[i].id = 'F-' + ('0000' + (i + 1)).slice(-4); }
    return list;
  };
}(IISLA));
