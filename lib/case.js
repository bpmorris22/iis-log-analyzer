/* IIS Log Analyzer - case.js
 * Settings, case workspace (case.json, audit.log, index/exports/reports folders),
 * tags, notes, finding dispositions and IOC lists.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io, C = NS.caseMgr = {};

  /* ---------- settings ---------- */
  C.userSettingsPath = function () { return U.joinPath(U.joinPath(U.env('APPDATA') || U.env('USERPROFILE'), 'IISLogAnalyzer'), 'settings.json'); };
  C.loadSettings = function () {
    var base = {}, txt = IO.resource('config/settings.json');
    if (txt) { base = JSON.parse(txt); }
    var p = C.userSettingsPath();
    try { var user = U.readJson(p); if (user) { U.extend(base, user); } } catch (e) { NS.bootWarnings.push('User settings unreadable (' + p + '): ' + e.message); }
    base.businessHours = base.businessHours || { start: '08:00', end: '19:00', days: [1, 2, 3, 4, 5] };
    base.indexCaps = base.indexCaps || { ips: 250000, stems: 500000, uas: 100000 };
    base.recentRoots = base.recentRoots || [];
    base.ruleOverrides = base.ruleOverrides || {};
    return base;
  };
  C.saveSettings = function (s) {
    var p = C.userSettingsPath();
    U.ensureFolder(U.parentOf(p));
    var copy = U.extend({}, s);
    delete copy.tzZone; // runtime zone object (functions + transition table), rebuilt from displayTzId
    U.writeJson(p, copy, 2);
  };
  C.loadLists = function () {
    var names = ['sensitive-paths', 'scanner-user-agents', 'executable-extensions', 'static-extensions', 'static-abuse-extensions', 'probe-extensions',
      'login-endpoints', 'known-exploit-paths', 'upload-directories', 'download-endpoints', 'public-download-directories', 'exfil-extensions',
      'exfil-high-extensions', 'webshell-names', 'webshell-parameters', 'dotnet-probe-paths'], out = {}, i, t;
    for (i = 0; i < names.length; i++) {
      t = IO.resource('lists/' + names[i] + '.txt');
      if (t !== null) { out[names[i]] = U.parseList(t); }
    }
    return out;
  };

  /* ---------- case workspace ---------- */
  C.cur = null;
  C.wsRoot = function (settings) { return U.expandEnv(settings.caseWorkspaceRoot || '%USERPROFILE%\\Documents\\IIS Log Analyzer Cases'); };
  C.listCases = function (settings) {
    var root = C.wsRoot(settings), out = [], fso = U.fso();
    if (!fso.FolderExists(root)) { return out; }
    IO.each(fso.GetFolder(root).SubFolders, function (f) {
      var cj = U.joinPath(U.joinPath(f.Path, 'IIS-Log-Analyzer'), 'case.json');
      if (fso.FileExists(cj)) {
        var info = { caseId: f.Name, path: U.parentOf(cj), modified: +new Date(fso.GetFile(cj).DateLastModified) };
        try { var c = U.readJson(cj); info.examiner = c.examiner; info.evidenceId = c.evidenceId; info.sourceHost = c.sourceHost; } catch (e) { }
        out.push(info);
      }
    });
    out.sort(function (a, b) { return b.modified - a.modified; });
    return out;
  };
  C.newCase = function (caseId, settings) {
    return {
      schema: 1, caseId: caseId, examiner: settings.examiner || '', evidenceId: '', sourceHost: '', collectionUtc: '',
      displayTzId: settings.displayTzId || ('fixed:' + (settings.displayTzOffsetMinutes || 0)), displayTzOffsetMinutes: settings.displayTzOffsetMinutes, displayTzLabel: settings.displayTzLabel || U.fmtOffset(settings.displayTzOffsetMinutes || 0),
      description: '', created: U.nowIso(), modified: U.nowIso(), toolVersion: NS.VERSION,
      evidenceRoots: [], lastRoot: '', lastSite: '',
      tagDefs: [{ name: 'Attacker', color: '#c53030' }, { name: 'Suspicious', color: '#dd6b20' }, { name: 'Benign', color: '#38a169' },
        { name: 'Review', color: '#d69e2e' }, { name: 'Reported', color: '#805ad5' }],
      tags: { rows: {}, ips: {}, stems: {}, uas: {}, sessions: {} },
      notes: [], dispositions: {}, presets: [], columns: null, ioc: { text: '' }, ruleOverrides: {}, bookmarks: []
    };
  };
  C.open = function (caseId, settings) {
    caseId = U.trim(caseId);
    if (!caseId || /[\\\/:*?"<>|]/.test(caseId)) { throw new Error('Case ID must not be empty or contain \\ / : * ? " < > |'); }
    var ws = U.joinPath(U.joinPath(C.wsRoot(settings), caseId), 'IIS-Log-Analyzer');
    U.ensureFolder(ws);
    var p = U.joinPath(ws, 'case.json'), c = U.readJson(p), created = false;
    if (!c) { c = C.newCase(caseId, settings); created = true; }
    var def = C.newCase(caseId, settings), k;
    for (k in def) { if (c[k] === undefined) { c[k] = def[k]; } }
    for (k in def.tags) { if (!c.tags[k]) { c.tags[k] = {}; } }
    C.cur = { data: c, ws: ws, path: p, index: U.joinPath(ws, 'index'), exports: U.joinPath(ws, 'exports'), reports: U.joinPath(ws, 'reports'), tmp: U.joinPath(ws, 'tmp') };
    U.ensureFolder(C.cur.index); U.ensureFolder(C.cur.exports); U.ensureFolder(C.cur.reports); U.ensureFolder(C.cur.tmp);
    C.save();
    C.audit(created ? 'case.create' : 'case.open', { caseId: caseId, workspace: ws });
    return C.cur;
  };
  C.save = function () {
    if (!C.cur) { return; }
    C.cur.data.modified = U.nowIso();
    U.writeJson(C.cur.path, C.cur.data, 1);
  };
  C.audit = function (action, params) {
    if (!C.cur) { return; }
    var rec = { ts: U.nowIso(), tool: 'IISLogAnalyzer ' + NS.VERSION, examiner: C.cur.data.examiner, action: action, params: params || {} };
    try { U.appendAscii(U.joinPath(C.cur.ws, 'audit.log'), U.asciiJson(rec)); } catch (e) { NS.ui.toast('Audit log write failed: ' + e.message, 'error'); }
  };
  C.readAudit = function (maxLines) {
    if (!C.cur) { return []; }
    var p = U.joinPath(C.cur.ws, 'audit.log');
    if (!U.fileExists(p)) { return []; }
    var lines = U.readTextUtf8(p).split(/\r?\n/), out = [], i;
    for (i = Math.max(0, lines.length - (maxLines || 1e9)); i < lines.length; i++) { if (lines[i]) { try { out.push(JSON.parse(lines[i])); } catch (e) { } } }
    return out;
  };
  C.errorLog = function (msg) {
    try {
      var dir = C.cur ? C.cur.ws : U.parentOf(C.userSettingsPath());
      U.ensureFolder(dir);
      U.appendAscii(U.joinPath(dir, 'tool-errors.log'), U.asciiJson({ ts: U.nowIso(), msg: msg }));
    } catch (e) { }
  };

  /* ---------- tags ---------- */
  C.rowKey = function (site, fileName, line) { return site + '/' + fileName + ':' + line; };
  C.tagColor = function (name) {
    var d = C.cur ? C.cur.data.tagDefs : [], i;
    for (i = 0; i < d.length; i++) { if (d[i].name === name) { return d[i].color; } }
    return '#718096';
  };
  C.getTags = function (kind, key) { return (C.cur && C.cur.data.tags[kind][key]) || []; };
  C.setTag = function (kind, key, tag, on) {
    if (!C.cur) { return; }
    var m = C.cur.data.tags[kind], list = m[key] || [], i = list.indexOf(tag);
    if (on && i < 0) { list.push(tag); } else if (!on && i >= 0) { list.splice(i, 1); }
    if (list.length) { m[key] = list; } else { delete m[key]; }
  };
  C.tagCounts = function () {
    var out = {}, k, kind, t, i;
    if (!C.cur) { return out; }
    t = C.cur.data.tags;
    for (kind in t) { for (k in t[kind]) { for (i = 0; i < t[kind][k].length; i++) { out[t[kind][k][i]] = (out[t[kind][k][i]] || 0) + 1; } } }
    return out;
  };
  C.addNote = function (targetType, targetKey, text) {
    if (!C.cur) { return; }
    var n = { ts: U.nowIso(), examiner: C.cur.data.examiner, type: targetType, key: targetKey, text: text };
    C.cur.data.notes.push(n); C.save(); C.audit('note.add', { type: targetType, key: targetKey });
    return n;
  };
  C.notesFor = function (type, key) {
    var out = [], i, ns = C.cur ? C.cur.data.notes : [];
    for (i = 0; i < ns.length; i++) { if (ns[i].type === type && ns[i].key === key) { out.push(ns[i]); } }
    return out;
  };

  /* ---------- dispositions ---------- */
  C.DISPOSITIONS = ['Needs review', 'True positive', 'False positive', 'Benign true positive'];
  C.getDisp = function (sig) { return (C.cur && C.cur.data.dispositions[sig]) || null; };
  C.setDisp = function (sig, state, note) {
    if (!C.cur) { return; }
    if (!state) { delete C.cur.data.dispositions[sig]; } else { C.cur.data.dispositions[sig] = { state: state, note: note || '', ts: U.nowIso(), examiner: C.cur.data.examiner }; }
    C.save(); C.audit('finding.disposition', { sig: sig, state: state, note: note || '' });
  };

  /* ---------- IOCs ---------- */
  /* Lines: "type,value[,note]" or a bare value (auto-detected). Types: ip cidr path query ua text regex user */
  C.parseIocs = function (text) {
    var lines = (text || '').split(/\r?\n/), out = [], errors = [], i, l, type, val, note, parts, c;
    for (i = 0; i < lines.length; i++) {
      l = U.trim(lines[i]);
      if (!l || l.charAt(0) === '#') { continue; }
      parts = l.split(',');
      if (parts.length >= 2 && /^(ip|ipv6|cidr|path|query|ua|text|regex|user)$/i.test(U.trim(parts[0]))) {
        type = U.trim(parts[0]).toLowerCase(); val = U.trim(parts[1]); note = U.trim(parts.slice(2).join(','));
      } else {
        val = l; note = '';
        if (U.isValidIp(val)) { type = 'ip'; } else if (U.parseCidr(val) && val.indexOf('/') > 0) { type = 'cidr'; } else if (val.substr(0, 3) === 're:') { type = 'regex'; val = val.substr(3); } else if (val.charAt(0) === '/') { type = 'path'; } else { type = 'text'; }
      }
      if (type === 'ipv6') { type = 'ip'; }
      if (type === 'ip' && !U.isValidIp(val)) { errors.push('Line ' + (i + 1) + ': invalid IP ' + val); continue; }
      if (type === 'cidr' && !U.parseCidr(val)) { errors.push('Line ' + (i + 1) + ': invalid CIDR ' + val); continue; }
      if (type === 'regex') { try { c = new RegExp(val, 'i'); } catch (e) { errors.push('Line ' + (i + 1) + ': invalid regex ' + e.message); continue; } }
      out.push({ type: type, value: val, note: note, line: i + 1 });
    }
    return { iocs: out, errors: errors };
  };
  /* Returns matcher.test(A) -> matching ioc or null. A is a filter accessor. */
  C.compileIocs = function (iocs) {
    var ips = U.newMap(), cidrs = [], paths = [], queries = [], uas = [], texts = [], regexes = [], users = U.newMap(), i, c;
    for (i = 0; i < iocs.length; i++) {
      c = iocs[i];
      switch (c.type) {
        case 'ip': ips[c.value.toLowerCase()] = c; break;
        case 'cidr': cidrs.push({ c: U.parseCidr(c.value), ioc: c }); break;
        case 'path': paths.push({ re: /[*?]/.test(c.value) ? U.globToRegex(c.value) : new RegExp(U.reEscape(c.value), 'i'), ioc: c }); break;
        case 'query': queries.push({ v: c.value.toLowerCase(), ioc: c }); break;
        case 'ua': uas.push({ v: c.value.toLowerCase(), ioc: c }); break;
        case 'text': texts.push({ v: c.value.toLowerCase(), ioc: c }); break;
        case 'regex': regexes.push({ re: new RegExp(c.value, 'i'), ioc: c }); break;
        case 'user': users[c.value.toLowerCase()] = c; break;
      }
    }
    var ipCache = U.newMap(), stemCache = U.newMap(), uaCache = U.newMap(), nCache = 0;
    function ipHit(ip) {
      var v = ipCache[ip];
      if (v !== undefined) { return v; }
      v = ips[ip.toLowerCase()] || null;
      if (!v) { for (var j = 0; j < cidrs.length; j++) { if (U.cidrMatch(cidrs[j].c, ip)) { v = cidrs[j].ioc; break; } } }
      if (nCache++ > 300000) { ipCache = U.newMap(); stemCache = U.newMap(); uaCache = U.newMap(); nCache = 0; }
      ipCache[ip] = v; return v;
    }
    function stemHit(s) {
      var v = stemCache[s];
      if (v !== undefined) { return v; }
      v = null; for (var j = 0; j < paths.length; j++) { if (paths[j].re.test(s)) { v = paths[j].ioc; break; } }
      stemCache[s] = v; return v;
    }
    function uaHit(s) {
      var v = uaCache[s];
      if (v !== undefined) { return v; }
      v = null; var l = s.toLowerCase(); for (var j = 0; j < uas.length; j++) { if (l.indexOf(uas[j].v) >= 0) { v = uas[j].ioc; break; } }
      uaCache[s] = v; return v;
    }
    return {
      count: iocs.length,
      test: function (A) {
        var h = ipHit(A.cip()) || (A.eip() !== A.cip() ? ipHit(A.eip()) : null), j, s;
        if (h) { return h; }
        if (paths.length) { h = stemHit(A.si().dec); if (h) { return h; } }
        if (uas.length) { h = uaHit(A.ui().dec); if (h) { return h; } }
        if (queries.length) { s = A.qi().lower; for (j = 0; j < queries.length; j++) { if (s.indexOf(queries[j].v) >= 0) { return queries[j].ioc; } } }
        if (users[A.user().toLowerCase()]) { return users[A.user().toLowerCase()]; }
        if (texts.length || regexes.length) {
          s = A.raw(); var sl = s.toLowerCase();
          for (j = 0; j < texts.length; j++) { if (sl.indexOf(texts[j].v) >= 0) { return texts[j].ioc; } }
          for (j = 0; j < regexes.length; j++) { if (regexes[j].re.test(s)) { return regexes[j].ioc; } }
        }
        return null;
      },
      ipHit: ipHit, stemHit: stemHit, uaHit: uaHit
    };
  };
  C.readListFile = function (path) {
    path = U.expandEnv(path || '');
    if (!path || !U.fileExists(path)) { return null; }
    var t = U.readTextUtf8(path);
    if (t.charCodeAt(0) === 0xFEFF) { t = t.substr(1); }
    return t;
  };
}(IISLA));
