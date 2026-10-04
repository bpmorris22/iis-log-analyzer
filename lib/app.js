/* IIS Log Analyzer - app.js
 * Controller: boot, global state, navigation, case/evidence handling,
 * scan / load / hash orchestration, pivots, autotest mode.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io, P = NS.parser, R = NS.rules, S = NS.scan, St = NS.store, F = NS.filter, C = NS.caseMgr, UI = NS.ui, X = NS.exporter;
  var A = NS.app = {};
  var st = A.state = {
    settings: null, lists: null, ruleset: null, rulesText: '', bits: 64, disc: null, site: null, siteIdx: 0, manifest: null, idx: null, store: null,
    grid: { model: { conds: [] }, view: null, sortKey: 'ts', sortDesc: false, sel: -1, first: 0, text: '' },
    columns: null, view: 'home', viewParam: null, busy: false, iocs: null, iocMatcher: null, sessions: null, autotest: null
  };

  /* ---------- boot ---------- */
  A.boot = function () {
    window.onerror = function (msg, url, line, col, err) {
      var text = msg + ' @ ' + (url ? U.baseOf('' + url) : '') + ':' + line + (col ? ':' + col : '') + (err && err.stack ? '\n' + err.stack : '');
      C.errorLog(text);
      NS.trace('ERROR ' + text);
      if (st.autotest) { st.autotest.errors.push(text); }
      try { UI.toast('Error: ' + msg + ' (line ' + line + ')', 'error'); } catch (e) { }
      return true;
    };
    if (!document.documentMode || document.documentMode < 11) {
      document.body.appendChild(UI.h('div', { className: 'fatal' }, 'IIS Log Analyzer requires the IE11 document mode (document.documentMode = ' + document.documentMode + '). Run it with mshta.exe on Windows 10/11.'));
      return;
    }
    var arch = U.env('PROCESSOR_ARCHITECTURE'), wow = U.env('PROCESSOR_ARCHITEW6432');
    st.bits = (arch && arch.toUpperCase() === 'X86') ? 32 : 64;
    st.osBits = wow ? 64 : st.bits;
    st.settings = C.loadSettings();
    var args = A.commandLine();
    // Double-clicking an .hta uses the 32-bit SysWOW64 mshta by default; relaunch in the 64-bit host for full capacity.
    if (st.bits === 32 && st.osBits === 64 && !args.autotest && !args.no64 && A.relaunch64(args)) { return; }
    UI.applyScale(UI.dpiScale() * (args.zoom || st.settings.uiZoom || 1));
    A.applyBitness();
    st.lists = C.loadLists();
    A.loadRules();
    A.applyNetworkLists();
    if (st.settings.geoCsv) { try { NS.enrich.load(st.settings.geoCsv); } catch (e) { NS.enrich.error = e.message; } if (NS.enrich.error) { NS.bootWarnings.push(NS.enrich.error); } }
    A.setZone(NS.tz.forSettings(st.settings));
    St.tagText = A.tagText;
    A.layout();
    document.onkeydown = A.globalKeys;
    var rsT = null;
    window.onresize = function () {
      if (rsT) { clearTimeout(rsT); }
      rsT = setTimeout(function () {
        if (st.view === 'grid') { if (st.gridCtl) { st.gridCtl.refresh(true); } return; }
        if (/^(overview|timeline|ipProfile|uriProfile|integrity)$/.test(st.view) && !document.querySelector('.overlay')) { A.nav(st.view, st.viewParam); }
      }, 350);
    };
    document.oncontextmenu = function (e) { var t = (e || window.event).srcElement; return !!(t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA')); };
    document.onmousewheel = function (e) {
      e = e || window.event;
      if (!e.ctrlKey) { return true; }
      A.zoom(e.wheelDelta > 0 ? 1 : -1);
      if (e.preventDefault) { e.preventDefault(); } e.returnValue = false; return false;
    };
    if (args.autotest || args.trace) { NS.traceOn = true; }
    NS.trace('boot args=' + JSON.stringify(args) + ' scale=' + UI.scale);
    if (args.tztest) { var tr = NS.tz.selfTest(args.tztest, args.out || U.joinPath(U.env('TEMP'), 'iisla-tztest.json')); NS.trace('tztest checked=' + tr.checked + ' mismatches=' + tr.mismatches.length); window.close(); return; }
    if (args.autotest) { A.autotest(args); return; }
    A.nav('home');
    if (args.root && (U.folderExists(args.root) || U.fileExists(args.root))) { A.openEvidencePrompt(args.root); }
    var w; for (w = 0; w < NS.bootWarnings.length; w++) { UI.toast(NS.bootWarnings[w], 'warn', 10000); }
  };
  /* Restarts this HTA in %WINDIR%\Sysnative\mshta.exe (the 64-bit host, as seen from a 32-bit process). */
  A.relaunch64 = function (args) {
    try {
      var sysnative = U.joinPath(U.env('WINDIR'), 'Sysnative\\mshta.exe');
      if (!U.fileExists(sysnative)) { return false; }
      var self = args.htaPath || decodeURIComponent(('' + document.location.pathname).replace(/^\/+/, '')).replace(/\//g, '\\');
      var cmd = '"' + sysnative + '" "' + self + '"', i;
      for (i = 0; i < args.pass.length; i++) { cmd += ' "' + args.pass[i].replace(/"/g, '') + '"'; }
      cmd += ' /no64';
      U.shell().Run(cmd, 1, false);
      window.close();
      return true;
    } catch (e) { NS.bootWarnings.push('Could not relaunch in 64-bit mshta (' + e.message + '); running 32-bit with reduced row cap.'); return false; }
  };
  /* Font/UI size: dir +1 larger, -1 smaller, 0 reset to the Windows display scaling. Persisted in user settings. */
  A.ZOOM_STEPS = [0.6, 0.7, 0.8, 0.9, 1, 1.1, 1.25, 1.4, 1.6, 1.8, 2];
  A.zoom = function (dir) {
    var z = st.settings.uiZoom || 1, steps = A.ZOOM_STEPS, i, best = 4;
    for (i = 0; i < steps.length; i++) { if (Math.abs(steps[i] - z) < Math.abs(steps[best] - z)) { best = i; } }
    if (dir === 0) { best = 4; } else { best = Math.max(0, Math.min(steps.length - 1, best + dir)); }
    st.settings.uiZoom = steps[best];
    try { C.saveSettings(st.settings); } catch (e) { }
    if (st.view === 'grid' && NS.views.saveGridPos) { NS.views.saveGridPos(); }
    UI.applyScale(UI.dpiScale() * st.settings.uiZoom);
    A.renderToolbar();
    if (!document.querySelector('.overlay')) { A.nav(st.view, st.viewParam); }
  };
  /* Sets the display time zone used for local times, local-time filters, business hours and exports. */
  A.setZone = function (zone) {
    St.tz = zone; st.settings.tzZone = zone;
    if (st.el) { A.renderToolbar(); }
  };
  A.applyBitness = function () {
    var s = st.settings;
    s.maxRows = st.bits === 32 ? s.maxRows32 : s.maxRows64;
    if (s.keepRaw === undefined) { s.keepRaw = st.bits === 32 ? s.keepRaw32 : s.keepRaw64; }
    s.chunkChars = st.bits === 32 ? (s.chunkChars32 || 2097152) : (s.chunkChars || 4194304);
    if (st.bits === 32) { s.ruleHitRetention = s.ruleHitRetention32 || 20000; }
  };
  A.loadRules = function () {
    st.rulesText = IO.resource('rules/default-rules.json');
    if (!st.rulesText) { throw new Error('rules/default-rules.json not found next to the HTA'); }
    var ov = U.extend({}, st.settings.ruleOverrides || {}, C.cur ? C.cur.data.ruleOverrides : {});
    st.ruleset = R.loadRuleset(st.rulesText, ov);
    var sev = {}, i;
    for (i = 0; i < st.ruleset.rules.length; i++) { sev[st.ruleset.rules[i].id] = st.ruleset.rules[i].severity; }
    st.ruleSev = sev;
  };
  A.applyNetworkLists = function () {
    U.setInternalCidrs(st.settings.internalCidrs || []);
    U.setTestNetsPublic(!!st.settings.testNetsPublic || !!st.demoTestNets);
    var t = C.readListFile(st.settings.allowedIpsFile), n = 0;
    if (t) { n = U.setAllowlist(U.parseList(t)); } else { U.setAllowlist([]); }
    st.allowCount = n;
  };
  /* Parses mshta command line: IISLogAnalyzer.hta [evidencePath] [/autotest root] [/files:regex] [/out:path] [/case:id] [/load] [/hash] [/stay] */
  A.commandLine = function () {
    var cl = '';
    try { cl = UI.$('IISLA').commandLine || ''; } catch (e) { cl = ''; }
    if (!cl) {
      try {
        // IE9+ document modes do not expose HTA commandLine or GetObject(); query WMI through the locator object.
        var wmi = new ActiveXObject('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\cimv2'), items = wmi.ExecQuery("SELECT CommandLine, CreationDate FROM Win32_Process WHERE Name = 'mshta.exe'"), best = '', bestD = '';
        IO.each(items, function (p) { var c = p.CommandLine || ''; if (c.toLowerCase().indexOf('iisloganalyzer') >= 0 && (p.CreationDate || '') >= bestD) { best = c; bestD = p.CreationDate || ''; } });
        cl = best;
      } catch (e2) { cl = ''; }
    }
    var toks = [], re = /"([^"]*)"|(\S+)/g, m;
    while ((m = re.exec(cl))) { toks.push(m[1] !== undefined ? m[1] : m[2]); }
    var out = { raw: cl }, i, t, hta = -1;
    for (i = 0; i < toks.length; i++) { if (/\.hta$/i.test(toks[i])) { hta = i; break; } }
    out.htaPath = hta >= 0 ? toks[hta] : '';
    out.pass = [];
    for (i = hta + 1; i < toks.length; i++) {
      t = toks[i];
      // The default .hta association appends "{GUID}%U{GUID}"; those tokens are not arguments.
      if (/^\{[0-9a-f\-]{36}\}/i.test(t)) { continue; }
      out.pass.push(t);
      if (/^\/autotest$/i.test(t)) { out.autotest = true; out.root = toks[++i]; } else if (/^\/files:/i.test(t)) { out.files = t.substr(7); } else if (/^\/out:/i.test(t)) { out.out = t.substr(5); } else if (/^\/case:/i.test(t)) { out.caseId = t.substr(6); } else if (/^\/load$/i.test(t)) { out.load = true; } else if (/^\/hash$/i.test(t)) { out.hash = true; } else if (/^\/stay$/i.test(t)) { out.stay = true; } else if (/^\/noscan$/i.test(t)) { out.noscan = true; } else if (/^\/filterq:/i.test(t)) { out.filterq = t.substr(9); } else if (/^\/cancelafter:/i.test(t)) { out.cancelAfter = t.substr(13); } else if (/^\/engine:/i.test(t)) { out.engine = t.substr(8); } else if (/^\/lpstub:/i.test(t)) { out.lpstub = t.substr(8); } else if (/^\/rawbundle$/i.test(t)) { out.rawbundle = true; } else if (/^\/streammb:/i.test(t)) { out.streamMB = +t.substr(10); } else if (/^\/tz:/i.test(t)) { out.tz = t.substr(4); } else if (/^\/testnets$/i.test(t)) { out.testnets = true; } else if (/^\/views$/i.test(t)) { out.views = true; } else if (/^\/no64$/i.test(t)) { out.no64 = true; } else if (/^\/tztest:/i.test(t)) { out.tztest = t.substr(8); } else if (/^\/zoom:/i.test(t)) { out.zoom = +t.substr(6); } else if (/^\/trace$/i.test(t)) { out.trace = true; } else if (/^\/shots$/i.test(t)) { out.shots = true; } else if (/^\/shotms:/i.test(t)) { out.shotMs = t.substr(8); } else if (t.charAt(0) !== '/' && !out.root) { out.root = t; }
    }
    return out;
  };

  /* ---------- layout ---------- */
  A.NAV = [
    ['home', 'Case & evidence'], ['overview', 'Overview'], ['findings', 'Findings'], ['grid', 'Rows (grid)'], ['topn', 'Top-N'], ['timeline', 'Timeline'],
    ['ips', 'Client IPs'], ['uris', 'URI stems'], ['sessions', 'Sessions'], ['integrity', 'Integrity'], ['iocs', 'IOCs'], ['logparser', 'Log Parser'], ['tags', 'Tags & notes'],
    ['settings', 'Settings'], ['help', 'Help']
  ];
  A.layout = function () {
    var app = UI.$('app');
    UI.clear(app);
    st.el = {
      toolbar: UI.h('div', { id: 'toolbar' }), nav: UI.h('div', { id: 'nav' }), main: UI.h('div', { id: 'main' }), status: UI.h('div', { id: 'statusbar' })
    };
    app.appendChild(st.el.toolbar);
    app.appendChild(UI.h('div', { id: 'mid' }, [st.el.nav, st.el.main]));
    app.appendChild(st.el.status);
    A.renderToolbar(); A.renderNav(); A.renderStatus();
  };
  A.renderToolbar = function () {
    var tb = st.el.toolbar;
    UI.clear(tb);
    tb.appendChild(UI.h('span', { className: 'brand' }, 'IIS Log Analyzer'));
    tb.appendChild(UI.btn('Open evidence\u2026', function () { A.nav('home'); }, '', 'Choose case and evidence folder'));
    tb.appendChild(UI.btn('Scan\u2026', function () { NS.views.scanDialog(); }, '', 'Index all selected log files (streaming)'));
    tb.appendChild(UI.btn('Load rows\u2026', function () { NS.views.loadDialog(); }, '', 'Load rows into the grid'));
    tb.appendChild(UI.btn('Export\u2026', function () { NS.views.exportDialog(); }, '', 'Export rows, findings, tables (Ctrl+E)'));
    tb.appendChild(UI.btn('Report', function () { A.report(); }, '', 'Generate HTML case report'));
    var sp = UI.h('span', { className: 'tb-right' });
    var caseTxt = C.cur ? 'Case: ' + C.cur.data.caseId : 'No case open';
    sp.appendChild(UI.h('span', { className: 'tb-info', title: C.cur ? C.cur.ws : '' }, caseTxt));
    sp.appendChild(UI.h('span', { className: 'tb-info' }, 'Display TZ: ' + (St.tz && St.tz.label ? St.tz.label : '') + (St.tz && St.tz.kind === 'windows' ? ' (DST)' : '') + ' \u00b7 times stored UTC'));
    sp.appendChild(UI.h('span', { className: 'tb-info' + (st.bits === 32 ? ' warn' : '') }, st.bits + '-bit host'));
    var zt = 'Text size. Ctrl+= / Ctrl+- / Ctrl+0 or Ctrl+mouse wheel. Windows display scaling ' + Math.round(UI.dpiScale() * 100) + '% is applied automatically.';
    sp.appendChild(UI.h('span', { className: 'zoom' }, [
      UI.btn('A\u2212', function () { A.zoom(-1); }, 'zbtn', 'Smaller text (Ctrl+-)'),
      UI.btn(Math.round((st.settings.uiZoom || 1) * 100) + '%', function () { A.zoom(0); }, 'zbtn zval', zt + ' Click to reset.'),
      UI.btn('A+', function () { A.zoom(1); }, 'zbtn', 'Larger text (Ctrl+=)')]));
    tb.appendChild(sp);
  };
  A.renderNav = function () {
    var nv = st.el.nav, i;
    UI.clear(nv);
    for (i = 0; i < A.NAV.length; i++) {
      (function (n) {
        var badge = null;
        if (n[0] === 'findings' && st.idx) {
          var hc = 0; st.idx.findings.forEach(function (f) { if (f.severity === 'critical' || f.severity === 'high') { hc++; } });
          badge = UI.h('span', { className: 'badge' + (hc ? ' hot' : '') }, '' + st.idx.findings.length);
        }
        if (n[0] === 'grid' && st.store) { badge = UI.h('span', { className: 'badge' }, U.fmtNum(st.grid.view ? st.grid.view.length : st.store.n)); }
        if (n[0] === 'logparser') { var lps = NS.logparser.status(st.settings); badge = UI.h('span', { className: 'tl-dot ' + lps.state, title: lps.label }); }
        nv.appendChild(UI.h('div', { className: 'nav-i' + (st.view === n[0] || (st.view === 'ipProfile' && n[0] === 'ips') || (st.view === 'uriProfile' && n[0] === 'uris') ? ' active' : ''), onclick: function () { A.nav(n[0]); } }, [n[1], badge]));
      }(A.NAV[i]));
    }
  };
  A.renderStatus = function () {
    var s = st.el.status, parts = [];
    UI.clear(s);
    if (st.site) { parts.push(st.site.name + ': ' + U.fmtNum(st.site.files.length) + ' files, ' + U.fmtBytes(st.site.totalBytes)); }
    if (st.idx) { parts.push((st.idx.partial ? 'PARTIAL index ' : 'Indexed ') + U.fmtNum(st.idx.totals.rows) + ' rows (' + st.idx.filesDone + '/' + st.idx.files.length + ' files)'); }
    if (st.idx) { parts.push(U.fmtNum(st.idx.findings.length) + ' findings'); }
    if (st.store) { parts.push('Loaded ' + U.fmtNum(st.store.n) + ' rows' + (st.store.capped ? ' (CAPPED)' : '') + ', ~' + U.fmtBytes(st.store.bytesEstimate())); }
    if (st.grid.view && st.store) { parts.push('Grid ' + U.fmtNum(st.grid.view.length)); }
    if (st.idx) { parts.push('Malformed ' + U.fmtNum(st.idx.totals.malformed)); }
    if (st.allowCount) { parts.push(st.allowCount + ' allow-listed IPs'); }
    s.appendChild(UI.h('span', null, parts.join('   \u00b7   ') || 'Ready. Open a case and an evidence folder to begin.'));
    if (st.busy) { s.appendChild(UI.h('span', { className: 'busy' }, ' working\u2026')); }
  };
  A.refreshChrome = function () { A.renderToolbar(); A.renderNav(); A.renderStatus(); };
  A.nav = function (view, param) {
    UI.closeMenu();
    if (st.view === 'grid' && NS.views.saveGridPos) { NS.views.saveGridPos(); }
    st.view = view; st.viewParam = param === undefined ? null : param;
    A.renderNav();
    var main = st.el.main;
    UI.clear(main);
    main.scrollTop = 0;
    var fn = NS.views[view];
    if (!fn) { main.appendChild(UI.h('div', { className: 'pad' }, 'Unknown view ' + view)); return; }
    try { fn(main, st.viewParam); } catch (e) {
      main.appendChild(UI.h('div', { className: 'pad error' }, 'View failed: ' + e.message));
      C.errorLog('view ' + view + ': ' + (e.stack || e.message));
      if (st.autotest) { st.autotest.errors.push('view ' + view + ': ' + (e.stack || e.message)); }
    }
    A.renderStatus();
  };
  A.globalKeys = function (e) {
    e = e || window.event;
    var k = e.keyCode;
    if (k === 116) { UI.toast('Refresh is disabled to protect loaded state. Close and reopen the HTA to restart.', 'warn'); e.keyCode = 0; return false; }
    if (e.ctrlKey && (k === 187 || k === 107)) { A.zoom(1); return false; }
    if (e.ctrlKey && (k === 189 || k === 109)) { A.zoom(-1); return false; }
    if (e.ctrlKey && (k === 48 || k === 96)) { A.zoom(0); return false; }
    if (e.ctrlKey && k === 70) { if (st.view !== 'grid') { A.nav('grid'); } setTimeout(function () { var q = UI.$('quickfilter'); if (q) { q.focus(); q.select(); } }, 30); return false; }
    if (e.ctrlKey && k === 69) { NS.views.exportDialog(); return false; }
    if (e.ctrlKey && k === 76) { NS.views.loadDialog(); return false; }
    if (e.altKey && k >= 49 && k <= 57) { var n = A.NAV[k - 49]; if (n) { A.nav(n[0]); } return false; }
    return true;
  };

  /* ---------- case ---------- */
  /* Everything derived from the selected evidence site: index, scope, loaded rows, grid and per-view state.
   * st.epoch changes so callbacks of background work started before the switch discard their results. */
  A.resetSiteState = function () {
    st.epoch = (st.epoch || 0) + 1;
    if (st.hashToken) { st.hashToken.cancelled = true; st.hashToken = null; }
    st.hashing = false;
    st.idx = null; st.idxPath = null; st.scope = null; st.store = null; st.loadInfo = null; st.sessions = null; st.sessionsMs = 0;
    st.grid = { model: { conds: [] }, view: null, sortKey: 'ts', sortDesc: false, sel: -1, first: 0, text: '' };
    st.gridCtl = null; st.lpResult = null; st.iocHits = null; st.topnLast = null; st.findFilter = null; st.viewParam = null;
    st.ipCfg = null; st.uriCfg = null; st.tlCfg = null; st.topnCfg = null; st.sesCfg = null;
  };
  /* Everything that belongs to the open case: the evidence selection plus all site state. */
  A.resetCaseState = function () {
    A.resetSiteState();
    st.disc = null; st.site = null; st.siteIdx = 0; st.manifest = null; st.appHost = null; st.lpSql = null;
  };
  A.notBusy = function (what) {
    if (!st.busy) { return true; }
    UI.alert('Busy', 'A scan or load is running. Finish or cancel it before ' + what + '.');
    return false;
  };
  A.openCase = function (caseId) {
    if (st.busy) { throw new Error('A scan or load is running. Finish or cancel it before switching cases.'); }
    if (C.cur && U.trim(caseId || '').toLowerCase() === ('' + C.cur.data.caseId).toLowerCase()) { return C.cur; }
    C.open(caseId, st.settings);
    // Nothing from the previous case (evidence, index, loaded rows, results) may carry over into this one.
    A.resetCaseState();
    A.loadRules();
    A.setZone(NS.tz.forCase(C.cur.data, st.settings));
    A.compileIocs();
    st.columns = C.cur.data.columns || null;
    A.refreshChrome();
    return C.cur;
  };
  A.requireCase = function () {
    if (C.cur) { return true; }
    UI.alert('No case open', 'Open or create a case first (Case & evidence view). Every action is recorded in the case audit log.');
    A.nav('home');
    return false;
  };
  A.compileIocs = function () {
    var p = C.parseIocs(C.cur ? C.cur.data.ioc.text : '');
    st.iocs = p.iocs; st.iocErrors = p.errors;
    st.iocMatcher = p.iocs.length ? C.compileIocs(p.iocs) : null;
  };

  /* ---------- evidence ---------- */
  A.openEvidencePrompt = function (root) {
    if (!C.cur) {
      var guess = '';
      var cn = IO.parseCollectionName(IO.collectionRoot(root));
      var m = /\\Cases\\([^\\]+)\\/i.exec(root);
      guess = m ? m[1] : (cn ? cn.host : 'CASE-' + U.stampForFile().substr(0, 8));
      UI.prompt('Open case', 'Case ID for this evidence (creates or reopens the case workspace under ' + C.wsRoot(st.settings) + '):', guess, function (v) {
        try { A.openCase(v); } catch (e) { UI.alert('Case', e.message); return false; }
        A.openEvidence(root);
        return true;
      });
      return;
    }
    A.openEvidence(root);
  };
  A.openEvidence = function (root, siteIdx) {
    if (!A.requireCase() || !A.notBusy('opening evidence')) { return false; }
    root = U.trim(root || '').replace(/^"|"$/g, '');
    if (C.cur && U.isInside(C.cur.ws, root)) { UI.alert('Workspace inside evidence', 'The case workspace (' + C.cur.ws + ') is inside the evidence folder. Choose a different workspace root in Settings so nothing is ever written under the evidence.'); return false; }
    var disc;
    try { disc = IO.discover(root, 3); } catch (e) { UI.alert('Evidence', e.message); return false; }
    if (!disc.sites.length) { UI.alert('Evidence', 'No .log files found under ' + root + ' (searched 3 folder levels).'); return false; }
    st.disc = disc;
    try { st.manifest = IO.loadManifest(disc.sites[0].path); } catch (e2) { st.manifest = null; UI.toast('Manifest unreadable: ' + e2.message, 'warn'); }
    try { st.appHost = IO.loadAppHostConfig(C.cur.data.appHostConfig || IO.findAppHostConfig(st.manifest ? st.manifest.root : IO.collectionRoot(root))); } catch (e4) { st.appHost = null; UI.toast('applicationHost.config unreadable: ' + e4.message, 'warn'); }
    var cd = C.cur.data;
    var cn = st.manifest ? IO.parseCollectionName(st.manifest.root) : IO.parseCollectionName(IO.collectionRoot(root));
    if (cn) { if (!cd.sourceHost) { cd.sourceHost = cn.host; } if (!cd.collectionUtc) { cd.collectionUtc = cn.time; } }
    if (cd.evidenceRoots.indexOf(root) < 0) { cd.evidenceRoots.push(root); }
    cd.lastRoot = root;
    var rr = st.settings.recentRoots, ri = rr.indexOf(root);
    if (ri >= 0) { rr.splice(ri, 1); } rr.unshift(root); if (rr.length > 10) { rr.length = 10; }
    try { C.saveSettings(st.settings); } catch (e3) { }
    C.save();
    C.audit('evidence.open', { root: root, sites: disc.sites.map(function (s) { return s.name + ' (' + s.files.length + ' files, ' + s.totalBytes + ' bytes)'; }), manifest: st.manifest ? st.manifest.root : null, warnings: disc.warnings });
    var si = siteIdx || 0, k;
    if (siteIdx === undefined && cd.lastSite) { for (k = 0; k < disc.sites.length; k++) { if (disc.sites[k].name === cd.lastSite) { si = k; } } }
    A.selectSite(si);
    return true;
  };
  A.selectSite = function (i) {
    if (!A.notBusy('switching sites')) { return; }
    // Clear the previous site's scope, index path, rows and results before anything else, so a missing
    // or unusable cached index can never leave the old site's file list in effect.
    A.resetSiteState();
    st.siteIdx = i; st.site = st.disc.sites[i];
    C.cur.data.lastSite = st.site.name; C.save();
    A.tryLoadIndex();
    A.refreshChrome();
    A.nav(st.idx ? 'overview' : 'home');
  };
  A.indexPath = function (site, files) {
    return U.joinPath(C.cur.index, U.safeName(site.name) + '-' + S.fingerprint(files) + '.index.json');
  };
  /* Looks for a cached index whose fingerprint covers the full site file list (or the last subset scanned). */
  A.tryLoadIndex = function () {
    var site = st.site, fso = U.fso(), candidates = [], best = null;
    if (!fso.FolderExists(C.cur.index)) { return false; }
    IO.each(fso.GetFolder(C.cur.index).Files, function (f) {
      if (f.Name.toLowerCase().indexOf(U.safeName(site.name).toLowerCase() + '-') === 0 && /\.index\.json$/i.test(f.Name)) { candidates.push({ path: f.Path, mtime: +new Date(f.DateLastModified) }); }
    });
    candidates.sort(function (a, b) { return b.mtime - a.mtime; });
    var full = A.indexPath(site, site.files), i;
    for (i = 0; i < candidates.length; i++) { if (candidates[i].path.toLowerCase() === full.toLowerCase()) { best = candidates[i]; } }
    if (!best && candidates.length) { best = candidates[0]; }
    if (!best) { return false; }
    var t0 = Date.now(), idx;
    try { idx = U.readJsonAscii(best.path); } catch (e) { UI.toast('Cached index unreadable: ' + e.message, 'warn'); return false; }
    if (!idx || idx.schemaVersion !== S.SCHEMA) { UI.toast('Cached index is from an older version; rescan required.', 'warn'); return false; }
    // verify the files it covers still match
    var byName = {}, changed = [];
    for (i = 0; i < site.files.length; i++) { byName[site.files[i].name.toLowerCase()] = site.files[i]; }
    for (i = 0; i < idx.files.length; i++) {
      var f = idx.files[i], cur = byName[f.name.toLowerCase()];
      if (!cur) { changed.push(f.name + ' missing'); continue; }
      if (cur.size !== f.size || cur.mtime !== f.mtime) { changed.push(f.name + ' changed size/time'); }
      f.path = cur.path;
    }
    if (changed.length) {
      UI.alert('Evidence changed since indexing', changed.length + ' file(s) differ from the cached index:\n' + changed.slice(0, 20).join('\n') + '\n\nThe index was NOT loaded. Rescan to rebuild it, and investigate why evidence changed.');
      C.audit('index.mismatch', { path: best.path, changed: changed.slice(0, 200) });
      return false;
    }
    st.idx = idx;
    st.idxPath = best.path;
    A.subsetSite();
    A.applyManifest();
    if ((idx.findingsRulesetHash || idx.rulesetHash) !== st.ruleset.hash) {
      idx.findings = S.buildFindings(idx, st.ruleset, st.settings);
      C.audit('findings.rebuild', { reason: 'rule set or enabled rules differ from the ones that built these findings', indexRules: idx.rulesetHash, currentRules: st.ruleset.hash, n: idx.findings.length });
    }
    var stale = A.rowRulesNeedingRescan(idx);
    if (stale.length) {
      C.audit('index.rulesStale', { enabledSinceScan: stale });
      UI.alert('Rules changed since this scan', 'These row rules are enabled now but were disabled when the index was built, so the index holds no hits for them:\n' + stale.join(', ') + '\n\nRescan to apply them. Findings of rules disabled since the scan are hidden.');
    }
    C.audit('index.load', { path: best.path, ms: Date.now() - t0, files: idx.files.length, rows: idx.totals.rows, partial: idx.partial });
    UI.toast('Loaded cached index (' + U.fmtNum(idx.totals.rows) + ' rows, ' + idx.files.length + ' files) in ' + U.fmtDuration(Date.now() - t0));
    return true;
  };
  /* Row rules enabled now that were disabled when idx was scanned (their hits are not in the index). */
  A.rowRulesNeedingRescan = function (idx) {
    var out = [], i, r, was = idx && idx.rulesDisabled;
    if (!was) { return out; }
    for (i = 0; i < was.length; i++) { r = st.ruleset.byId[was[i]]; if (r && r.enabled && r.scope === 'row') { out.push(r.id); } }
    return out;
  };
  /* st.scope = site restricted to the files covered by the current index */
  A.subsetSite = function () {
    var names = {}, i, files = [];
    for (i = 0; i < st.idx.files.length; i++) { names[st.idx.files[i].name.toLowerCase()] = 1; }
    for (i = 0; i < st.site.files.length; i++) { if (names[st.site.files[i].name.toLowerCase()]) { files.push(st.site.files[i]); } }
    st.scope = U.extend({}, st.site, { files: files });
  };
  A.saveIndex = function () {
    if (!st.idx || !C.cur) { return; }
    var t0 = Date.now();
    try {
      st.idxPath = A.indexPath(st.site, st.scope.files);
      var bytes = U.writeJsonAscii(st.idxPath, st.idx);
      C.audit('index.save', { path: st.idxPath, bytes: bytes, ms: Date.now() - t0 });
    } catch (e) { UI.toast('Index save failed: ' + e.message, 'error'); }
  };

  /* ---------- manifest / hashes ---------- */
  A.applyManifest = function () {
    var idx = st.idx, man = st.manifest, i, f, e;
    if (!idx) { return; }
    for (i = 0; i < idx.files.length; i++) {
      f = idx.files[i];
      if (!man) { f.manifest = null; continue; }
      e = IO.manifestLookup(man, f);
      if (!e) { f.manifest = { status: 'not-in-manifest', detail: 'No collector record for ' + f.displayPath }; continue; }
      var issues = [];
      if (e.fileSize !== undefined && e.fileSize !== f.size) { issues.push('size on disk ' + f.size + ' vs collected ' + e.fileSize); }
      if (e.uploadedSize !== undefined && e.fileSize !== undefined && e.uploadedSize < e.fileSize) { issues.push('upload truncated (' + e.uploadedSize + ' of ' + e.fileSize + ' bytes)'); }
      if (e.sha256 && f.sha256 && e.sha256 !== f.sha256) { issues.push('SHA-256 differs from collector record ' + e.sha256); }
      var note = (e.recordedSize !== undefined && e.recordedSize !== f.size) ? 'collector metadata Size ' + e.recordedSize + ' (file was still being written at collection time)' : '';
      f.manifest = { status: issues.length ? 'mismatch' : (e.sha256 && f.sha256 ? 'match' : (e.sha256 ? 'match-size (hash pending)' : 'match')), detail: issues.concat(note ? [note] : []).join('; '), sha256: e.sha256 || '' };
    }
  };
  A.hashFiles = function (cb, quiet) {
    if (!st.idx) { if (cb) { cb(); } return; }
    var paths = [], i, files = st.idx.files, token = { cancelled: false }, epoch = st.epoch, idx0 = st.idx;
    for (i = 0; i < files.length; i++) { paths.push(files[i].path); }
    st.hashing = true; st.hashToken = token;
    var prog = quiet ? null : UI.progress('Hashing ' + paths.length + ' evidence files (SHA-256, PowerShell Get-FileHash, hidden)', function () { token.cancelled = true; });
    C.audit('hash.start', { files: paths.length });
    IO.hashFiles(paths, C.cur.tmp, function (err, map, fails) {
      if (prog) { prog.close(); }
      // The case or site changed while hashing ran in the background: never apply these results to the new selection.
      if (st.epoch !== epoch || st.idx !== idx0) { UI.toast('Hash results discarded: the case or evidence selection changed while hashing.', 'warn'); return; }
      st.hashing = false; st.hashToken = null;
      if (err) { UI.toast('Hashing failed: ' + err.message, 'error'); C.audit('hash.error', { error: err.message }); if (cb) { cb(err); } return; }
      var changed = [];
      for (i = 0; i < files.length; i++) {
        var h = map[files[i].path.toLowerCase()];
        if (!h) { continue; }
        if (files[i].sha256 && files[i].sha256 !== h) { changed.push(files[i].name); files[i].sha256Prev = files[i].sha256; }
        files[i].sha256 = h;
      }
      st.idx.hashes = { done: true, tool: 'PowerShell Get-FileHash SHA256', when: U.nowIso(), failures: fails.length, changed: changed };
      A.applyManifest();
      A.saveIndex();
      C.audit('hash.done', { files: U.countKeys(map), failures: fails, changedSinceLastHash: changed });
      if (changed.length) { UI.alert('INTEGRITY WARNING', changed.length + ' file(s) have a different SHA-256 than when last hashed:\n' + changed.join('\n')); }
      if (!quiet) { UI.toast('Hashed ' + U.countKeys(map) + ' files' + (fails.length ? ', ' + fails.length + ' failed' : '')); }
      if (st.view === 'integrity' || st.view === 'overview') { A.nav(st.view); }
      if (cb) { cb(null); }
    }, function (n, tot) { if (prog) { prog.update({ file: n, files: tot, current: 'hashed ' + n + ' of ' + tot }); } }, token);
  };

  /* ---------- scan ---------- */
  A.scan = function (fileIds, opts, cb) {
    if (!A.requireCase() || !st.site) { return; }
    opts = opts || {};
    var files = [], i;
    for (i = 0; i < fileIds.length; i++) { files.push(st.site.files[fileIds[i]]); }
    var scope = U.extend({}, st.site, { files: files, totalBytes: files.reduce(function (a, f) { return a + f.size; }, 0) });
    var token = { cancelled: false }, resume = null;
    st.scanToken = token;
    if (opts.resume && st.idx && st.idx.partial) {
      // A resume must continue with the rules and business hours the scan started with, or the result would mix two configurations.
      if (st.idx.rulesetHash !== st.ruleset.hash || JSON.stringify(st.idx.settingsUsed.businessHours) !== JSON.stringify(st.settings.businessHours)) {
        UI.alert('Cannot continue this scan', 'The rules, enabled rules or business hours changed since this scan was cancelled. Rescan from the start so every finding comes from one configuration.');
        return;
      }
      if (!st.idx.resumeState) { UI.alert('Cannot continue this scan', 'This partial index has no saved detection state (it was made by an older version). Rescan from the start.'); return; }
      resume = st.idx; scope = st.scope;
    }
    // Engine: 'fast' = compiled C# out of process (engine\Scan-IISLogs.ps1); 'builtin' = JavaScript in this window. Resume always uses the built-in engine.
    var engine = resume ? 'builtin' : (opts.engine || st.settings.scanEngine || (NS.engine.available() ? 'fast' : 'builtin'));
    if (engine === 'fast' && !NS.engine.available()) { engine = 'builtin'; UI.toast('Fast engine unavailable (PowerShell or engine files missing); using the built-in engine.', 'warn'); }
    st.busy = true; A.renderStatus();
    var prog = UI.progress((resume ? 'Resuming scan of ' : 'Scanning ') + scope.files.length + ' files (' + U.fmtBytes(scope.totalBytes) + ') \u2014 ' + (engine === 'fast' ? 'fast engine' : 'built-in engine'), function () { token.cancelled = true; });
    C.audit('scan.start', { site: st.site.name, files: scope.files.length, bytes: scope.totalBytes, first: scope.files[0] && scope.files[0].name, last: scope.files.length && scope.files[scope.files.length - 1].name, resume: !!resume, rules: st.ruleset.hash, rulesDisabled: st.ruleset.disabledIds, engine: engine, tz: St.tz && St.tz.id });
    st.scope = scope; st.store = null; st.grid.view = null; st.sessions = null;
    if (opts.hash && !resume) { setTimeout(function () { A.hashFiles(null, true); }, 50); }
    var finished = function (err, idx, cancelled) {
      prog.close(); st.busy = false;
      if (err && engine === 'fast' && !opts.noFallback) {
        C.audit('scan.error', { error: err.message, engine: engine });
        UI.confirm('Fast engine failed', err.message + '\n\nRun the scan with the built-in engine instead?', function () { A.scan(fileIds, U.extend({}, opts, { engine: 'builtin' }), cb); }, 'Use built-in engine');
        A.refreshChrome(); return;
      }
      if (err) { UI.alert('Scan failed', err.message + '\n' + (err.stack || '')); C.audit('scan.error', { error: err.message }); A.refreshChrome(); if (cb) { cb(err); } return; }
      st.idx = idx;
      A.applyManifest();
      A.saveIndex();
      C.audit(cancelled ? 'scan.cancelled' : 'scan.done', { rows: idx.totals.rows, lines: idx.totals.lines, malformed: idx.totals.malformed, filesDone: idx.filesDone, findings: idx.findings.length, ms: idx.scanMs });
      A.refreshChrome();
      UI.toast((cancelled ? 'Scan cancelled at file ' + idx.filesDone + '. Partial results kept; use Continue scan to resume. ' : 'Scan complete: ') + U.fmtNum(idx.totals.rows) + ' rows, ' + idx.findings.length + ' findings in ' + U.fmtDuration(idx.scanMs), cancelled ? 'warn' : 'info');
      if (!st.autotest) { A.nav('overview'); }
      if (cb) { cb(null, idx); }
    };
    if (engine === 'fast') {
      var skeleton = S.newIndex(scope, scope.files, st.settings, st.ruleset);
      st.idx = skeleton;
      try {
        NS.engine.run({ files: scope.files, settings: st.settings, ruleset: st.ruleset, lists: st.lists, zone: St.tz }, C.cur.tmp, function (p) { prog.update(p); }, function (err, out, cancelled) {
          if (err) { finished(err); return; }
          try { NS.engine.merge(skeleton, out, st.ruleset, st.settings); } catch (e) { finished(e); return; }
          finished(null, skeleton, cancelled);
        }, token);
      } catch (e) { finished(e); }
      return;
    }
    var sc = new S.Scanner({ site: scope, settings: st.settings, ruleset: st.ruleset, lists: st.lists, manifest: st.manifest, resumeIndex: resume, tz: St.tz, onProgress: function (p) { prog.update(p); } });
    st.idx = sc.idx;
    sc.run(finished, token);
  };

  /* ---------- load ---------- */
  /* opts: { fileIds, from, to, preText, preModel, keepRaw, maxRows, label } */
  A.load = function (opts, cb) {
    if (!A.requireCase() || !st.site) { return; }
    var site = st.scope || st.site, pre = null, model = opts.preModel || null;
    try { if (!model && opts.preText) { model = F.parse(opts.preText, St.tz); } pre = F.compile(model, A.filterEnv()); } catch (e) { UI.alert('Pre-filter', e.message); return; }
    var token = { cancelled: false }, bytes = 0, i;
    for (i = 0; i < opts.fileIds.length; i++) { bytes += site.files[opts.fileIds[i]].size; }
    st.busy = true; A.renderStatus();
    var prog = UI.progress('Loading rows from ' + opts.fileIds.length + ' file(s) (' + U.fmtBytes(bytes) + ')', function () { token.cancelled = true; });
    C.audit('load', { label: opts.label || '', files: opts.fileIds.length, bytes: bytes, from: opts.from ? U.fmtIso(opts.from) : null, to: opts.to ? U.fmtIso(opts.to) : null, prefilter: F.toText(model), keepRaw: opts.keepRaw, maxRows: opts.maxRows || st.settings.maxRows });
    st.store = null; st.grid.view = null; st.sessions = null;
    St.load({ site: site, fileIds: opts.fileIds, from: opts.from, to: opts.to, prefilter: pre, settings: st.settings, ruleset: st.ruleset, lists: st.lists, index: st.idx,
      maxRows: opts.maxRows || st.settings.maxRows, keepRaw: opts.keepRaw === undefined ? st.settings.keepRaw : opts.keepRaw, token: token,
      onProgress: function (p) { p.msg = '  \u00b7  scanned ' + U.fmtNum(p.scanned); prog.update(p); } }, function (err, store) {
      prog.close(); st.busy = false;
      if (err) { UI.alert('Load failed', err.message); C.audit('load.error', { error: err.message }); A.refreshChrome(); if (cb) { cb(err); } return; }
      st.store = store; st.loadInfo = { label: opts.label || '', pre: F.toText(model), from: opts.from, to: opts.to, files: opts.fileIds.length, failed: store.failed.length };
      st.grid = { model: { conds: [] }, view: null, sortKey: 'ts', sortDesc: false, sel: -1, first: 0, text: '' };
      A.applyGrid();
      C.audit('load.done', { rows: store.n, scanned: store.scanned, ms: store.loadMs, capped: store.capped, cancelled: store.cancelled, incomplete: store.incomplete, failedFiles: store.failed });
      if (store.failed.length) {
        UI.alert('Load incomplete', store.failed.length + ' of ' + opts.fileIds.length + ' file(s) could not be read, so their rows are NOT in the grid or in any export of this load:' + String.fromCharCode(10, 10) +
          store.failed.slice(0, 20).map(function (f) { return f.name + ': ' + f.error; }).join(String.fromCharCode(10)) + (store.failed.length > 20 ? String.fromCharCode(10) + '...' : '') + String.fromCharCode(10, 10) +
          'The omission is recorded in the audit log and in the metadata of every export made from this load.');
      }
      if (store.capped) { UI.alert('Row cap reached', 'Loading stopped at ' + U.fmtNum(store.n) + ' rows (cap ' + U.fmtNum(store.max) + '). Narrow the date range, file set or pre-filter. Nothing was sampled: rows after the cap were not loaded.'); }
      UI.toast('Loaded ' + U.fmtNum(store.n) + ' rows (scanned ' + U.fmtNum(store.scanned) + ') in ' + U.fmtDuration(store.loadMs) + (store.cancelled ? ' - CANCELLED, partial' : ''));
      A.refreshChrome();
      if (!st.autotest) { A.nav('grid'); }
      if (cb) { cb(null, store); }
    });
  };
  A.allFileIds = function () { var out = [], i, n = (st.scope || st.site).files.length; for (i = 0; i < n; i++) { out.push(i); } return out; };
  /* Load rows for a list of [fileId, line] pointers (fileIds refer to the index file list). */
  A.loadPointers = function (ptrs, label) {
    var files = {}, list = [], keys = [], i;
    for (i = 0; i < ptrs.length; i++) { files[ptrs[i][0]] = 1; keys.push(ptrs[i][0] + ':' + ptrs[i][1]); }
    for (var k in files) { list.push(+k); }
    list.sort(function (a, b) { return a - b; });
    A.load({ fileIds: list, preModel: { conds: [{ f: 'ptr', op: 'in', v: keys, text: 'rows:' + ptrs.length + ' pointers' }] }, label: label });
  };
  A.loadWhere = function (text, label, fileIds) {
    A.load({ fileIds: fileIds || A.allFileIds(), preText: text, label: label || text });
  };
  /* File ids whose filename date / time range overlaps [from,to] */
  A.fileIdsForRange = function (from, to) {
    var out = [], i, files = (st.scope || st.site).files, idxf = st.idx ? st.idx.files : null;
    for (i = 0; i < files.length; i++) {
      var f0 = null, f1 = null;
      if (idxf && idxf[i] && idxf[i].minTs) { f0 = idxf[i].minTs; f1 = idxf[i].maxTs; } else if (files[i].nameDate && files[i].nameKind === 'daily') { f0 = U.dayKeyToMs(files[i].nameDate) - 14 * 3600000; f1 = f0 + 52 * 3600000; }
      if (f0 === null || ((to === null || to === undefined || f0 <= to) && (from === null || from === undefined || f1 >= from))) { out.push(i); }
    }
    return out;
  };

  /* ---------- grid filter ---------- */
  A.filterEnv = function () {
    return {
      tz: St.tz, index: st.idx, ruleSev: st.ruleSev,
      fileName: function (id) { var f = (st.scope || st.site).files[id]; return f ? f.name : ''; },
      tagsOf: A.tagsOfAccessor,
      iocTest: function (Ax) { return st.iocMatcher ? !!st.iocMatcher.test(Ax) : false; }
    };
  };
  A.applyGrid = function () {
    var g = st.grid, store = st.store;
    if (!store) { return; }
    var t0 = Date.now(), pred = F.compile(g.model, A.filterEnv());
    var v = F.apply(store, pred);
    if (g.sortKey !== 'ts' || g.sortDesc) { v = St.sortView(store, v, g.sortKey, g.sortDesc); }
    g.view = v; g.sel = -1; g.first = 0; g.ms = Date.now() - t0;
    st.sessions = null;
  };
  A.setGridFilterText = function (text) {
    var model;
    try { model = F.parse(text, St.tz); } catch (e) { UI.toast(e.message, 'error'); return false; }
    st.grid.model = model; st.grid.text = text;
    if (st.store && st.store.n > 500000 && model.conds.some(function (c) { return c.f === 'text'; })) { UI.toast('Raw-text search over ' + U.fmtNum(st.store.n) + ' rows is the slowest filter; prefer field filters.', 'warn'); }
    A.applyGrid();
    C.audit('grid.filter', { filter: F.toText(model), rows: st.grid.view.length });
    return true;
  };
  A.addGridCond = function (cond) {
    var g = st.grid;
    g.model.conds.push(cond);
    g.text = F.toText(g.model);
    A.applyGrid();
    C.audit('grid.filter', { filter: g.text, rows: g.view.length });
  };
  /* Pivot from anywhere: if rows are loaded, filter the grid; otherwise load from the index scope. */
  A.pivot = function (q, label) {
    if (st.store) {
      if (A.setGridFilterText((st.grid.text ? st.grid.text + ' ' : '') + q)) { A.nav('grid'); }
    } else if (st.site) {
      UI.confirm('Load rows', 'No rows are loaded. Stream all ' + (st.scope || st.site).files.length + ' files and load rows matching:\n\n' + q, function () { A.loadWhere(q, label); }, 'Load');
    }
  };
  A.sortGrid = function (key) {
    var g = st.grid;
    if (g.sortKey === key) { g.sortDesc = !g.sortDesc; } else { g.sortKey = key; g.sortDesc = key === 'taken' || key === 'scb'; }
    var t0 = Date.now();
    g.view = St.sortView(st.store, g.view, g.sortKey, g.sortDesc);
    g.sel = -1; g.first = 0;
    UI.toast('Sorted ' + U.fmtNum(g.view.length) + ' rows in ' + U.fmtDuration(Date.now() - t0));
  };

  /* ---------- tags ---------- */
  A.rowKey = function (fileId, line) {
    var f = (st.scope || st.site).files[fileId];
    return C.rowKey(st.site.name, f ? f.name : '#' + fileId, line);
  };
  A.tagText = function (store, i) {
    if (!C.cur) { return ''; }
    var t = C.cur.data.tags, out = [], k, j, add = function (list) { if (list) { for (j = 0; j < list.length; j++) { if (out.indexOf(list[j]) < 0) { out.push(list[j]); } } } };
    k = C.rowKey(st.site ? st.site.name : '', store.files[store.file[i]].name, store.line[i]);
    add(t.rows[k]);
    add(t.ips[store.t.ip.vals[store.eip[i]]]);
    var si = store.stemInfo[store.stem[i]]; if (si) { add(t.stems[si.key]); }
    return out.join(', ');
  };
  A.tagsOfAccessor = function (Ax) {
    if (!C.cur) { return []; }
    var t = C.cur.data.tags, out = [], j, add = function (list) { if (list) { for (j = 0; j < list.length; j++) { if (out.indexOf(list[j]) < 0) { out.push(list[j]); } } } };
    var fname = Ax.store ? Ax.store.files[Ax.fileId()].name : ((st.scope || st.site).files[Ax.fileId()] || {}).name;
    add(t.rows[C.rowKey(st.site ? st.site.name : '', fname, Ax.line())]);
    add(t.ips[Ax.eip()]);
    add(t.stems[Ax.si().key]);
    return out;
  };

  /* ---------- raw context ---------- */
  A.rawContext = function (fileId, line, files) {
    var f = (files || (st.scope || st.site).files)[fileId];
    if (!f) { return; }
    var from = Math.max(1, line - 50), to = line + 50;
    UI.toast('Reading ' + f.name + ' lines ' + from + '-' + to + '\u2026');
    IO.readLineRange(f.path, from, to, function (err, lines) {
      if (err) { UI.alert('Raw context', err.message); return; }
      var pre = UI.h('div', { className: 'rawctx' }), i, target = null;
      for (i = 0; i < lines.length; i++) {
        var lt = /[^\u0000-\u007f]/.test(lines[i].t) ? U.fixUtf8(lines[i].t) : lines[i].t;
        var el = UI.h('div', { className: 'rl' + (lines[i].n === line ? ' hl' : '') + (lines[i].t.charAt(0) === '#' ? ' dir' : '') }, [UI.h('span', { className: 'ln' }, '' + lines[i].n), lt]);
        if (lines[i].n === line) { target = el; }
        pre.appendChild(el);
      }
      UI.dialog({ title: f.name + ' \u2014 lines ' + from + '\u2013' + (from + lines.length - 1) + ' (read directly from evidence)', body: [UI.h('div', { className: 'muted mb' }, f.path), pre], width: 1100, height: 520,
        buttons: [{ label: 'Copy lines', onClick: function () { UI.copy(lines.map(function (l) { return l.t; }).join('\r\n')); return false; } }, { label: 'Close', primary: true }] });
      if (target) { setTimeout(function () { target.scrollIntoView(); }, 50); }
      C.audit('raw.context', { file: f.name, line: line });
    });
  };

  /* ---------- report ---------- */
  A.report = function (quiet) {
    if (!A.requireCase()) { return; }
    if (!st.idx) { UI.alert('Report', 'Scan the evidence first; the report is built from the index and findings.'); return; }
    try {
      var r = X.report({ tz: St.tz, caseData: C.cur.data, idx: st.idx, site: st.site, disc: st.disc, manifest: st.manifest, ruleset: st.ruleset, settings: st.settings, auditEntries: C.readAudit() });
      if (quiet) { return r; }
      UI.dialog({ title: 'Report generated', body: UI.kv([['File', r.path], ['SHA-256', r.sha256, 'mono'], ['Size', U.fmtBytes(r.bytes)]]),
        buttons: [{ label: 'Open report', primary: true, onClick: function () { try { U.shell().Run('"' + r.path + '"', 1, false); } catch (e) { UI.toast(e.message, 'error'); } } }, { label: 'Show in folder', onClick: function () { X.openFolder(r.path); } }, { label: 'Close' }] });
      return r;
    } catch (e) { UI.alert('Report failed', e.message + '\n' + (e.stack || '')); }
  };

  /* ---------- autotest ---------- */
  /* Headless self-test: open case, scan (and optionally load) the selected files, render every view,
   * write a JSON result file, then close. Used for acceptance testing inside the real mshta engine. */
  A.autotest = function (args) {
    var res = st.autotest = { started: U.nowIso(), args: args, errors: [], steps: [], documentMode: document.documentMode, bits: st.bits };
    if (args.testnets) { st.demoTestNets = true; A.applyNetworkLists(); } // demo data: documentation ranges count as public (not saved)
    var out = args.out || U.joinPath(U.env('TEMP'), 'iisla-autotest.json');
    /* /shots: show each view for a few seconds so an external capture script can photograph the window. */
    function shots(cb) {
      var topIp = '', fi; // the client of the most severe client finding
      for (fi = 0; st.idx && fi < st.idx.findings.length && !topIp; fi++) { if (st.idx.findings[fi].entity === 'ip') { topIp = st.idx.findings[fi].key; } }
      var seq = [['overview'], ['findings'], ['grid'], ['ipProfile', args.shotip || topIp || '203.0.113.45'], ['topn'], ['timeline'], ['uris'], ['sessions'], ['integrity'], ['logparser'], ['home'], ['help']], k = 0;
      function next() {
        if (k >= seq.length) { cb(); return; }
        var s = seq[k++];
        if (s[0] === 'grid' && st.store) { A.setGridFilterText('class:public method:POST'); }
        A.nav(s[0], s[1]);
        NS.trace('shot ' + s[0]);
        setTimeout(function () {
          // Static, script-free DOM snapshot for visual review in another browser.
          try {
            var dir = U.joinPath(U.joinPath(IO.appFolder(), 'test'), 'snapshots'), css = 'file:///' + IO.appFolder().replace(/\\/g, '/') + '/lib/app.css';
            U.ensureFolder(dir);
            var sc = UI.$('appcss-scaled'), cssText = (sc && sc.textContent) || IO.resource('lib/app.css') || '';
            // typed values are properties, not attributes: copy them so the static snapshot shows them
            var ins = document.getElementsByTagName('input'), ii;
            for (ii = 0; ii < ins.length; ii++) { if (ins[ii].type === 'checkbox') { if (ins[ii].checked) { ins[ii].setAttribute('checked', 'checked'); } } else if (ins[ii].value) { ins[ii].setAttribute('value', ins[ii].value); } }
            var html = '<!DOCTYPE html>\n' + document.documentElement.outerHTML.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<link[^>]*app\.css[^>]*>/i, function () { return '<style>' + cssText + '</style>'; });
            css = null;
            U.writeTextUtf8(U.joinPath(dir, (k < 10 ? '0' : '') + k + '-' + s[0] + '.html'), html, false);
          } catch (e) { res.errors.push('snapshot ' + s[0] + ': ' + e.message); }
          next();
        }, +args.shotMs || 1500);
      }
      next();
    }
    function step(name, data) { NS.trace('step ' + name); res.steps.push({ t: U.nowIso(), name: name, data: data || null }); }
    var finished = false;
    function finish() {
      if (args.shots && !finished) { finished = true; shots(finish); return; }
      res.finished = U.nowIso();
      try { U.writeTextUtf8(out, JSON.stringify(res, null, 1), false); } catch (e) { }
      if (!args.stay) { setTimeout(function () { window.close(); }, 300); }
    }
    try {
      A.nav('home');
      A.openCase(args.caseId || 'AUTOTEST'); if (args.streamMB > 0) { IO.streamOverrideMB = args.streamMB; } // self-test only: never saved to settings
      if (args.tz) { C.cur.data.displayTzId = args.tz; C.save(); A.setZone(NS.tz.forCase(C.cur.data, st.settings)); } // self-test: case display zone
      step('case', { ws: C.cur.ws });
      var tOpen = Date.now();
      if (!A.openEvidence(args.root)) { res.errors.push('openEvidence failed'); finish(); return; }
      step('openEvidence', { ms: Date.now() - tOpen, cachedIndex: !!st.idx, indexPath: st.idxPath || null, rows: st.idx ? st.idx.totals.rows : 0 });
      step('discover', { sites: st.disc.sites.length, files: st.site.files.length, bytes: st.site.totalBytes, manifest: st.manifest ? st.manifest.sources : null });
      var ids = [], re = args.files ? new RegExp(args.files, 'i') : null, i;
      for (i = 0; i < st.site.files.length; i++) { if (!re || re.test(st.site.files[i].name)) { ids.push(i); } }
      var t0 = Date.now();
      // /noscan: reuse the cached index found by openEvidence (measures reload instead of scanning)
      // /cancelafter:ms cancels the scan once, then resumes it (tests mid-file resume without double counting)
      var resumed = false;
      if (args.cancelAfter) { setTimeout(function () { if (st.scanToken) { st.scanToken.cancelled = true; } }, +args.cancelAfter); }
      (args.noscan && st.idx ? function (a1, a2, cb) { cb(null, st.idx); } : A.scan)(ids, { hash: false, engine: args.engine || 'builtin', noFallback: true }, function onScanned(err, idx) {
        if (err) { res.errors.push('scan: ' + err.message); finish(); return; }
        if (idx.partial && args.cancelAfter && !resumed) {
          resumed = true;
          step('scan.cancelled', { filesDone: idx.filesDone, partialFile: idx.partialFile, partialLine: idx.partialLine, rows: idx.totals.rows });
          A.scan([], { resume: true }, onScanned);
          return;
        }
        var t = idx.totals;
        step('scan', { ms: Date.now() - t0, files: idx.files.length, rows: t.rows, lines: t.lines, malformed: t.malformed, blocks: t.blocks, restarts: idx.restarts.length,
          methods: idx.methods, statuses: idx.statuses, sports: idx.sports, uas: U.countKeys(idx.uas), ips: U.countKeys(idx.ips), stems: U.countKeys(idx.stems),
          heartbeat: idx.heartbeat, ruleHits: (function () { var o = {}; for (var k in idx.ruleHits) { o[k] = idx.ruleHits[k].n; } return o; }()),
          findings: idx.findings.map(function (f) { return f.id + ' ' + f.severity + ' ' + f.ruleId + ' ' + f.entity + ':' + f.key; }).slice(0, 400),
          rowsPerSec: Math.round(t.rows / Math.max(1, idx.scanMs) * 1000), indexPath: st.idxPath, engine: idx.engine || 'builtin' });
        var hashed = false;
        var after = function () {
          if (args.hash && !hashed) {
            hashed = true;
            var th = Date.now();
            A.hashFiles(function (herr) {
              var ms = {}, i2; for (i2 = 0; i2 < st.idx.files.length; i2++) { var mf = st.idx.files[i2].manifest, k2 = mf ? mf.status : 'none'; ms[k2] = (ms[k2] || 0) + 1; }
              step('hash', { ms: Date.now() - th, error: herr ? herr.message : null, hashed: st.idx.files.filter(function (f) { return f.sha256; }).length, manifest: ms,
                mismatches: st.idx.files.filter(function (f) { return f.manifest && f.manifest.status === 'mismatch'; }).map(function (f) { return f.name + ': ' + f.manifest.detail; }).slice(0, 20) });
              after();
            }, true);
            return;
          }
          var views = ['overview', 'findings', 'topn', 'timeline', 'ips', 'uris', 'integrity', 'iocs', 'logparser', 'tags', 'settings', 'help', 'home'];
          if (st.store) { views.splice(2, 0, 'grid', 'sessions'); }
          var v;
          for (v = 0; v < views.length; v++) { var tv = Date.now(); A.nav(views[v]); step('view.' + views[v], { ms: Date.now() - tv, nodes: st.el.main.getElementsByTagName('*').length }); }
          // dialogs: open and close each one to catch rendering errors
          var dlgs = [['scan', NS.views.scanDialog], ['load', NS.views.loadDialog], ['export', NS.views.exportDialog]], di;
          for (di = 0; di < dlgs.length; di++) {
            try { dlgs[di][1](); var ovs = document.querySelectorAll('.overlay'), oi; step('dialog.' + dlgs[di][0], { opened: ovs.length }); for (oi = ovs.length - 1; oi >= 0; oi--) { ovs[oi].parentNode.removeChild(ovs[oi]); } } catch (de) { res.errors.push('dialog ' + dlgs[di][0] + ': ' + de.message); }
          }
          try { var tzs = NS.views.tzSelect('Pacific Standard Time'), z = tzs.get(); step('tz.select', { id: z.id, label: z.label, offNow: z.off(Date.now()), offJan: z.off(Date.UTC(2026, 0, 15)), offJul: z.off(Date.UTC(2026, 6, 15)) }); } catch (te) { res.errors.push('tzSelect: ' + te.message); }
          // XSS canary: render a hostile string through every text path
          var canary = '<img src=x onerror=alert(1)>"><scr' + 'ipt>alert(2)</scr' + 'ipt>';
          var probe = UI.h('div', null, canary);
          step('xss.probe', { rendered: probe.textContent === canary, childElements: probe.getElementsByTagName('*').length });
          try { var rp = A.report(true); step('report', rp); } catch (e) { res.errors.push('report: ' + e.message); }
          if (st.store) {
            var tq = Date.now(); A.setGridFilterText(args.filterq || 'class:public'); step('filter.ip', { rows: st.grid.view.length, ms: Date.now() - tq });
            tq = Date.now(); A.sortGrid('taken'); step('sort.taken', { ms: Date.now() - tq, top: st.store.taken[st.grid.view[0]] });
            tq = Date.now(); var ss = St.sessions(st.store, st.grid.view, 30); step('sessions', { n: ss.length, ms: Date.now() - tq });
            var doExport = function () {
              var p2 = X.outPath('autotest-tle', 'csv');
              X.rows(st.store, st.grid.view, null, 'tle', p2, St.tz, null, function (err2, info) {
                if (err2) { res.errors.push('export: ' + err2.message); } else { step('export.tle', info); }
                finish();
              });
            };
            if (args.lpstub) {
              st.settings.logParserPath = args.lpstub;
              NS.views.runLogParser(NS.logparser.TEMPLATES[0].sql, -1, function (e3) {
                step('logparser', { error: e3 ? e3.message : null, rows: st.lpResult ? st.lpResult.rows.length : 0, header: st.lpResult ? st.lpResult.header : null, firstRow: st.lpResult ? st.lpResult.rows[0] : null });
                doExport();
              });
            } else { doExport(); }
            return;
          }
          finish();
        };
        if (args.load) {
          var tl = Date.now();
          A.load({ fileIds: A.allFileIds(), label: 'autotest' }, function (err3, store) {
            if (err3) { res.errors.push('load: ' + err3.message); finish(); return; }
            step('load', { rows: store.n, ms: Date.now() - tl, capped: store.capped, estBytes: store.bytesEstimate(), failed: store.failed, streamedAboveMB: IO.streamOverrideMB || st.settings.streamAboveMB || IO.STREAM_ABOVE_MB, fsoStreamOk: IO.fsoStreamOk() });
            if (args.rawbundle) {
              try { var all = [], q; for (q = 0; q < store.n; q++) { all.push(q); } step('rawbundle', X.rawBundle(store, all, X.outPath('autotest-raw', 'txt'))); } catch (eR) { res.errors.push('rawbundle: ' + eR.message); }
            }
            after();
          });
        } else { after(); }
      });
    } catch (e) { res.errors.push('autotest: ' + (e.stack || e.message)); finish(); }
  };
}(IISLA));
