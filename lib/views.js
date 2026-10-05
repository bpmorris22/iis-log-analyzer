/* IIS Log Analyzer - views.js
 * All views and dialogs. Evidence text reaches the DOM only via UI.h / textContent.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io, R = NS.rules, S = NS.scan, St = NS.store, F = NS.filter, C = NS.caseMgr, UI = NS.ui, X = NS.exporter, A = NS.app;
  var V = NS.views = {}, h = UI.h, st = A.state;

  function page(main, title, tools, sub) {
    var hd = h('div', { className: 'page-h' }, [h('h1', null, title), sub ? h('span', { className: 'page-sub' }, sub) : null, tools ? h('span', { className: 'page-tools' }, tools) : null]);
    main.appendChild(hd);
    var body = h('div', { className: 'page-b' });
    main.appendChild(body);
    return body;
  }
  function needIndex(main, title) {
    var b = page(main, title);
    if (!C.cur) { b.appendChild(h('p', null, ['Open a case and an evidence folder first. ', UI.link('Go to Case & evidence', function () { A.nav('home'); })])); return null; }
    if (!st.site) { b.appendChild(h('p', null, ['No evidence opened. ', UI.link('Open evidence', function () { A.nav('home'); })])); return null; }
    b.appendChild(h('p', null, ['This view needs the index. ', UI.btn('Scan\u2026', function () { V.scanDialog(); }, 'primary')]));
    return null;
  }
  function needRows(main, title) {
    var b = page(main, title);
    b.appendChild(h('p', null, ['No rows are loaded. ', UI.btn('Load rows\u2026', function () { V.loadDialog(); }, 'primary')]));
    return b;
  }
  function tsCell(ms) { return ms ? U.fmtTs(ms) : ''; }
  function tzLabel() { return St.tz && St.tz.label ? St.tz.label : U.fmtOffset(U.tzOff(St.tz, Date.now())); }
  function ipLink(ip) { return UI.link(ip, function () { A.nav('ipProfile', ip); }, 'Open IP profile'); }
  function stemLink(key, label) { return UI.link(label || key, function () { A.nav('uriProfile', key); }, 'Open URI profile'); }
  V.ipLink = ipLink; V.stemLink = stemLink;
  function topList(map, n) { return U.sortedKeys(map, function (v) { return v; }, n); }
  function tagChips(kind, key, onChange) {
    var wrap = h('span', { className: 'tags' }), defs = C.cur ? C.cur.data.tagDefs : [], i;
    for (i = 0; i < defs.length; i++) {
      (function (d) {
        var on = C.getTags(kind, key).indexOf(d.name) >= 0;
        var chip = h('span', { className: 'chip' + (on ? ' on' : ''), style: on ? { background: d.color, borderColor: d.color } : { borderColor: d.color }, title: (on ? 'Remove' : 'Add') + ' tag ' + d.name,
          onclick: function () { C.setTag(kind, key, d.name, !on); C.save(); C.audit('tag', { kind: kind, key: key, tag: d.name, on: !on }); if (onChange) { onChange(); } } }, d.name);
        wrap.appendChild(chip);
      }(defs[i]));
    }
    return wrap;
  }
  V.tagChips = tagChips;
  function notesBox(type, key) {
    var box = h('div', { className: 'notes' }), list = C.notesFor(type, key), i;
    for (i = 0; i < list.length; i++) { box.appendChild(h('div', { className: 'note' }, [h('span', { className: 'muted' }, list[i].ts + ' ' + (list[i].examiner || '') + ': '), list[i].text])); }
    box.appendChild(UI.link('+ add note', function () { UI.prompt('Note', 'Note for ' + type + ' ' + key, '', function (v) { if (v) { C.addNote(type, key, v); A.nav(st.view, st.viewParam); } }, true); }));
    return box;
  }

  /* ======================= HOME ======================= */
  V.home = function (main) {
    var b = page(main, 'Case & evidence', null, 'All analysis is read-only against the evidence; outputs go to the case workspace.');
    // --- case ---
    var cases = C.listCases(st.settings), caseIn = UI.input(C.cur ? C.cur.data.caseId : '', { style: { width: '220px' }, placeholder: 'e.g. 2026-10-CASE-001' });
    var openCase = function () { try { A.openCase(caseIn.value); A.nav('home'); } catch (e) { UI.alert('Case', e.message); } };
    caseIn.onkeydown = function (e) { if ((e || window.event).keyCode === 13) { openCase(); } };
    var caseBox = [h('div', { className: 'row' }, [UI.field('Case ID', caseIn), UI.btn(C.cur ? 'Switch / create' : 'Open / create', openCase, 'primary')]),
      h('div', { className: 'muted small' }, 'Workspace root: ' + C.wsRoot(st.settings))];
    if (cases.length) {
      caseBox.push(h('div', { className: 'mt' }, 'Existing cases:'));
      caseBox.push(UI.table(['Case', 'Examiner', 'Evidence ID', 'Source host', 'Modified'], cases.slice(0, 15).map(function (c) {
        return [UI.link(c.caseId, function () { try { A.openCase(c.caseId); A.nav('home'); } catch (e) { UI.alert('Case', e.message); } }), c.examiner || '', c.evidenceId || '', c.sourceHost || '', U.fmtTs(c.modified)];
      })));
    }
    b.appendChild(UI.section('1. Case', caseBox));
    if (C.cur) {
      var cd = C.cur.data, fields = {};
      var mk = function (key, label, w) { fields[key] = UI.input(cd[key] === undefined ? '' : cd[key], { style: { width: (w || 260) + 'px' } }); return UI.field(label, fields[key]); };
      var tzSel = V.tzSelect(cd.displayTzId || ('fixed:' + (cd.displayTzOffsetMinutes || 0)));
      var desc = h('textarea', { rows: 2, style: { width: '540px' } }); desc.value = cd.description || '';
      var meta = h('div', { className: 'form' }, [
        h('div', { className: 'row' }, [mk('examiner', 'Examiner'), mk('evidenceId', 'Evidence ID'), mk('sourceHost', 'Source host')]),
        h('div', { className: 'row' }, [mk('collectionUtc', 'Collection time (UTC)', 200), UI.field('Display time zone (DST-aware Windows zones, or a fixed offset)', tzSel.el)]),
        UI.field('Description', desc),
        h('div', { className: 'row' }, [UI.btn('Save case details', function () {
          var k; for (k in fields) { cd[k] = U.trim(fields[k].value); }
          var zone = tzSel.get(); if (!zone) { return; }
          cd.displayTzId = zone.id; cd.displayTzLabel = zone.label; cd.displayTzOffsetMinutes = zone.off(Date.now()); cd.description = desc.value;
          A.setZone(zone);
          C.save(); C.audit('case.update', { examiner: cd.examiner, evidenceId: cd.evidenceId, sourceHost: cd.sourceHost, tz: zone.id });
          A.refreshChrome(); UI.toast('Case details saved');
        }), h('span', { className: 'muted small' }, 'Workspace: ' + C.cur.ws)])
      ]);
      b.appendChild(UI.section('Case details', meta));

      // --- evidence ---
      var rootIn = UI.input(cd.lastRoot || (st.settings.recentRoots[0] || ''), { style: { width: '760px' }, placeholder: 'Folder containing W3SVC*/ log files, or a single .log file' });
      var go = function () { A.openEvidence(rootIn.value); };
      rootIn.onkeydown = function (e) { if ((e || window.event).keyCode === 13) { go(); } };
      var browse = function () {
        try {
          var sh = new ActiveXObject('Shell.Application'), f = sh.BrowseForFolder(0, 'Select the evidence folder (e.g. LogFiles or W3SVC1)', 0x0040 | 0x0010 | 0x4000, 0);
          if (f) { rootIn.value = f.Self.Path; }
        } catch (e) { UI.toast('Browse failed: ' + e.message, 'error'); }
      };
      var ahIn = UI.input(cd.appHostConfig || '', { style: { width: '640px' }, placeholder: 'optional: path to a collected applicationHost.config (maps W3SVCn to site names and bindings)' });
      ahIn.onchange = function () { cd.appHostConfig = U.trim(ahIn.value); C.save(); };
      var evBox = [h('div', { className: 'row' }, [rootIn, UI.btn('Browse\u2026', browse), UI.btn('Open evidence', go, 'primary')]), h('div', { className: 'row' }, [UI.field('applicationHost.config', ahIn)])];
      if (st.settings.recentRoots.length) {
        var rec = h('div', { className: 'recent' }, 'Recent: ');
        st.settings.recentRoots.forEach(function (r) { rec.appendChild(UI.link(r, function () { rootIn.value = r; })); rec.appendChild(h('br')); });
        evBox.push(rec);
      }
      b.appendChild(UI.section('2. Evidence', evBox));
    }
    // --- discovery ---
    if (st.disc) {
      var rows = st.disc.sites.map(function (s, i) {
        var dated = s.files.filter(function (f) { return f.nameDate; }).map(function (f) { return f.nameDate; }).sort();
        var si = IO.siteInfo(st.appHost, s.name);
        return [i === st.siteIdx ? h('b', null, s.name) : UI.link(s.name, function () { A.selectSite(i); }), si ? si.name + (si.bindings.length ? '  [' + si.bindings.join(', ') + ']' : '') : '', s.kind, U.fmtNum(s.files.length), U.fmtBytes(s.totalBytes), dated.length ? dated[0] + ' \u2026 ' + dated[dated.length - 1] : '', s.displayPath];
      });
      var dbox = [UI.table(['Site', 'IIS site name (applicationHost.config)', 'Kind', 'Files', 'Size', 'Filename dates', 'Original path'], rows)];
      dbox.push(h('div', { className: 'small muted' }, st.appHost ? 'applicationHost.config: ' + st.appHost.path : 'No applicationHost.config found in the collection (optional: set its path under Evidence).'));
      if (st.manifest) { dbox.push(h('div', { className: 'small' }, 'Velociraptor collection detected at ' + st.manifest.root + ' \u2014 cross-checking against ' + st.manifest.sources.join(', '))); }
      if (st.disc.warnings.length) { dbox.push(h('div', { className: 'warn' }, st.disc.warnings.join('\n'))); }
      dbox.push(h('div', { className: 'row mt' }, [
        UI.btn('Scan\u2026', function () { V.scanDialog(); }, 'primary', 'Build the index over the selected files'),
        st.idx && st.idx.partial ? UI.btn('Continue scan', function () { A.scan([], { resume: true }); }, '', 'Resume the partial scan') : null,
        UI.btn('Load rows\u2026', function () { V.loadDialog(); }), st.idx ? UI.btn('Overview', function () { A.nav('overview'); }) : null,
        st.idx ? h('span', { className: 'muted' }, 'Index: ' + (st.idx.partial ? 'partial ' : '') + st.idx.files.length + ' files, ' + U.fmtNum(st.idx.totals.rows) + ' rows, built ' + (st.idx.completedUtc || st.idx.createdUtc)) : h('span', { className: 'muted' }, 'No index yet for this site.')
      ]));
      b.appendChild(UI.section('3. Discovered sites', dbox));
    }
  };

  /* Time zone picker: Windows zones (DST rules from the registry), UTC, or a fixed offset. get() returns a zone or null. */
  V.tzSelect = function (currentId) {
    var list = [], opts = [['UTC', '(UTC) Coordinated Universal Time']], i, fixedIn = UI.input(/^fixed:/.test(currentId) ? currentId.substr(6) : '', { style: { width: '60px' }, placeholder: 'min' });
    try { list = NS.tz.list(); } catch (e) { NS.ui.toast('Windows time zone list unavailable: ' + e.message, 'warn'); }
    for (i = 0; i < list.length; i++) { opts.push([list[i].id, list[i].label + (list[i].hasDst ? '  [DST]' : '')]); }
    opts.push(['fixed', 'Fixed offset (minutes east of UTC) ...']);
    var sel = UI.select(opts, /^fixed:/.test(currentId) ? 'fixed' : currentId, function (v) { fixedIn.style.display = v === 'fixed' ? '' : 'none'; }, { style: { width: '420px' } });
    fixedIn.style.display = /^fixed:/.test(currentId) ? '' : 'none';
    return { el: h('span', null, [sel, ' ', fixedIn]), get: function () {
      if (sel.value === 'fixed') { var m = parseInt(fixedIn.value, 10); if (isNaN(m) || m < -840 || m > 840) { UI.alert('Time zone', 'Fixed offset must be minutes between -840 and 840 (e.g. 480 for UTC+08:00).'); return null; } return NS.tz.fixed(m); }
      try { return NS.tz.byId(sel.value); } catch (e) { UI.alert('Time zone', e.message); return null; }
    } };
  };

  /* ======================= DIALOGS ======================= */
  /* Filename-date range of the files whose rows overlap [from, to] (index first/last timestamps, else the filename
   * date). Returns null when no dated file overlaps, so the dialog falls back to all files. */
  V.fileDefaultsForRange = function (from, to) {
    var files = (st.scope || st.site).files, ids = A.fileIdsForRange(from, to), a = '', z = '', i, d;
    for (i = 0; i < ids.length; i++) { d = files[ids[i]].nameDate; if (d && d.length === 10) { if (!a || d < a) { a = d; } if (!z || d > z) { z = d; } } }
    return a ? { from: a, to: z } : null;
  };
  function fileSelector(files, defaults) {
    var dates = files.filter(function (f) { return f.nameDate; }).map(function (f) { return f.nameDate; }).sort();
    var from = UI.input(defaults && defaults.from || (dates[0] || ''), { style: { width: '110px' } }), to = UI.input(defaults && defaults.to || (dates[dates.length - 1] || ''), { style: { width: '110px' } });
    var glob = UI.input(defaults && defaults.glob || '*', { style: { width: '160px' } });
    var info = h('span', { className: 'muted' });
    function sel() {
      var g = U.globToRegex(glob.value || '*'), a = U.trim(from.value), z = U.trim(to.value), out = [], bytes = 0, i, f;
      for (i = 0; i < files.length; i++) {
        f = files[i];
        if (!g.test(f.name)) { continue; }
        if (f.nameDate && f.nameDate.length === 10 && ((a && f.nameDate < a) || (z && f.nameDate > z))) { continue; }
        out.push(i); bytes += f.size;
      }
      UI.text(info, U.fmtNum(out.length) + ' of ' + U.fmtNum(files.length) + ' files, ' + U.fmtBytes(bytes));
      return { ids: out, bytes: bytes, from: a, to: z, glob: glob.value };
    }
    from.onkeyup = to.onkeyup = glob.onkeyup = sel; from.onchange = to.onchange = glob.onchange = sel;
    sel();
    return { el: h('div', { className: 'row' }, [UI.field('Filename date from', from), UI.field('to', to), UI.field('Filename glob', glob), info]), get: sel };
  }
  V.scanDialog = function () {
    if (!A.requireCase()) { return; }
    if (!st.site) { UI.alert('Scan', 'Open evidence first.'); return; }
    var fs = fileSelector(st.site.files), hash = h('input', { type: 'checkbox', checked: st.settings.hashOnScan });
    var fastOk = NS.engine.available(), engSel = UI.select([['fast', 'Fast engine \u2014 compiled C# via PowerShell, several times faster' + (fastOk ? '' : ' (unavailable)')], ['builtin', 'Built-in engine \u2014 JavaScript in this window']], st.settings.scanEngine || (fastOk ? 'fast' : 'builtin'));
    var body = [h('p', null, 'The scan streams every selected file once, builds the index (aggregates, first-seen tables, integrity facts) and evaluates all enabled rules. Rows are not kept in memory.'), fs.el,
      h('label', { className: 'chk' }, [hash, ' Compute SHA-256 of the selected files in parallel (hidden PowerShell Get-FileHash)']),
      h('div', { className: 'row' }, [UI.field('Engine (both produce identical indexes)', engSel)]),
      h('p', { className: 'muted small' }, 'Rule set ' + st.ruleset.version + ' (' + st.ruleset.rules.filter(function (r) { return r.enabled; }).length + ' rules enabled). Built-in engine: roughly 1 minute per 1 GB. The fast engine compiles itself on first use (a few seconds) and is cached afterwards.')];
    UI.dialog({ title: 'Scan ' + st.site.name, body: body, width: 760, buttons: [{ label: 'Start scan', primary: true, onClick: function () {
      var s = fs.get(); if (!s.ids.length) { UI.toast('No files selected', 'warn'); return false; }
      st.settings.scanEngine = engSel.value; try { C.saveSettings(st.settings); } catch (e) { }
      A.scan(s.ids, { hash: hash.checked, engine: engSel.value });
    } }, { label: 'Cancel' }] });
  };
  V.loadDialog = function (preset) {
    if (!A.requireCase()) { return; }
    if (!st.site) { UI.alert('Load', 'Open evidence first.'); return; }
    preset = preset || {};
    var files = (st.scope || st.site).files;
    // A time range from a chart also narrows the file selection to the files that cover it, so only those are read.
    var fs = fileSelector(files, preset.fileDefaults || ((preset.from || preset.to) ? V.fileDefaultsForRange(preset.from, preset.to) : null));
    var tf = UI.input(preset.from ? U.fmtTs(preset.from, St.tz) : '', { style: { width: '150px' }, placeholder: 'YYYY-MM-DD[ HH:MM]' });
    var tt = UI.input(preset.to ? U.fmtTs(preset.to, St.tz) : '', { style: { width: '150px' }, placeholder: 'YYYY-MM-DD[ HH:MM]' });
    var pre = UI.input(preset.pre || '', { id: 'loadpre', style: { width: '560px' }, placeholder: 'optional quick filter applied while loading, e.g. class:public' });
    var presetSel = UI.select([['', 'Presets\u2026']].concat(F.PRESETS.map(function (p) { return [p.q, p.name]; })), '', function (v) { if (v) { pre.value = (pre.value ? pre.value + ' ' : '') + v; } presetSel.value = ''; });
    var raw = h('input', { type: 'checkbox', checked: st.settings.keepRaw });
    var cap = UI.input(st.settings.maxRows, { style: { width: '100px' } });
    var body = [fs.el,
      h('div', { className: 'row' }, [UI.field('Rows from (' + tzLabel() + ')', tf), UI.field('to', tt), h('span', { className: 'muted small' }, 'Append Z for UTC. Leave empty for all.')]),
      h('div', { className: 'row' }, [UI.field('Pre-filter', pre), presetSel]),
      h('div', { className: 'row' }, [h('label', { className: 'chk' }, [raw, ' Keep raw lines (needed for raw exports; ~260 bytes/row)']), UI.field('Row cap', cap)]),
      h('p', { className: 'muted small' }, 'Pre-filtering while loading is how to work on a slice of a large corpus (e.g. all external traffic for a month) without loading internal noise. The cap is enforced; nothing is sampled.')];
    UI.dialog({ title: 'Load rows into the grid', body: body, width: 820, enterButton: 0, buttons: [{ label: 'Load', primary: true, onClick: function () {
      var s = fs.get(), from = tf.value ? U.parseDateInput(tf.value, St.tz) : null, to = tt.value ? U.parseDateInput(tt.value, St.tz) : null;
      if ((tf.value && isNaN(from)) || (tt.value && isNaN(to))) { UI.toast('Bad date/time', 'error'); return false; }
      if (to !== null && /^\d{4}-\d{2}-\d{2}$/.test(U.trim(tt.value))) { to += 86400000 - 1; }
      var ids = s.ids;
      if (from !== null || to !== null) { var ov = A.fileIdsForRange(from, to), set = {}; ov.forEach(function (x) { set[x] = 1; }); ids = ids.filter(function (x) { return set[x]; }); }
      if (!ids.length) { UI.toast('No files in range', 'warn'); return false; }
      try { if (pre.value) { F.parse(pre.value, St.tz); } } catch (e) { UI.toast(e.message, 'error'); return false; }
      A.load({ fileIds: ids, from: from, to: to, preText: pre.value, keepRaw: raw.checked, maxRows: Math.max(1000, parseInt(cap.value, 10) || st.settings.maxRows), label: preset.label || 'manual' });
    } }, { label: 'Cancel' }] });
  };
  V.exportDialog = function () {
    if (!A.requireCase()) { return; }
    var items = [];
    var done = function (err, info) {
      if (err) { UI.alert('Export failed', err.message); return; }
      UI.dialog({ title: 'Export written', body: UI.kv([['File', info.path], ['SHA-256', info.sha256, 'mono'], ['Size', U.fmtBytes(info.bytes)]]), buttons: [{ label: 'Show in folder', onClick: function () { X.openFolder(info.path); } }, { label: 'Close', primary: true }] });
    };
    function rowsExport(fmt, all) {
      return function () {
        var g = st.grid, cols = V.gridColumns(all);
        var prog = UI.progress('Exporting ' + U.fmtNum(g.view.length) + ' rows (' + fmt + ')');
        X.rows(st.store, g.view, cols, fmt, X.outPath('rows', fmt === 'jsonl' ? 'jsonl' : 'csv'), St.tz, tzLabel(), function (e, i) { prog.close(); done(e, i); }, function (p) { prog.update(p); }, { filter: F.toText(g.model), sort: g.sortKey + (g.sortDesc ? ' desc' : '') });
      };
    }
    if (st.store && st.grid.view) {
      var n = U.fmtNum(st.grid.view.length);
      items.push(['Grid rows \u2192 CSV (visible columns)', n + ' rows as shown, current sort', rowsExport('csv', false)]);
      items.push(['Grid rows \u2192 CSV (all columns)', n + ' rows, every parsed and derived field', rowsExport('csv', true)]);
      items.push(['Grid rows \u2192 Timeline Explorer CSV', n + ' rows, TLE column order with UTC and local timestamps', rowsExport('tle')]);
      items.push(['Grid rows \u2192 JSONL', n + ' rows, one JSON object per line (decoded + raw)', rowsExport('jsonl')]);
      items.push(['Selected rows \u2192 raw line bundle', 'Original lines byte-for-byte as stored in the evidence, grouped by source file (select rows in the grid first)', function () {
        var sel = V.gridSelection(); if (!sel.length) { UI.toast('Select rows in the grid first', 'warn'); return; }
        try { done(null, X.rawBundle(st.store, sel, X.outPath('raw-lines', 'txt'))); } catch (e) { done(e); }
      }]);
    }
    if (st.idx) {
      items.push(['Findings \u2192 CSV', st.idx.findings.length + ' findings with dispositions', function () {
        var rows = st.idx.findings.map(function (f) { var d = C.getDisp(R.findingSig(f)); return [f.id, f.severity, f.ruleId, f.name, f.category, f.entity, f.key, f.count, U.fmtIso(f.first), U.fmtIso(f.last), (f.attack || []).join(' '), f.detail, (f.ips || []).slice(0, 25).join(' '), (f.stems || []).slice(0, 10).join(' '), d ? d.state : 'Needs review', d ? d.note : '']; });
        done(null, X.table(['ID', 'Severity', 'Rule', 'Name', 'Category', 'Entity', 'Key', 'Count', 'First UTC', 'Last UTC', 'ATT&CK', 'Detail', 'IPs', 'Stems', 'Disposition', 'Note'], rows, X.outPath('findings', 'csv'), 'findings'));
      }]);
      items.push(['Findings \u2192 JSON', 'Full finding objects including example rows', function () { done(null, X.json({ caseId: C.cur.data.caseId, generated: U.nowIso(), ruleset: st.ruleset.hash, findings: st.idx.findings, dispositions: C.cur.data.dispositions }, X.outPath('findings', 'json'), 'findings-json')); }]);
      items.push(['Integrity / file table \u2192 CSV', st.idx.files.length + ' files with hashes, blocks, anomalies', function () {
        var rows = st.idx.files.map(function (f) { return [f.name, f.displayPath, f.path, f.size, U.fmtIso(f.mtime), f.rows || 0, f.lines || 0, f.blocks ? f.blocks.length : 0, f.malformed || 0, f.nonAscii || 0, f.decodeErr || 0, f.tailNoEol ? 'yes' : '', f.backSteps || 0, U.fmtIso(f.minTs), U.fmtIso(f.maxTs), f.sha256 || '', f.manifest ? f.manifest.status : '', f.manifest ? f.manifest.detail : '']; });
        done(null, X.table(['File', 'Original path', 'Evidence path', 'Bytes', 'Modified UTC', 'Rows', 'Lines', 'Header blocks', 'Malformed', 'Non-ASCII', 'Decode errors', 'Truncated tail', 'Backwards steps', 'Min UTC', 'Max UTC', 'SHA-256', 'Manifest', 'Manifest detail'], rows, X.outPath('integrity', 'csv'), 'integrity'));
      }]);
      items.push(['Client IPs (index) \u2192 CSV', U.fmtNum(st.idx.counts.ips) + ' IPs with counts, status mix, rule hits', function () {
        var rows = [], k, r; for (k in st.idx.ips) { r = st.idx.ips[k]; rows.push([k, r.cls, NS.enrich.lookup(k), r.n, U.fmtIso(r.first), U.fmtIso(r.last), r.s2, r.s3, r.s4, r.s5, r.post, r.exec, r.stat, r.stN + (r.stOv ? '+' : ''), Object.keys(r.hits).join(' '), C.getTags('ips', k).join(' ')]); }
        rows.sort(function (a, b) { return b[3] - a[3]; });
        done(null, X.table(['IP', 'Class', 'ASN / Geo', 'Requests', 'First UTC', 'Last UTC', '2xx', '3xx', '4xx', '5xx', 'POST', 'Exec', 'Static', 'Distinct stems', 'Rule hits', 'Tags'], rows, X.outPath('ips', 'csv'), 'ips'));
      }]);
      items.push(['URI stems (index) \u2192 CSV', U.fmtNum(st.idx.counts.stems) + ' stems with first seen, clients, status', function () {
        var rows = [], k, s; for (k in st.idx.stems) { s = st.idx.stems[k]; rows.push([s.raw, s.n, U.fmtIso(s.first), U.fmtIso(s.last), s.fIp, (st.idx.files[s.fFile] || {}).name, s.fLine, s.ipN + (s.ipOv ? '+' : ''), s.pubN, s.post, s.ok, s.okPub, s.s4, s.s5, s.exec ? 'yes' : '']); }
        rows.sort(function (a, b) { return a[2] < b[2] ? -1 : 1; });
        done(null, X.table(['Stem', 'Requests', 'First UTC', 'Last UTC', 'First client', 'First file', 'First line', 'Distinct IPs', 'Public IPs', 'POST', '200', 'Public 200', '4xx', '5xx', 'Executable'], rows, X.outPath('stems', 'csv'), 'stems'));
      }]);
    }
    if (st.sessions) {
      items.push(['Sessions \u2192 CSV', st.sessions.length + ' sessions from the current grid view', function () {
        var rows = st.sessions.map(function (s) { return [s.id, s.ip, s.cls, s.fam, s.ua, U.fmtIso(s.start), U.fmtIso(s.end), Math.round(s.duration / 1000), s.rows, s.stems, s.s2, s.s3, s.s4, s.s5, s.execPost, s.hits]; });
        done(null, X.table(['Session', 'IP', 'Class', 'UA family', 'User agent', 'Start UTC', 'End UTC', 'Duration s', 'Rows', 'Distinct stems', '2xx', '3xx', '4xx', '5xx', 'Exec POST', 'Rule-hit rows'], rows, X.outPath('sessions', 'csv'), 'sessions'));
      }]);
    }
    if (st.uaLast) { items.push(['User agents \u2192 CSV', st.uaLast.rows.length + ' rows: ' + st.uaLast.title + ', with parsed browser, age, flags and reasons', function () { done(null, X.table(st.uaLast.headers, st.uaLast.rows, X.outPath('user-agents', 'csv'), 'user-agents', { title: st.uaLast.title })); }]); }
    if (st.topnLast) { items.push(['Top-N table \u2192 CSV', st.topnLast.title, function () { done(null, X.table(st.topnLast.headers, st.topnLast.rows, X.outPath('topn', 'csv'), 'topn', { title: st.topnLast.title })); }]); }
    if (st.lpResult) {
      items.push(['Log Parser result \u2192 CSV', U.fmtNum(st.lpResult.rows.length) + ' rows from the last Log Parser query', function () {
        var dst = X.outPath('logparser', 'csv'); U.fso().CopyFile(st.lpResult.csvPath, dst, false);
        done(null, X.finalize(dst, 'logparser', { rows: st.lpResult.rows.length, sql: st.lpResult.sql.substr(0, 2000) }));
      }]);
    }
    if (st.iocHits) { items.push(['IOC hits \u2192 CSV', st.iocHits.length + ' IOC hit rows', function () { done(null, X.table(['IOC type', 'IOC', 'Note', 'Where', 'Hits', 'First UTC', 'Last UTC', 'Sample'], st.iocHits.map(function (r) { return [r.type, r.value, r.note, r.where, r.n, U.fmtIso(r.first), U.fmtIso(r.last), r.sample]; }), X.outPath('ioc-hits', 'csv'), 'ioc-hits')); }]); }
    items.push(['Case bundle \u2192 ZIP', 'case.json, audit log, index, exports and reports zipped (hidden PowerShell Compress-Archive)', function () {
      var prog = UI.progress('Creating case bundle');
      X.caseBundle(function (err, info) { prog.close(); done(err, info); });
    }]);
    if (!items.length) { UI.alert('Export', 'Nothing to export yet. Scan the evidence or load rows first.'); return; }
    var list = h('div', { className: 'exportlist' });
    var dlg;
    items.forEach(function (it) { list.appendChild(h('div', { className: 'export-i', onclick: function () { dlg.close(); setTimeout(it[2], 30); } }, [h('b', null, it[0]), h('div', { className: 'muted small' }, it[1])])); });
    dlg = UI.dialog({ title: 'Export (to ' + C.cur.exports + ')', body: [list, h('p', { className: 'muted small' }, 'Every export is hashed (SHA-256 sidecar file) and recorded in the case audit log.')], width: 640, buttons: [{ label: 'Close' }] });
  };

  /* ======================= OVERVIEW ======================= */
  V.overview = function (main) {
    if (!st.idx) { needIndex(main, 'Overview'); return; }
    var idx = st.idx, t = idx.totals;
    var b = page(main, 'Overview \u2014 ' + idx.site, [idx.partial ? UI.btn('Continue scan', function () { A.scan([], { resume: true }); }, 'primary') : null, UI.btn('Rescan\u2026', function () { V.scanDialog(); })], idx.siteDisplayPath);
    if (idx.partial) { b.appendChild(h('div', { className: 'banner warn' }, 'PARTIAL INDEX: ' + idx.filesDone + ' of ' + idx.files.length + ' files scanned' + (idx.cancelledAt ? ' (cancelled ' + idx.cancelledAt + ')' : '') + '. Figures below cover only the scanned files.')); }
    var sev = {}; idx.findings.forEach(function (f) { sev[f.severity] = (sev[f.severity] || 0) + 1; });
    var cards = h('div', { className: 'cards' }, [
      UI.card('Files', U.fmtNum(idx.files.length), U.fmtBytes(t.bytes)),
      UI.card('Time span (UTC)', t.firstTs ? U.dayKey(t.firstTs) : '-', t.lastTs ? 'to ' + U.dayKey(t.lastTs) : ''),
      UI.card('Requests', U.fmtNum(t.rows), U.fmtNum(t.lines) + ' lines read'),
      UI.card('Client IPs', U.fmtNum(idx.counts.ips), U.fmtNum(U.countKeys(idx.ips) - countClass('rfc1918') - countClass('loopback')) + ' non-internal', '', function () { A.nav('ips'); }),
      UI.card('Findings', U.fmtNum(idx.findings.length), (sev.critical || 0) + ' critical \u00b7 ' + (sev.high || 0) + ' high \u00b7 ' + (sev.medium || 0) + ' medium', (sev.critical || sev.high) ? 'hot' : '', function () { A.nav('findings'); }),
      UI.card('Restarts', U.fmtNum(idx.restarts.length), U.fmtNum(t.blocks) + ' header blocks', '', function () { A.nav('integrity'); }),
      UI.card('Gaps / missing files', idx.gaps.length + ' / ' + idx.missingFiles.length, 'gaps \u2265 ' + (st.ruleset.byId['R-INF-001'] ? st.ruleset.byId['R-INF-001'].params.gapHours : 4) + ' h', (idx.gaps.length || idx.missingFiles.length) ? 'warm' : '', function () { A.nav('integrity'); }),
      UI.card('Malformed rows', U.fmtNum(t.malformed), U.fmtNum(t.nonAscii) + ' non-ASCII \u00b7 ' + U.fmtNum(t.decodeErr) + ' decode err', t.malformed ? 'warm' : '')
    ]);
    function countClass(c) { var n = 0, k; for (k in idx.ips) { if (idx.ips[k].cls === c) { n++; } } return n; }
    b.appendChild(cards);

    // per-day chart
    var days = Object.keys(idx.perDay).sort(), chartHost = h('div', { className: 'chart-host' }), chart2 = h('div', { className: 'chart-host' });
    var gran = days.length > 400 ? 'month' : 'day', labels = [], vals = [], keys = [];
    if (gran === 'month') {
      var m = {}, i, j;
      for (i = 0; i < days.length; i++) { var mk = days[i].substr(0, 7); if (!m[mk]) { m[mk] = [0, 0, 0, 0, 0, 0, 0, 0]; keys.push(mk); } for (j = 0; j < 8; j++) { m[mk][j] += idx.perDay[days[i]][j]; } }
      labels = keys; vals = keys.map(function (k) { return m[k]; });
    } else { labels = days; vals = days.map(function (d) { return idx.perDay[d]; }); }
    b.appendChild(UI.section('Requests per ' + gran + ' by status class (UTC) \u2014 drag to load that range, click a bar to load it', chartHost));
    b.appendChild(UI.section('Requests per ' + gran + ': external vs loopback vs rule-hit rows', chart2));
    setTimeout(function () {
      function rangeOf(i0, i1) {
        var a, z;
        if (gran === 'month') { a = U.dayKeyToMs(labels[i0] + '-01'); var e = U.dayKeyToMs(labels[i1] + '-01'); var d = new Date(e); z = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) - 1; } else { a = U.dayKeyToMs(labels[i0]); z = U.dayKeyToMs(labels[i1]) + 86400000 - 1; }
        V.loadDialog({ from: a, to: z, label: 'overview range' });
      }
      UI.barChart(chartHost, { labels: labels, stacked: true, height: 190, series: [
        { name: '2xx', color: UI.COLORS.s2, values: vals.map(function (v) { return v[1]; }) }, { name: '3xx', color: UI.COLORS.s3, values: vals.map(function (v) { return v[2]; }) },
        { name: '4xx', color: UI.COLORS.s4, values: vals.map(function (v) { return v[3]; }) }, { name: '5xx', color: UI.COLORS.s5, values: vals.map(function (v) { return v[4]; }) }],
        onBrush: rangeOf, onClick: function (i) { rangeOf(i, i); } });
      UI.barChart(chart2, { labels: labels, stacked: false, height: 160, log: true, series: [
        { name: 'external', color: UI.COLORS.ext, values: vals.map(function (v) { return v[5]; }) }, { name: 'loopback', color: UI.COLORS.int, values: vals.map(function (v) { return v[6]; }) },
        { name: 'rule hits', color: UI.COLORS.hits, values: vals.map(function (v) { return v[7]; }) }], onBrush: rangeOf, onClick: function (i) { rangeOf(i, i); } });
    }, 10);

    // heatmap year x month
    var years = {}, k2, yl = [];
    for (k2 in idx.perDay) { var y = k2.substr(0, 4); if (!years[y]) { years[y] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; yl.push(y); } years[y][+k2.substr(5, 2) - 1] += idx.perDay[k2][0]; }
    yl.sort();
    var hm = h('div');
    UI.heatmap(hm, { rows: yl, cols: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], values: yl.map(function (y) { return years[y]; }),
      onClick: function (r, c) { var a = Date.UTC(+yl[r], c, 1), z = Date.UTC(+yl[r], c + 1, 1) - 1; V.loadDialog({ from: a, to: z, label: 'heatmap ' + yl[r] + '-' + (c + 1) }); } });

    // facts
    var sports = topList(idx.sports, 10).map(function (k) { return k + ' (' + U.fmtNum(idx.sports[k]) + ')'; }).join(', ');
    var dh = [], i3;
    for (i3 = 0; i3 < idx.files.length; i3++) { var fr = idx.files[i3]; if (fr.nameDate && fr.nameKind === 'daily' && fr.minTs) { dh.push(Math.round((fr.minTs - U.dayKeyToMs(fr.nameDate)) / 3600000)); } }
    var rollHint = dh.length ? (function () { var cnt = {}, best = 0, bv = 0; dh.forEach(function (x) { cnt[x] = (cnt[x] || 0) + 1; if (cnt[x] > bv) { bv = cnt[x]; best = x; } }); return best === 0 ? 'Daily files start at 00:00 UTC (UTC rollover, IIS default)' : 'Daily files start ' + best + ' h from midnight UTC: local-time rollover suggests server TZ ' + U.fmtOffset(-best * 60); }()) : 'n/a';
    var hb = idx.heartbeat ? idx.heartbeat.stem + '?' + idx.heartbeat.query + ' (~' + U.fmtNum(idx.heartbeat.perDay) + '/day from loopback)' : 'none learned';
    var hashed = idx.files.filter(function (f) { return f.sha256; }).length, manBad = idx.files.filter(function (f) { return f.manifest && f.manifest.status === 'mismatch'; }).length;
    var facts = UI.kv([
      ['IIS software', Object.keys(idx.softwares).join('; ')],
      (function () { var si = IO.siteInfo(st.appHost, idx.site); return si ? ['IIS site', si.name + ' (id ' + si.id + ')\n' + si.bindings.join('\n') + (si.apps.length ? '\n' + si.apps.join('\n') : '')] : null; }()),
      ['Field layout(s)', idx.schemas.map(function (s) { return s.fields + '  [' + U.fmtNum(s.blocks) + ' blocks]'; }).join('\n')],
      ['Server IP:port', sports],
      ['Rollover / server TZ hint', rollHint],
      ['Learned heartbeat', hb],
      ['Codepage hint', idx.totals.nonAscii ? U.fmtNum(idx.totals.nonAscii) + ' rows contain non-ASCII bytes; displayed via the system ANSI codepage (case hint ' + st.settings.codepageHint + ').' : 'All rows ASCII (non-ASCII appears only percent-encoded).'],
      ['Hashes', hashed + ' / ' + idx.files.length + ' files SHA-256' + (st.hashing ? ' (hashing in progress\u2026)' : ''), hashed < idx.files.length ? 'warn' : ''],
      ['Collector manifest', st.manifest ? (manBad ? manBad + ' mismatch(es)' : 'consistent') + ' \u2014 ' + st.manifest.sources.join('; ') : 'not found', manBad ? 'warn' : ''],
      ['Index caps', ((idx.caps.ipEvicted || idx.caps.stemEvicted || idx.caps.uaEvicted) ? 'APPROXIMATE: evicted IPs ' + idx.caps.ipEvicted + ', stems ' + idx.caps.stemEvicted + ', UAs ' + idx.caps.uaEvicted : 'exact (no evictions)') + (idx.counts && (idx.counts.ips > idx.caps.ipCap || idx.counts.stems > idx.caps.stemCap || idx.counts.uas > idx.caps.uaCap) ? '; caps exceeded (IPs ' + idx.counts.ips + '/' + idx.caps.ipCap + ', stems ' + idx.counts.stems + '/' + idx.caps.stemCap + ', UAs ' + idx.counts.uas + '/' + idx.caps.uaCap + '): entries with rule hits, successful executable paths and frequent entries are never evicted' : '')],
      ['Scan', (idx.partial ? 'partial' : 'complete') + ' \u00b7 ' + U.fmtDuration(idx.scanMs) + ' \u00b7 ' + U.fmtNum(Math.round(t.rows / Math.max(1, idx.scanMs) * 1000)) + ' rows/s \u00b7 rules ' + idx.rulesetVersion + ' (' + idx.rulesetHash + ')']
    ]);
    b.appendChild(h('div', { className: 'cols2' }, [UI.section('Server and corpus facts', facts), UI.section('Requests per month', hm)]));

    // headline tables
    var ext = [], k3;
    for (k3 in idx.ips) { if (!U.isInternalClass(idx.ips[k3].cls)) { ext.push(k3); } }
    ext.sort(function (a, c) { return idx.ips[c].n - idx.ips[a].n; });
    var extTbl = UI.table(['IP', 'Class', 'Requests', '4xx', 'First', 'Last', 'Rule hits'], ext.slice(0, 15).map(function (ip) {
      var r = idx.ips[ip]; return [ipLink(ip), r.cls, U.fmtNum(r.n), U.pct(r.s4, r.n), tsCell(r.first), tsCell(r.last), Object.keys(r.hits).join(' ')];
    }));
    var recent = [], cutoff = t.lastTs - 30 * 86400000, k4;
    for (k4 in idx.stems) { var s4 = idx.stems[k4]; if (s4.exec && s4.first >= cutoff && s4.ok > 0) { recent.push(k4); } }
    recent.sort(function (a, c) { return idx.stems[c].first - idx.stems[a].first; });
    var newTbl = recent.length ? UI.table(['Stem', 'First seen', 'First client', 'Requests', 'Clients', '200s (public)'], recent.slice(0, 20).map(function (k) {
      var s = idx.stems[k]; return [stemLink(k, s.raw), tsCell(s.first), ipLink(s.fIp), U.fmtNum(s.n), s.ipN + (s.ipOv ? '+' : ''), s.ok + ' (' + s.okPub + ')'];
    })) : h('p', { className: 'muted' }, 'No executable path first seen in the last 30 days of the corpus returned 200.');
    b.appendChild(h('div', { className: 'cols2' }, [UI.section('Top non-internal clients', extTbl), UI.section('Executable paths first seen in the last 30 days of the corpus (with any 200)', newTbl)]));
    var crit = idx.findings.filter(function (f) { return f.severity === 'critical' || f.severity === 'high'; }).slice(0, 15);
    if (crit.length) {
      b.appendChild(UI.section('Critical and high findings', UI.table(['ID', 'Severity', 'Rule', 'Entity', 'First', 'Detail'], crit.map(function (f) {
        return [UI.link(f.id, function () { A.nav('findings', f.id); }), UI.sevBadge(f.severity), f.ruleId + ' ' + f.name, f.entity + ': ' + f.key, tsCell(f.first), f.detail];
      }))));
    }
  };

  /* ======================= FINDINGS ======================= */
  V.findings = function (main, focusId) {
    if (!st.idx) { needIndex(main, 'Findings'); return; }
    var all = st.idx.findings, fs = st.findFilter || (st.findFilter = { sev: '', cat: '', disp: '', text: '', rule: '' });
    var b = page(main, 'Findings', [UI.btn('Re-evaluate aggregate rules', function () { st.idx.findings = S.buildFindings(st.idx, st.ruleset, st.settings); A.saveIndex(); C.audit('findings.rebuild', { n: st.idx.findings.length }); A.nav('findings'); }, '', 'Rebuild findings from the index with the current rule settings (row-rule changes need a rescan)')]);
    var cats = {}; all.forEach(function (f) { cats[f.category] = 1; });
    var rules = {}; all.forEach(function (f) { rules[f.ruleId] = f.name; });
    var txt = UI.input(fs.text, { placeholder: 'search id, entity, detail', style: { width: '220px' } });
    var bar = h('div', { className: 'row' }, [
      UI.field('Severity', UI.select([['', 'All'], ['critical', 'Critical'], ['high', 'High+'], ['medium', 'Medium+'], ['low', 'Low+']], fs.sev, function (v) { fs.sev = v; A.nav('findings'); })),
      UI.field('Category', UI.select([['', 'All']].concat(Object.keys(cats).sort()), fs.cat, function (v) { fs.cat = v; A.nav('findings'); })),
      UI.field('Rule', UI.select([['', 'All']].concat(Object.keys(rules).sort().map(function (r) { return [r, r + ' ' + rules[r]]; })), fs.rule, function (v) { fs.rule = v; A.nav('findings'); }, { style: { width: '260px' } })),
      UI.field('Disposition', UI.select([['', 'All']].concat(C.DISPOSITIONS), fs.disp, function (v) { fs.disp = v; A.nav('findings'); })),
      UI.field('Search', txt), UI.btn('Apply', function () { fs.text = txt.value; A.nav('findings'); })
    ]);
    txt.onkeydown = function (e) { if ((e || window.event).keyCode === 13) { fs.text = txt.value; A.nav('findings'); } };
    b.appendChild(bar);
    var minSev = { critical: 5, high: 4, medium: 3, low: 2 }[fs.sev] || 0, tl = fs.text.toLowerCase();
    var list = all.filter(function (f) {
      if (minSev && R.SEV[f.severity] < minSev) { return false; }
      if (fs.cat && f.category !== fs.cat) { return false; }
      if (fs.rule && f.ruleId !== fs.rule) { return false; }
      var d = C.getDisp(R.findingSig(f)), ds = d ? d.state : 'Needs review';
      if (fs.disp && ds !== fs.disp) { return false; }
      if (tl && (f.id + ' ' + f.ruleId + ' ' + f.name + ' ' + f.key + ' ' + f.detail + ' ' + (f.ips || []).join(' ')).toLowerCase().indexOf(tl) < 0) { return false; }
      return true;
    });
    var split = h('div', { className: 'split-v' }), top = h('div', { className: 'split-top' }), detail = h('div', { className: 'split-bottom detail' });
    split.appendChild(top); split.appendChild(detail);
    b.appendChild(h('div', { className: 'muted small' }, U.fmtNum(list.length) + ' of ' + U.fmtNum(all.length) + ' findings'));
    b.appendChild(split);
    var cols = [{ key: 'id', label: 'ID', w: 62 }, { key: 'sev', label: 'Severity', w: 66 }, { key: 'rule', label: 'Rule', w: 88 }, { key: 'name', label: 'Name', w: 290 },
      { key: 'entity', label: 'Entity', w: 300 }, { key: 'count', label: 'Count', w: 70, num: true }, { key: 'first', label: 'First (UTC)', w: 135 }, { key: 'last', label: 'Last (UTC)', w: 135 },
      { key: 'disp', label: 'Disposition', w: 110 }, { key: 'detail', label: 'Detail', w: 500 }];
    var grid = new UI.VGrid(top, { columns: cols, count: function () { return list.length; },
      cell: function (r, k) {
        var f = list[r];
        switch (k) {
          case 'id': return f.id; case 'sev': return f.severity; case 'rule': return f.ruleId; case 'name': return f.name; case 'entity': return f.entity + ': ' + f.key;
          case 'count': return U.fmtNum(f.count); case 'first': return tsCell(f.first); case 'last': return tsCell(f.last);
          case 'disp': var d = C.getDisp(R.findingSig(f)); return d ? d.state : ''; case 'detail': return f.detail;
        }
        return '';
      },
      rowClass: function (r) { var d = C.getDisp(R.findingSig(list[r])); return 'sevrow-' + list[r].severity + (d && d.state === 'False positive' ? ' fp' : ''); },
      onSelect: function (r) { showDetail(list[r]); }
    });
    function showDetail(f) {
      UI.clear(detail);
      var sig = R.findingSig(f), d = C.getDisp(sig);
      var dsel = UI.select([['', 'Needs review']].concat(C.DISPOSITIONS.slice(1)), d ? d.state : '');
      var note = UI.input(d ? d.note : '', { style: { width: '380px' }, placeholder: 'examiner note' });
      var acts = h('div', { className: 'row' }, [
        UI.btn('Load evidence rows', function () { V.loadForFinding(f); }, 'primary'),
        f.ips && f.ips.length === 1 ? UI.btn('IP profile', function () { A.nav('ipProfile', f.ips[0]); }) : null,
        f.entity === 'stem' ? UI.btn('URI profile', function () { A.nav('uriProfile', f.key); }) : null,
        f.entity === 'ua' ? UI.btn('User agent details', function () { A.nav('uas', f.key); }) : null,
        f.firstRef ? UI.btn('Raw context of first occurrence', function () { A.rawContext(f.firstRef[0], f.firstRef[1]); }) : null,
        f.fileRefs && f.fileRefs.length ? UI.btn('Raw context', function () { A.rawContext(f.fileRefs[0][0], f.fileRefs[0][1]); }) : null,
        h('span', { className: 'sp' }), UI.field('Disposition', dsel), note,
        UI.btn('Save', function () { C.setDisp(sig, dsel.value, note.value); grid.render(); UI.toast('Disposition saved'); })
      ]);
      detail.appendChild(h('div', { className: 'det-h' }, [UI.sevBadge(f.severity), ' ', h('b', null, f.id + '  ' + f.ruleId + ' \u2014 ' + f.name), h('span', { className: 'muted' }, '  ' + f.category + '  \u00b7  ATT&CK ' + (f.attack || []).join(', '))]));
      detail.appendChild(acts);
      var ipsEl = h('span'); (f.ips || []).slice(0, 25).forEach(function (ip, i) { if (i) { ipsEl.appendChild(document.createTextNode(', ')); } ipsEl.appendChild(ipLink(ip)); });
      var stEl = h('span'); (f.stems || []).slice(0, 15).forEach(function (s, i) { if (i) { stEl.appendChild(document.createTextNode('  \u00b7  ')); } stEl.appendChild(stemLink(s.toLowerCase(), s)); });
      detail.appendChild(UI.kv([['Entity', f.entity + ': ' + f.key], ['Detail', f.detail], ['Count / first / last', U.fmtNum(f.count) + '  \u00b7  ' + tsCell(f.first) + '  \u2192  ' + tsCell(f.last) + ' UTC'],
        ['Clients', ipsEl], ['Paths', stEl], ['Description', f.description], ['False positives', f.falsePositives],
        d ? ['Disposition', d.state + (d.note ? ': ' + d.note : '') + '  (' + d.examiner + ', ' + d.ts + ')'] : null]));
      if (f.examples && f.examples.length) {
        var ex = h('div', { className: 'rawctx small' });
        f.examples.forEach(function (x) {
          var sc = x[5] >= 0 ? Math.floor(x[5] / 100) : 0;
          ex.appendChild(h('div', { className: 'rl clickable', title: 'Double-click: raw context' + (x[6] ? ' · severity of this hit: ' + x[6] : ''), ondblclick: function () { A.rawContext(x[0], x[1]); } }, [
            h('span', { className: 'ln' }, ((st.idx.files[x[0]] || {}).name || '') + ':' + x[1]),
            x[5] !== undefined ? h('span', { className: 'exst s' + sc }, x[5] >= 0 ? '' + x[5] : '-') : null,
            x[4] || h('span', { className: 'muted' }, U.fmtTs(x[2]) + ' UTC  ' + x[3] + '  (raw line not kept; double-click for the raw context)')]));
        });
        detail.appendChild(h('div', { className: 'mt' }, ['Example rows' + (f.kept ? ' (' + f.examples.length + ' of ' + U.fmtNum(f.kept) + ' kept; responses 2xx and 5xx first, then the rest in log order)' : '') + ':', ex]));
      }
    }
    if (list.length) {
      var fi = 0, i;
      if (focusId) { for (i = 0; i < list.length; i++) { if (list[i].id === focusId) { fi = i; } } }
      grid.select(fi);
    }
  };
  V.loadForFinding = function (f) {
    var idx = st.idx;
    if (f.entity === 'rows') {
      var h0 = idx.ruleHits[f.ruleId];
      if (!h0) { return; }
      if (h0.kept.length < h0.n) { UI.toast('Loading the ' + U.fmtNum(h0.kept.length) + ' retained pointers of ' + U.fmtNum(h0.n) + ' hits; use rule:' + f.ruleId + ' as a pre-filter to load all.', 'warn', 8000); }
      A.loadPointers(h0.kept, f.id + ' ' + f.ruleId);
    } else if (f.entity === 'ip') {
      var r = idx.ips[f.key], ids = r ? A.fileIdsForRange(r.first, r.last) : A.allFileIds();
      A.loadWhere('cip:' + f.key, f.id + ' ' + f.ruleId, ids);
    } else if (f.entity === 'stem') {
      var s = idx.stems[f.key], ids2 = s ? A.fileIdsForRange(s.first, s.last) : A.allFileIds();
      A.load({ fileIds: ids2, preModel: { conds: [{ f: 'stem', op: 'eq', v: [f.key], text: 'stem:=' + f.key }] }, label: f.id + ' ' + f.ruleId });
    } else if (f.entity === 'ua') {
      A.load({ fileIds: A.fileIdsForRange(f.first, f.last), preText: V.uaFilter(f.key), label: f.id + ' ' + f.ruleId });
    } else if (f.entity === 'summary') {
      var mem = f.members || [], fids = [], j;
      for (j = 0; j < idx.files.length; j++) { if (mem.indexOf(idx.files[j].name) >= 0) { fids.push(j); } }
      if (fids.length) { A.load({ fileIds: fids, label: f.id + ' ' + f.ruleId + ' summary' }); return; }
      if (f.ips && f.ips.length) {
        if (f.ips.length > 500) { UI.toast('Loading rows for the first 500 of ' + f.ips.length + ' clients in this summary', 'warn', 8000); }
        A.loadWhere('cip:' + f.ips.slice(0, 500).join(','), f.id + ' ' + f.ruleId + ' summary');
        return;
      }
      UI.toast('Nothing to load for this summary finding', 'warn');
    } else if (f.entity === 'file') {
      var fid = -1, i; for (i = 0; i < idx.files.length; i++) { if (idx.files[i].name === f.key) { fid = i; } }
      if (fid >= 0) { A.load({ fileIds: [fid], label: f.id + ' ' + f.ruleId }); }
    } else if (f.first) {
      var a = f.first - 3600000, z = (f.last || f.first) + 3600000;
      A.load({ fileIds: A.fileIdsForRange(a, z), from: a, to: z, label: f.id + ' ' + f.ruleId + ' \u00b11h' });
    }
  };

  /* ======================= GRID ======================= */
  V.gridColumns = function (all) {
    var cfg = st.columns, out = [], i, c;
    if (all) { for (i = 0; i < St.COLUMNS.length; i++) { out.push(U.extend({}, St.COLUMNS[i])); } return out; }
    if (!cfg) { cfg = []; for (i = 0; i < St.COLUMNS.length; i++) { if (!St.COLUMNS[i].hidden) { cfg.push({ key: St.COLUMNS[i].key, w: St.COLUMNS[i].w }); } } st.columns = cfg; }
    for (i = 0; i < cfg.length; i++) { c = St.colByKey[cfg[i].key]; if (c) { out.push(U.extend({}, c, { w: cfg[i].w || c.w })); } }
    return out;
  };
  V.gridSelection = function () {
    if (!st.gridCtl || !st.grid.view) { return []; }
    return st.gridCtl.selection().map(function (r) { return st.grid.view[r]; });
  };
  V.saveGridPos = function () { if (st.gridCtl) { st.grid.first = st.gridCtl.first; st.grid.sel = st.gridCtl.sel; } };
  V.grid = function (main) {
    if (!st.store) { needRows(main, 'Rows'); st.gridCtl = null; return; }
    var g = st.grid, store = st.store;
    if (!g.view) { A.applyGrid(); }
    var li = st.loadInfo || {};
    var sub = 'Loaded ' + U.fmtNum(store.n) + ' rows' + (store.capped ? ' (CAPPED)' : '') + (store.failed && store.failed.length ? ' (INCOMPLETE: ' + store.failed.length + ' file(s) unreadable)' : '') + (li.pre ? ' with pre-filter ' + li.pre : '') + (li.label ? ' \u2014 ' + li.label : '');
    var b = page(main, 'Rows', [UI.btn('Columns\u2026', V.columnsDialog), UI.btn('Sessions', function () { A.nav('sessions'); }), UI.btn('Export\u2026', V.exportDialog), UI.btn('Load\u2026', function () { V.loadDialog(); })], sub);
    b.className += ' page-fill';
    var q = UI.input(g.text, { id: 'quickfilter', className: 'qf', placeholder: 'Quick filter (Ctrl+F) e.g.  class:public status:200 method:POST exec:yes   \u2014  see Help for syntax' });
    var apply = function () { if (A.setGridFilterText(q.value)) { A.nav('grid'); } };
    q.onkeydown = function (e) { if ((e || window.event).keyCode === 13) { apply(); return false; } };
    var presets = UI.select([['', 'Presets\u2026']].concat(F.PRESETS.map(function (p) { return [p.q, p.name]; })).concat((C.cur.data.presets || []).map(function (p) { return [p.q, '\u2605 ' + p.name]; })), '', function (v) { if (v) { q.value = (q.value ? q.value + ' ' : '') + v; apply(); } });
    b.appendChild(h('div', { className: 'row qfrow' }, [q, UI.btn('Apply', apply, 'primary'), UI.btn('Clear', function () { q.value = ''; apply(); }), presets,
      UI.btn('Save preset', function () { if (!q.value) { return; } UI.prompt('Save preset', 'Name for this filter', '', function (n) { if (n) { C.cur.data.presets.push({ name: n, q: q.value }); C.save(); UI.toast('Preset saved'); } }); }),
      UI.btn('Invert', function () { if (!g.model.conds.length) { return; } var t = g.model.conds.map(function (c) { return (c.neg ? '' : '-') + F.describe(c).replace(/^-/, ''); }).join(' '); q.value = t; apply(); }, '', 'Negate every condition (rows NOT matching any... per term)')]));
    // breadcrumbs
    var bc = h('div', { className: 'crumbs' });
    g.model.conds.forEach(function (c, i) {
      bc.appendChild(h('span', { className: 'crumb' + (c.neg ? ' neg' : '') }, [F.describe(c), h('span', { className: 'x', title: 'Remove', onclick: function () { g.model.conds.splice(i, 1); g.text = F.toText(g.model); A.applyGrid(); C.audit('grid.filter', { filter: g.text, rows: g.view.length }); A.nav('grid'); } }, '\u00d7')]));
    });
    bc.appendChild(h('span', { className: 'muted small' }, U.fmtNum(g.view.length) + ' of ' + U.fmtNum(store.n) + ' rows' + (g.ms !== undefined ? ' \u00b7 ' + g.ms + ' ms' : '') + ' \u00b7 sorted by ' + g.sortKey + (g.sortDesc ? ' \u2193' : ' \u2191')));
    b.appendChild(bc);
    var area = h('div', { className: 'grid-area' }), gh = h('div', { className: 'grid-host' }), det = h('div', { className: 'detail grid-detail' });
    area.appendChild(gh); area.appendChild(h('div', { className: 'hsplit', title: 'Drag to resize', onmousedown: function (e) {
      e = e || window.event; var sy = e.clientY, sh = det.offsetHeight;
      document.onmousemove = function (ev) { ev = ev || window.event; det.style.height = Math.max(UI.px(60), Math.min(UI.px(700), sh - (ev.clientY - sy))) + 'px'; st.detH = det.style.height; };
      document.onmouseup = function () { document.onmousemove = null; document.onmouseup = null; if (st.gridCtl) { st.gridCtl.refresh(true); } };
      return false;
    } })); area.appendChild(det);
    if (st.detH) { det.style.height = st.detH; }
    b.appendChild(area);
    var cols = V.gridColumns();
    var tagCache = {};
    var ctl = st.gridCtl = new UI.VGrid(gh, {
      columns: cols, pinned: C.cur.data.pinnedCols || 0, sortKey: g.sortKey, sortDesc: g.sortDesc, emptyText: 'No rows match the filter',
      count: function () { return g.view.length; },
      cell: function (r, k) { return St.colByKey[k].get(store, g.view[r]); },
      rowClass: function (r) {
        var i = g.view[r], s = store.status[i], c = s >= 500 ? 's5' : (s >= 400 ? 's4' : '');
        if (store.flags[i] & St.FLAGS.HITS) { var hs = store.t.hsev.vals[store.hsev[i]], sv = 0, p = hs.split(','), j; for (j = 0; j < p.length; j++) { sv = Math.max(sv, R.SEV[p[j]] || 0); } c += ' hit' + sv; }
        if (C.cur && St.tagText(store, i)) { c += ' tagged'; }
        return c;
      },
      onSort: function (k) { A.sortGrid(k); A.nav('grid'); },
      onSelect: function (r) { V.rowDetail(det, g.view[r]); },
      onActivate: function (r) { A.rawContext(store.file[g.view[r]], store.line[g.view[r]], st.scope ? st.scope.files : null); },
      onContext: function (r, key, x, y) { V.rowMenu(g.view[r], key, x, y); },
      onCopy: function (rows, raw) {
        var out = [], i, j, ix;
        if (rows.length > 100000) { UI.toast('Copy limited to 100,000 rows; use Export for more', 'warn'); rows = rows.slice(0, 100000); }
        if (!raw) { out.push(cols.map(function (c) { return c.label; }).join('\t')); }
        for (i = 0; i < rows.length; i++) {
          ix = g.view[rows[i]];
          if (raw) { out.push(store.raw ? store.raw[ix] : St.colByKey.raw.get(store, ix)); } else { var line = []; for (j = 0; j < cols.length; j++) { line.push(('' + cols[j].get(store, ix)).replace(/[\t\r\n]/g, ' ')); } out.push(line.join('\t')); }
        }
        UI.copy(out.join('\r\n'));
      },
      onColumns: function (cs) { st.columns = cs.map(function (c) { return { key: c.key, w: c.w }; }); C.cur.data.columns = st.columns; C.save(); }
    });
    setTimeout(function () {
      ctl.refresh(true);
      if (g.first) { ctl.scrollTo(g.first); }
      if (g.sel >= 0 && g.sel < g.view.length) { ctl.select(g.sel); } else if (g.view.length) { ctl.select(0); }
      try { ctl.root.focus(); } catch (e) { }
    }, 0);
  };
  V.rowDetail = function (host, i) {
    var store = st.store, A2 = F.storeAccessor(store); A2.i = i;
    UI.clear(host);
    var si = A2.si(), qi = A2.qi(), ui = A2.ui(), ip = A2.eip(), idx = st.idx;
    var ipRec = idx ? idx.ips[ip] : null, stRec = idx ? idx.stems[si.key] : null, hits = A2.hits();
    var stCode = store.status[i] + '.' + Math.max(0, store.sub[i]);
    var file = store.files[store.file[i]], rk = C.rowKey(st.site.name, file.name, store.line[i]);
    var hitsEl = h('span');
    if (hits) { var hsv = (A2.hitSevs ? A2.hitSevs() : '').split(','); hits.split(',').forEach(function (id, hi) { var r = st.ruleset.byId[id], gsv = hsv[hi] || (r ? r.severity : 'info'); hitsEl.appendChild(h('span', { className: 'sev sev-' + gsv, title: (r ? r.description : '') + (r && gsv !== r.severity ? ' (graded ' + gsv + ' for this response; rule default ' + r.severity + ')' : '') }, id)); hitsEl.appendChild(document.createTextNode(' ' + (r ? r.name : '') + '   ')); }); }
    var ioc = st.iocMatcher ? st.iocMatcher.test(A2) : null;
    var left = UI.kv([
      ['Time', U.fmtTs(store.ts[i]) + ' UTC   \u00b7   ' + U.fmtTs(store.ts[i], St.tz) + ' ' + tzLabel()],
      ['Client', [ipLink(ip), '  ' + A2.cls() + (NS.enrich.loaded && NS.enrich.lookup(ip) ? '  \u00b7  ' + NS.enrich.lookup(ip) : '') + (A2.cip() !== ip ? '  (c-ip ' + A2.cip() + ')' : '') + (ipRec ? '  \u00b7  ' + U.fmtNum(ipRec.n) + ' requests ' + U.dayKey(ipRec.first) + ' \u2026 ' + U.dayKey(ipRec.last) : '')]],
      ['Request', A2.method() + ' ' + A2.stem() + (qi.empty ? '' : '?' + A2.query())],
      ['Stem', [stemLink(si.key, si.dec), stRec ? '  \u00b7  first seen ' + U.fmtTs(stRec.first) + ' by ' + stRec.fIp + '  \u00b7  ' + stRec.ipN + (stRec.ipOv ? '+' : '') + ' clients' : '', si.exec ? '  \u00b7  executable' : '', si.upDir ? ' in upload/static dir' : '']],
      qi.empty ? null : ['Query (decoded)', qi.dec + (qi.decErr ? '   [DECODE ERROR]' : '')],
      ['Status', stCode + '  ' + (U.SUBSTATUS[stCode] || '') + '   win32 ' + store.win32[i] + ' ' + (U.WIN32[store.win32[i]] || '') + '   \u00b7   ' + (store.taken[i] >= 0 ? U.fmtNum(store.taken[i]) + ' ms' : '')],
      ['User agent', ui.dec + '   [' + ui.fam + ']'],
      A2.user() !== '-' ? ['Username', A2.user()] : null,
      ['Server', A2.sip() + ':' + store.port[i]],
      ['Rule hits', hits ? hitsEl : 'none'],
      ioc ? ['IOC match', ioc.type + ' ' + ioc.value + (ioc.note ? ' (' + ioc.note + ')' : ''), 'warn'] : null,
      ['Source', file.path + '  line ' + store.line[i]]
    ]);
    var right = h('div', { className: 'det-side' }, [
      h('div', null, [h('b', null, 'Row tags: '), tagChips('rows', rk, function () { V.rowDetail(host, i); if (st.gridCtl) { st.gridCtl.render(); } })]),
      h('div', null, [h('b', null, 'IP tags: '), tagChips('ips', ip, function () { V.rowDetail(host, i); if (st.gridCtl) { st.gridCtl.render(); } })]),
      h('div', null, [h('b', null, 'Stem tags: '), tagChips('stems', si.key, function () { V.rowDetail(host, i); if (st.gridCtl) { st.gridCtl.render(); } })]),
      h('div', { className: 'row mt' }, [UI.btn('Raw context', function () { A.rawContext(store.file[i], store.line[i], st.scope ? st.scope.files : null); }), UI.btn('\u00b15 min', function () { V.aroundRow(i, 5); }), UI.btn('Bookmark', function () { UI.prompt('Bookmark', 'Label', A2.method() + ' ' + A2.stem(), function (v) { C.cur.data.bookmarks.push({ ts: store.ts[i], label: v, ref: file.name + ':' + store.line[i], ip: ip }); C.save(); C.audit('bookmark', { ref: file.name + ':' + store.line[i] }); UI.toast('Bookmarked'); }); })]),
      notesBox('row', rk)
    ]);
    host.appendChild(h('div', { className: 'det-cols' }, [h('div', { className: 'det-main' }, left), right]));
    host.appendChild(h('div', { className: 'rawline' }, store.raw ? store.raw[i] : '(raw line not retained \u2014 use Raw context)'));
  };
  V.aroundRow = function (i, min) {
    var t = st.store.ts[i], a = t - min * 60000, z = t + min * 60000;
    var g = st.grid;
    g.model.conds = g.model.conds.filter(function (c) { return c.f !== 'time'; });
    A.addGridCond({ f: 'time', op: 'between', v: [a, z], text: 'after:"' + U.fmtTs(a) + 'Z" before:"' + U.fmtTs(z) + 'Z"' });
    A.nav('grid');
  };
  V.rowMenu = function (i, key, x, y) {
    var store = st.store, A2 = F.storeAccessor(store); A2.i = i;
    var ip = A2.eip(), si = A2.si(), stc = store.status[i] + '.' + Math.max(0, store.sub[i]), ua = A2.ui();
    function q(s) { return s.indexOf(' ') >= 0 || s.indexOf('"') >= 0 ? '"' + s.replace(/"/g, '') + '"' : s; }
    function add(t) { if (A.setGridFilterText((st.grid.text ? st.grid.text + ' ' : '') + t)) { A.nav('grid'); } }
    var hr = new Date(store.ts[i] + U.tzOff(St.tz, store.ts[i]) * 60000).getUTCHours();
    var val = key && St.colByKey[key] ? '' + St.colByKey[key].get(store, i) : '';
    UI.menu(x, y, [
      { header: 'Filter to' },
      { label: 'Client ' + ip, onClick: function () { add('cip:' + ip); } },
      { label: 'Stem ' + (si.dec.length > 50 ? si.dec.substr(0, 50) + '\u2026' : si.dec), onClick: function () { add('stem:=' + q(A2.stem())); } },
      { label: 'Status ' + stc, onClick: function () { add('status:' + stc); } },
      { label: 'UA family ' + ua.fam, onClick: function () { add('family:' + ua.fam); } },
      { label: 'Same user agent', onClick: function () { add(V.uaFilter(ua.dec)); } },
      { label: 'Hour ' + hr + ' (local)', onClick: function () { add('hour:' + hr); } },
      { label: '\u00b15 minutes around this row', onClick: function () { V.aroundRow(i, 5); } },
      { header: 'Exclude' },
      { label: 'Exclude client ' + ip, onClick: function () { add('-cip:' + ip); } },
      { label: 'Exclude this stem', onClick: function () { add('-stem:=' + q(A2.stem())); } },
      { label: 'Exclude status ' + stc, onClick: function () { add('-status:' + stc); } },
      { label: 'Exclude this user agent', onClick: function () { add('-' + V.uaFilter(ua.dec)); } },
      { sep: true },
      { label: 'IP profile', onClick: function () { A.nav('ipProfile', ip); } },
      { label: 'URI profile', onClick: function () { A.nav('uriProfile', si.key); } },
      { label: 'User agent details', onClick: function () { A.nav('uas', A2.ua()); } },
      { label: 'Raw context (\u00b150 lines)', onClick: function () { A.rawContext(store.file[i], store.line[i], st.scope ? st.scope.files : null); } },
      { label: 'Tag row as Attacker', onClick: function () { C.setTag('rows', C.rowKey(st.site.name, store.files[store.file[i]].name, store.line[i]), 'Attacker', true); C.save(); C.audit('tag', { kind: 'rows', tag: 'Attacker' }); st.gridCtl.render(); } },
      { label: 'Tag IP ' + ip + ' as Attacker', onClick: function () { C.setTag('ips', ip, 'Attacker', true); C.save(); C.audit('tag', { kind: 'ips', key: ip, tag: 'Attacker' }); st.gridCtl.render(); } },
      { label: 'Add note\u2026', onClick: function () { UI.prompt('Note', 'Note for this row', '', function (v) { if (v) { C.addNote('row', C.rowKey(st.site.name, store.files[store.file[i]].name, store.line[i]), v); } }, true); } },
      { sep: true },
      { label: 'Copy cell value', disabled: !val, onClick: function () { UI.copy(val); } },
      { label: 'Copy selected rows (TSV)', onClick: function () { st.gridCtl.o.onCopy(st.gridCtl.selection(), false); } },
      { label: 'Copy selected raw lines', onClick: function () { st.gridCtl.o.onCopy(st.gridCtl.selection(), true); } }
    ]);
  };
  V.columnsDialog = function () {
    var cfg = (st.columns || []).slice(0), shown = {}, i, list = h('div', { className: 'collist' });
    cfg.forEach(function (c) { shown[c.key] = c; });
    var order = cfg.map(function (c) { return c.key; });
    St.COLUMNS.forEach(function (c) { if (order.indexOf(c.key) < 0) { order.push(c.key); } });
    function draw() {
      UI.clear(list);
      order.forEach(function (k, ix) {
        var c = St.colByKey[k], cb = h('input', { type: 'checkbox', checked: !!shown[k] });
        cb.onclick = function () { if (cb.checked) { shown[k] = { key: k, w: c.w }; } else { delete shown[k]; } };
        list.appendChild(h('div', { className: 'colrow' }, [cb, ' ' + c.label + ' ', UI.link('\u25b2', function () { if (ix > 0) { order.splice(ix, 1); order.splice(ix - 1, 0, k); draw(); } }), ' ', UI.link('\u25bc', function () { if (ix < order.length - 1) { order.splice(ix, 1); order.splice(ix + 1, 0, k); draw(); } })]));
      });
    }
    draw();
    var pinIn = UI.input(C.cur.data.pinnedCols || 0, { style: { width: '40px' } });
    UI.dialog({ title: 'Grid columns', body: [UI.field('Pin the first N visible columns', pinIn), list], width: 380, height: 460, buttons: [{ label: 'Apply', primary: true, onClick: function () {
      st.columns = order.filter(function (k) { return shown[k]; }).map(function (k) { return { key: k, w: shown[k].w }; });
      if (!st.columns.length) { st.columns = [{ key: 'ts', w: 140 }]; }
      C.cur.data.pinnedCols = Math.max(0, Math.min(5, parseInt(pinIn.value, 10) || 0));
      C.cur.data.columns = st.columns; C.save(); A.nav('grid');
    } }, { label: 'Reset', onClick: function () { st.columns = null; C.cur.data.columns = null; C.save(); A.nav('grid'); } }, { label: 'Cancel' }] });
  };

  /* ======================= TOP-N ======================= */
  V.topn = function (main) {
    var cfg = st.topnCfg || (st.topnCfg = { scope: st.store ? 'loaded' : 'index', dim: 'cip', sort: 'rows', cls: '', n: 100 });
    if (!st.idx && !st.store) { needIndex(main, 'Top-N'); return; }
    var b = page(main, 'Top-N');
    var idxDims = [['cip', 'Client IP'], ['stem', 'URI stem'], ['ua', 'User agent'], ['status', 'Status'], ['method', 'Method'], ['ext', 'Extension'], ['sport', 'Server IP:port'], ['fam', 'UA family'], ['user', 'Username'], ['rule', 'Rule hit']];
    var dims = cfg.scope === 'index' ? idxDims : St.DIMENSIONS;
    var measures = [['rows', 'Rows'], ['ips', 'Distinct IPs'], ['stems', 'Distinct stems'], ['s4', '4xx'], ['s5', '5xx'], ['post', 'POST'], ['avg', 'Avg time-taken'], ['max', 'Max time-taken'], ['first', 'First seen'], ['last', 'Last seen'], ['hits', 'Rule-hit rows']];
    var nIn = UI.input(cfg.n, { style: { width: '60px' } });
    b.appendChild(h('div', { className: 'row' }, [
      UI.field('Scope', UI.select([['index', 'Whole corpus (index)'], ['loaded', 'Loaded rows (current grid filter)']], cfg.scope, function (v) { cfg.scope = v; if (v === 'index' && !idxDims.some(function (d) { return d[0] === cfg.dim; })) { cfg.dim = 'cip'; } A.nav('topn'); })),
      UI.field('Dimension', UI.select(dims, cfg.dim, function (v) { cfg.dim = v; A.nav('topn'); })),
      UI.field('Sort by', UI.select(measures, cfg.sort, function (v) { cfg.sort = v; A.nav('topn'); })),
      UI.field('Client class', UI.select([['', 'All'], ['public', 'Public only'], ['internal', 'Internal only']], cfg.cls, function (v) { cfg.cls = v; A.nav('topn'); })),
      UI.field('N', nIn), UI.btn('Apply', function () { cfg.n = Math.max(1, Math.min(5000, parseInt(nIn.value, 10) || 100)); A.nav('topn'); }),
      UI.btn('Export CSV', function () { V.exportDialog(); })
    ]));
    var rows = [], approx = '';
    if (cfg.scope === 'index') {
      if (!st.idx) { b.appendChild(h('p', null, 'Scan first.')); return; }
      var idx = st.idx, k, r;
      if (cfg.dim === 'cip') { for (k in idx.ips) { r = idx.ips[k]; if (cfg.cls === 'public' && r.cls !== 'public') { continue; } if (cfg.cls === 'internal' && !U.isInternalClass(r.cls)) { continue; } rows.push({ key: k, rows: r.n, ips: 1, stems: r.stN + (r.stOv ? 0.5 : 0), s4: r.s4, s5: r.s5, post: r.post, first: r.first, last: r.last, hits: U.countKeys(r.hits) ? Object.keys(r.hits).reduce(function (a, x) { return a + r.hits[x]; }, 0) : 0, extra: r.cls }); } approx = idx.caps.ipEvicted ? 'approximate (IP cap reached)' : ''; }
      else if (cfg.dim === 'stem') { for (k in idx.stems) { r = idx.stems[k]; if (cfg.cls === 'public' && !r.pubN) { continue; } rows.push({ key: r.raw, k2: k, rows: r.n, ips: r.ipN + (r.ipOv ? 0.5 : 0), stems: 1, s4: r.s4, s5: r.s5, post: r.post, first: r.first, last: r.last, hits: 0, extra: r.exec ? 'exec' : '' }); } approx = idx.caps.stemEvicted ? 'approximate (stem cap reached)' : ''; }
      else if (cfg.dim === 'ua') { for (k in idx.uas) { r = idx.uas[k]; rows.push({ key: k === '-' ? '(empty)' : k.replace(/\+/g, ' '), rows: r.n, ips: r.ipN + (r.ipOv ? 0.5 : 0), first: r.first, last: r.last, extra: r.fam }); } }
      else if (cfg.dim === 'rule') { for (k in idx.ruleHits) { r = idx.ruleHits[k]; rows.push({ key: k, rows: r.n, ips: r.ipN, stems: r.stN, first: r.first, last: r.last, extra: (st.ruleset.byId[k] || {}).name }); } }
      else {
        var map = { status: idx.statuses, method: idx.methods, ext: idx.exts, sport: idx.sports, fam: idx.uaFams, user: null }[cfg.dim];
        if (cfg.dim === 'user') { for (k in idx.users) { r = idx.users[k]; rows.push({ key: k, rows: r.n, ips: r.ipN, first: r.first, last: r.last }); } } else { for (k in map) { rows.push({ key: k, rows: map[k] }); } }
      }
    } else {
      if (!st.store) { b.appendChild(h('p', null, 'No rows loaded.')); return; }
      var view = st.grid.view || F.apply(st.store, null), t0 = Date.now(), cv = view;
      if (cfg.cls) { var tmp = [], j; for (j = 0; j < view.length; j++) { var pubf = st.store.flags[view[j]] & St.FLAGS.PUB, intf = st.store.flags[view[j]] & St.FLAGS.INTERNAL; if ((cfg.cls === 'public' && pubf) || (cfg.cls === 'internal' && intf)) { tmp.push(view[j]); } } cv = tmp; }
      var groups = St.topN(st.store, cv, cfg.dim);
      groups.forEach(function (g) { rows.push({ key: g.key, rows: g.rows, ips: g.ipN, stems: g.stN, s4: g.s4, s5: g.s5, post: g.post, avg: g.avgTaken, max: g.takenMax, first: g.first, last: g.last, hits: g.hits }); });
      approx = 'computed over ' + U.fmtNum(cv.length) + ' rows in ' + U.fmtDuration(Date.now() - t0);
    }
    var sk = cfg.sort;
    rows.sort(function (a, c) { var x = a[sk] || 0, y = c[sk] || 0; return sk === 'first' ? x - y : y - x; });
    var total = rows.length; rows = rows.slice(0, cfg.n);
    b.appendChild(h('div', { className: 'muted small' }, U.fmtNum(total) + ' distinct values' + (approx ? ' \u00b7 ' + approx : '') + ' \u00b7 double-click a row to pivot'));
    var cols = [{ key: 'rank', label: '#', w: 44, num: true }, { key: 'key', label: (dims.filter(function (d) { return d[0] === cfg.dim; })[0] || [0, 'Value'])[1], w: 420 }, { key: 'extra', label: 'Info', w: 90 }, { key: 'rows', label: 'Rows', w: 80, num: true }, { key: 'ips', label: 'IPs', w: 60, num: true },
      { key: 'stems', label: 'Stems', w: 60, num: true }, { key: 's4', label: '4xx', w: 70, num: true }, { key: 's5', label: '5xx', w: 60, num: true }, { key: 'post', label: 'POST', w: 70, num: true },
      { key: 'avg', label: 'Avg ms', w: 70, num: true }, { key: 'max', label: 'Max ms', w: 80, num: true }, { key: 'first', label: 'First (UTC)', w: 135 }, { key: 'last', label: 'Last (UTC)', w: 135 }, { key: 'hits', label: 'Hit rows', w: 70, num: true }];
    function cellv(r, k) {
      var o = rows[r], v = o[k];
      if (k === 'rank') { return '' + (r + 1); }
      if (v === undefined || v === null) { return ''; }
      if (k === 'first' || k === 'last') { return tsCell(v); }
      if (k === 'ips' || k === 'stems') { return v % 1 ? Math.floor(v) + '+' : U.fmtNum(v); }
      if (typeof v === 'number') { return U.fmtNum(v); }
      return v;
    }
    st.topnLast = { title: 'Top ' + cfg.n + ' ' + cfg.dim + ' by ' + cfg.sort + ' (' + cfg.scope + ')', headers: cols.map(function (c) { return c.label; }), rows: rows.map(function (o, r) { return cols.map(function (c) { return cellv(r, c.key); }); }) };
    var host = h('div', { className: 'grid-host tall' });
    b.appendChild(host);
    new UI.VGrid(host, { columns: cols, count: function () { return rows.length; }, cell: cellv,
      onActivate: function (r) {
        var o = rows[r], key = o.k2 || o.key, dmap = { cip: 'cip:', eip: 'cip:', stem: 'stem:=', status: 'status:', method: 'method:', fam: 'family:', ext: 'ext:', user: 'user:=', cls: 'class:', rule: 'rule:', dir: 'dir:', file: 'file:', hour: 'hour:', query: 'query:=' };
        if (cfg.scope === 'index' && cfg.dim === 'cip') { A.nav('ipProfile', key); return; }
        if (cfg.scope === 'index' && cfg.dim === 'stem') { A.nav('uriProfile', o.k2); return; }
        if (cfg.dim === 'ua') { A.pivot(V.uaFilter(o.key === '(empty)' ? '' : o.key), 'top-n ua'); return; }
        var pre = dmap[cfg.dim]; if (!pre) { UI.toast('No pivot for this dimension', 'warn'); return; }
        var val = cfg.dim === 'hour' ? '' + (+o.key) : (cfg.dim === 'dow' ? o.key.charAt(0) : o.key);
        A.pivot(pre + (/[\s"]/.test(val) ? '"' + val.replace(/"/g, '') + '"' : val), 'top-n ' + cfg.dim);
      }
    });
  };

  /* ======================= TIMELINE ======================= */
  V.timeline = function (main) {
    if (!st.idx && !st.store) { needIndex(main, 'Timeline'); return; }
    var cfg = st.tlCfg || (st.tlCfg = { scope: st.store ? 'loaded' : 'index', bucket: 'auto', series: ['', 'class:public', 'status:5xx', 'rule:any'] });
    var b = page(main, 'Timeline');
    var ins = cfg.series.map(function (s) { return UI.input(s, { style: { width: '220px' }, placeholder: 'quick filter (empty = all rows)' }); });
    b.appendChild(h('div', { className: 'row' }, [
      UI.field('Scope', UI.select([['index', 'Whole corpus (index)'], ['loaded', 'Loaded rows (grid view)']], cfg.scope, function (v) { cfg.scope = v; A.nav('timeline'); })),
      UI.field('Bucket', UI.select([['auto', 'Auto'], ['60000', '1 minute'], ['900000', '15 minutes'], ['3600000', '1 hour'], ['86400000', '1 day'], ['604800000', '1 week']], cfg.bucket, function (v) { cfg.bucket = v; A.nav('timeline'); }))
    ]));
    if (cfg.scope === 'loaded') {
      b.appendChild(h('div', { className: 'row' }, ins.map(function (inp, i) { return UI.field('Series ' + (i + 1), inp); }).concat([UI.btn('Apply', function () { cfg.series = ins.map(function (x) { return x.value; }); A.nav('timeline'); }, 'primary')])));
    }
    var host = h('div', { className: 'chart-host' }), info = h('div', { className: 'muted small' });
    b.appendChild(UI.section('Requests over time (UTC) \u2014 drag to filter the grid / load that range; shaded columns mark restarts (grey) and gaps (red)', [host, info]));
    var labels = [], series = [], markers = [], bucket, t0, nb, i;
    if (cfg.scope === 'index') {
      if (!st.idx) { b.appendChild(h('p', null, 'Scan first.')); return; }
      var idx = st.idx, span = idx.totals.lastTs - idx.totals.firstTs;
      bucket = cfg.bucket === 'auto' ? (span > 120 * 86400000 ? 604800000 : (span > 3 * 86400000 ? 86400000 : 3600000)) : Math.max(3600000, +cfg.bucket);
      t0 = Math.floor(idx.totals.firstTs / bucket) * bucket; nb = Math.min(5000, Math.floor((idx.totals.lastTs - t0) / bucket) + 1);
      var s = [[], [], [], []]; for (i = 0; i < nb; i++) { s[0].push(0); s[1].push(0); s[2].push(0); s[3].push(0); }
      var k, src = bucket >= 86400000 ? idx.perDay : idx.perHour;
      for (k in src) {
        var ms = bucket >= 86400000 ? U.dayKeyToMs(k) : U.hourKeyToMs(k), bi = Math.floor((ms - t0) / bucket);
        if (bi < 0 || bi >= nb) { continue; }
        var v = src[k];
        if (bucket >= 86400000) { s[0][bi] += v[0] - v[5] - v[6]; s[1][bi] += v[5]; s[2][bi] += v[4]; s[3][bi] += v[7]; } else { s[0][bi] += v[0] - v[2] - v[3]; s[1][bi] += v[2]; s[2][bi] += v[1]; s[3][bi] += v[4]; }
      }
      series = [{ name: 'internal/other', color: UI.COLORS.int, values: s[0] }, { name: 'external', color: UI.COLORS.ext, values: s[1] }, { name: '5xx', color: UI.COLORS.s5, values: s[2] }, { name: 'rule hits', color: UI.COLORS.hits, values: s[3] }];
      idx.restarts.forEach(function (r) { var bi2 = Math.floor((r.ts - t0) / bucket); if (bi2 >= 0 && bi2 < nb) { markers.push({ i: bi2, color: '#718096', title: 'restart ' + r.date }); } });
      idx.gaps.forEach(function (g) { var a = Math.floor((g.from - t0) / bucket), z = Math.floor((g.to - t0) / bucket); for (var q = Math.max(0, a); q <= Math.min(nb - 1, z); q++) { markers.push({ i: q, color: '#c53030', title: 'gap ' + g.hours.toFixed(1) + ' h' }); } });
    } else {
      if (!st.store) { b.appendChild(h('p', null, 'No rows loaded.')); return; }
      var view = st.grid.view, store = st.store, mn = Infinity, mx = -Infinity, j;
      for (j = 0; j < view.length; j++) { var tt = store.ts[view[j]]; if (tt < mn) { mn = tt; } if (tt > mx) { mx = tt; } }
      if (!view.length) { b.appendChild(h('p', null, 'Grid view is empty.')); return; }
      var spn = mx - mn;
      bucket = cfg.bucket === 'auto' ? [60000, 300000, 900000, 3600000, 21600000, 86400000, 604800000].filter(function (x) { return spn / x <= 600; })[0] || 604800000 : +cfg.bucket;
      t0 = Math.floor(mn / bucket) * bucket; nb = Math.min(20000, Math.floor((mx - t0) / bucket) + 1);
      var Ax = F.storeAccessor(store), env = A.filterEnv();
      cfg.series.forEach(function (q, si) {
        var pred = null; try { pred = q ? F.compile(F.parse(q, St.tz), env) : null; } catch (e) { UI.toast('Series ' + (si + 1) + ': ' + e.message, 'error'); return; }
        var vals = []; for (i = 0; i < nb; i++) { vals.push(0); }
        for (j = 0; j < view.length; j++) { Ax.i = view[j]; if (pred && !pred(Ax)) { continue; } var bi3 = Math.floor((store.ts[view[j]] - t0) / bucket); if (bi3 >= 0 && bi3 < nb) { vals[bi3]++; } }
        series.push({ name: q || 'all rows', color: UI.COLORS.series[si], values: vals });
      });
    }
    for (i = 0; i < nb; i++) { labels.push(bucket >= 86400000 ? U.dayKey(t0 + i * bucket) : U.fmtTs(t0 + i * bucket).substr(0, 16)); }
    UI.text(info, U.fmtNum(nb) + ' buckets of ' + U.fmtDuration(bucket) + ' from ' + U.fmtTs(t0) + ' UTC' + (nb >= 5000 ? ' (truncated)' : ''));
    setTimeout(function () {
      UI.barChart(host, { labels: labels, series: series, stacked: false, height: 300, markers: markers, onBrush: function (a, z) {
        var from = t0 + a * bucket, to = t0 + (z + 1) * bucket - 1;
        if (cfg.scope === 'loaded') { var g = st.grid; g.model.conds = g.model.conds.filter(function (c) { return c.f !== 'time'; }); A.addGridCond({ f: 'time', op: 'between', v: [from, to], text: 'after:"' + U.fmtTs(from) + 'Z" before:"' + U.fmtTs(to + 1) + 'Z"' }); A.nav('grid'); } else { V.loadDialog({ from: from, to: to, label: 'timeline range' }); }
      } });
    }, 10);
  };

  /* ======================= IPs ======================= */
  V.ips = function (main) {
    if (!st.idx) { needIndex(main, 'Client IPs'); return; }
    var cfg = st.ipCfg || (st.ipCfg = { q: '', cls: '', sort: 'n' }), idx = st.idx;
    var b = page(main, 'Client IPs', null, U.fmtNum(idx.counts.ips) + ' distinct effective client addresses in the index');
    var q = UI.input(cfg.q, { placeholder: 'IP substring or CIDR', style: { width: '200px' } });
    var go = function () { cfg.q = q.value; A.nav('ips'); };
    q.onkeydown = function (e) { if ((e || window.event).keyCode === 13) { go(); } };
    b.appendChild(h('div', { className: 'row' }, [UI.field('Search', q), UI.field('Class', UI.select([['', 'All']].concat(U.IP_CLASSES), cfg.cls, function (v) { cfg.cls = v; A.nav('ips'); })),
      UI.field('Sort', UI.select([['n', 'Requests'], ['first', 'First seen'], ['last', 'Last seen'], ['s4r', '4xx share'], ['hits', 'Rule hits'], ['post', 'POST'], ['tags', 'Tagged first']], cfg.sort, function (v) { cfg.sort = v; A.nav('ips'); })), UI.btn('Search', go, 'primary')]));
    var list = [], k, r, cidr = cfg.q.indexOf('/') > 0 ? U.parseCidr(cfg.q) : null, ql = cfg.q.toLowerCase();
    for (k in idx.ips) {
      r = idx.ips[k];
      if (cfg.cls && r.cls !== cfg.cls) { continue; }
      if (cidr ? !U.cidrMatch(cidr, k) : (ql && k.toLowerCase().indexOf(ql) < 0)) { continue; }
      list.push(k);
    }
    function hitsN(x) { var s = 0, z; for (z in idx.ips[x].hits) { s += idx.ips[x].hits[z]; } return s; }
    var sorters = { n: function (a, c) { return idx.ips[c].n - idx.ips[a].n; }, first: function (a, c) { return idx.ips[a].first - idx.ips[c].first; }, last: function (a, c) { return idx.ips[c].last - idx.ips[a].last; },
      s4r: function (a, c) { return idx.ips[c].s4 / idx.ips[c].n - idx.ips[a].s4 / idx.ips[a].n; }, hits: function (a, c) { return hitsN(c) - hitsN(a); }, post: function (a, c) { return idx.ips[c].post - idx.ips[a].post; },
      tags: function (a, c) { return C.getTags('ips', c).length - C.getTags('ips', a).length || idx.ips[c].n - idx.ips[a].n; } };
    list.sort(sorters[cfg.sort] || sorters.n);
    b.appendChild(h('div', { className: 'muted small' }, U.fmtNum(list.length) + ' match \u00b7 double-click for profile'));
    var host = h('div', { className: 'grid-host tall' }); b.appendChild(host);
    var cols = [{ key: 'ip', label: 'IP', w: 150 }, { key: 'cls', label: 'Class', w: 75 }, { key: 'n', label: 'Requests', w: 80, num: true }, { key: 'first', label: 'First (UTC)', w: 135 }, { key: 'last', label: 'Last (UTC)', w: 135 },
      { key: 's2', label: '2xx', w: 65, num: true }, { key: 's4', label: '4xx', w: 65, num: true }, { key: 's5', label: '5xx', w: 55, num: true }, { key: 'post', label: 'POST', w: 65, num: true }, { key: 'stems', label: 'Stems', w: 60, num: true },
      { key: 'uas', label: 'UAs', w: 45, num: true }, { key: 'hits', label: 'Rule hits', w: 260 }, { key: 'tags', label: 'Tags', w: 120 }, { key: 'ioc', label: 'IOC', w: 50 }];
    if (NS.enrich.loaded) { cols.splice(2, 0, { key: 'asn', label: 'ASN / Geo', w: 220 }); }
    new UI.VGrid(host, { columns: cols, count: function () { return list.length; },
      cell: function (ri, c) {
        var ip = list[ri], x = idx.ips[ip];
        switch (c) {
          case 'ip': return ip; case 'cls': return x.cls; case 'n': return U.fmtNum(x.n); case 'first': return tsCell(x.first); case 'last': return tsCell(x.last);
          case 's2': return U.fmtNum(x.s2); case 's4': return U.fmtNum(x.s4); case 's5': return U.fmtNum(x.s5); case 'post': return U.fmtNum(x.post);
          case 'stems': return x.stN + (x.stOv ? '+' : ''); case 'uas': return x.uaN + (x.uaOv ? '+' : ''); case 'hits': return Object.keys(x.hits).map(function (z) { return z + '\u00d7' + x.hits[z]; }).join(' ');
          case 'tags': return C.getTags('ips', ip).join(', '); case 'ioc': return st.iocMatcher && st.iocMatcher.ipHit(ip) ? 'IOC' : ''; case 'asn': return NS.enrich.lookup(ip);
        }
        return '';
      },
      rowClass: function (ri) { var x = idx.ips[list[ri]], c = C.getTags('ips', list[ri]).length ? 'tagged' : ''; if (U.countKeys(x.hits)) { c += ' hit2'; } return c; },
      onActivate: function (ri) { A.nav('ipProfile', list[ri]); },
      onContext: function (ri, key, x, y) { var ip = list[ri]; UI.menu(x, y, [{ label: 'IP profile', onClick: function () { A.nav('ipProfile', ip); } }, { label: 'Load all rows for ' + ip, onClick: function () { A.loadWhere('cip:' + ip, 'ip ' + ip, A.fileIdsForRange(idx.ips[ip].first, idx.ips[ip].last)); } }, { label: 'Tag as Attacker', onClick: function () { C.setTag('ips', ip, 'Attacker', true); C.save(); C.audit('tag', { kind: 'ips', key: ip, tag: 'Attacker' }); A.nav('ips'); } }, { label: 'Copy IP', onClick: function () { UI.copy(ip); } }]); }
    });
  };
  V.ipProfile = function (main, ip) {
    if (!st.idx) { needIndex(main, 'IP profile'); return; }
    var idx = st.idx, r = idx.ips[ip];
    var b = page(main, 'IP profile \u2014 ' + ip, [UI.btn('\u2190 Client IPs', function () { A.nav('ips'); }), UI.btn('Load all rows for this IP', function () { A.loadWhere('cip:' + ip, 'ip ' + ip, r ? A.fileIdsForRange(r.first, r.last) : A.allFileIds()); }, 'primary'),
      st.store ? UI.btn('Filter grid to IP', function () { A.pivot('cip:' + ip); }) : null, UI.btn('Reverse DNS\u2026', function () { V.reverseDns(ip); }), UI.btn('Copy', function () { UI.copy(ip); })]);
    if (!r) { b.appendChild(h('p', null, 'This address is not in the index (it may have been evicted by the IP cap, or it never appears as a client).')); return; }
    var hitsTot = 0, z; for (z in r.hits) { hitsTot += r.hits[z]; }
    var ioc = st.iocMatcher ? st.iocMatcher.ipHit(ip) : null;
    var methods = topList(r.m, 10).map(function (m) { return m + ' ' + U.fmtNum(r.m[m]); }).join(', ');
    b.appendChild(h('div', { className: 'cards' }, [UI.card('Class', r.cls, U.classifyIp(ip) !== r.cls ? 'raw ' + U.classifyIp(ip) : ''), UI.card('Requests', U.fmtNum(r.n), methods),
      UI.card('Active', U.dayKey(r.first) + ' \u2026 ' + U.dayKey(r.last), U.fmtDuration(r.last - r.first)), UI.card('Status mix', U.pct(r.s2, r.n) + ' 2xx', U.pct(r.s4, r.n) + ' 4xx \u00b7 ' + U.pct(r.s5, r.n) + ' 5xx'),
      UI.card('Rule hits', U.fmtNum(hitsTot), Object.keys(r.hits).length + ' rules', hitsTot ? 'hot' : ''), ioc ? UI.card('IOC', ioc.value, ioc.note, 'hot') : null,
      NS.enrich.loaded ? UI.card('ASN / Geo (offline CSV)', NS.enrich.lookup(ip) || 'no match', U.baseOf(NS.enrich.path)) : null]));
    b.appendChild(h('div', null, [h('b', null, 'Tags: '), tagChips('ips', ip, function () { A.nav('ipProfile', ip); })]));
    b.appendChild(notesBox('ip', ip));
    // activity by day
    var dk = Object.keys(r.d).sort(), sp = h('div', { className: 'chart-host' });
    b.appendChild(UI.section('Requests per day (' + dk.length + ' active days' + (r.dOv ? ', more not tracked' : '') + ')', sp));
    setTimeout(function () { UI.barChart(sp, { labels: dk, series: [{ name: 'requests', color: UI.COLORS.ext, values: dk.map(function (d) { return r.d[d]; }) }], height: 140, onClick: function (i) { var a = U.dayKeyToMs(dk[i]); A.load({ fileIds: A.fileIdsForRange(a, a + 86399999), from: a, to: a + 86399999, preText: 'cip:' + ip, label: ip + ' ' + dk[i] }); } }); }, 10);
    var stems = topList(r.st, 50);
    var hitsRows = Object.keys(r.hits).map(function (id) { var rr = st.ruleset.byId[id] || {}; return [UI.sevBadge(rr.severity || 'info'), id, rr.name || '', U.fmtNum(r.hits[id])]; });
    var related = V.relatedIps(ip);
    b.appendChild(h('div', { className: 'cols2' }, [
      UI.section('Top paths (' + r.stN + (r.stOv ? '+, ' + U.fmtNum(r.stOv) + ' requests to untracked paths' : '') + ')', UI.table(['Stem', 'Requests'], stems.map(function (s) { return [stemLink(s, (idx.stems[s] || {}).raw || s), U.fmtNum(r.st[s])]; }))),
      h('div', null, [UI.section('Rule hits', hitsRows.length ? UI.table(['Sev', 'Rule', 'Name', 'Rows'], hitsRows) : h('p', { className: 'muted' }, 'None')),
        UI.section('User agents' + (r.uaOv ? ' (first ' + r.uaN + ' tracked)' : ''), UI.table(['User agent', 'Flags', 'Requests'], topList(r.ua, 20).map(function (u) {
          var dec = NS.useragent.decodeKey(u), ur = idx.uas[u], fl = NS.useragent.at(NS.useragent.info(dec), ur ? ur.first : r.first).flags;
          if (dec && NS.useragent.isRare(ur)) { fl.push('rare'); }
          return [UI.link(dec || '(empty)', function () { A.nav('uas', u); }, 'User agent details'), h('span', { style: { wordBreak: 'normal' } }, fl.join(' ')), U.fmtNum(r.ua[u])];
        }))),
        UI.section('Windows', UI.kv([['Max distinct paths / 5 min', r.ms5 + (r.ms5t ? ' at ' + U.fmtTs(r.ms5t) : '')], ['Max login POSTs / window', r.mlogin + (r.mlogint ? ' at ' + U.fmtTs(r.mlogint) : '')], ['Max 401 / window', '' + r.m401], ['Max UAs in a day', r.muaDay + (r.muaDayD ? ' on ' + r.muaDayD : '')], ['First exploit-rule hit', r.firstExp ? U.fmtTs(r.firstExp) : 'none']])),
        UI.section('Related IPs (share a rare user agent or rare path)', related.length ? UI.table(['IP', 'Shared', 'Requests'], related.slice(0, 30).map(function (x) { return [ipLink(x.ip), x.why, U.fmtNum((idx.ips[x.ip] || {}).n || 0)]; })) : h('p', { className: 'muted' }, 'None found'))])
    ]));
    if (st.store) {
      var sid = st.store.t.ip.find(ip);
      if (sid >= 0) {
        var vv = [], j; for (j = 0; j < st.store.n; j++) { if (st.store.eip[j] === sid) { vv.push(j); } }
        var ss = St.sessions(st.store, vv, st.settings.sessionIdleMinutes);
        b.appendChild(UI.section('Sessions in loaded rows (' + ss.length + ')', UI.table(['#', 'Start (UTC)', 'Duration', 'Rows', 'Stems', '2xx/4xx/5xx', 'Exec POST', 'UA'], ss.slice(0, 50).map(function (s) { return [s.id, tsCell(s.start), U.fmtDuration(s.duration), s.rows, s.stems, s.s2 + '/' + s.s4 + '/' + s.s5, s.execPost, s.ua]; }))));
      }
    }
  };
  V.relatedIps = function (ip) {
    var idx = st.idx, r = idx.ips[ip], out = {}, k, i;
    if (!r) { return []; }
    for (k in r.ua) { var u = idx.uas[k]; if (u && !u.ipOv && u.ipN <= 5 && k !== '-') { for (i in u.ips) { if (i !== ip) { out[i] = (out[i] ? out[i] + '; ' : '') + 'UA ' + k.replace(/\+/g, ' ').substr(0, 60); } } } }
    for (k in r.st) { var s = idx.stems[k]; if (s && !s.ipOv && s.ipN <= 5) { for (i in s.ips) { if (i !== ip) { out[i] = (out[i] ? out[i] + '; ' : '') + 'path ' + s.raw.substr(0, 60); } } } }
    var list = []; for (k in out) { list.push({ ip: k, why: out[k] }); }
    return list;
  };
  V.reverseDns = function (ip) {
    if (!U.isValidIp(ip)) { return; }
    UI.confirm('Reverse DNS (network action)', 'This sends a PTR query for ' + ip + ' to your configured DNS resolver.\n\nOPSEC: an attacker controlling the reverse zone can see the lookup, and the resolver logs your investigation. Only continue if this is acceptable for the case.', function () {
      var tmp = U.joinPath(C.cur.tmp, 'nslookup-' + Date.now() + '.txt');
      U.shell().Run('cmd.exe /c nslookup ' + ip + ' > "' + tmp + '" 2>&1', 0, true);
      var out = ''; try { out = U.readTextUtf8(tmp); U.fso().DeleteFile(tmp, true); } catch (e) { out = e.message; }
      C.audit('network.reverseDns', { ip: ip, result: out.substr(0, 1000) });
      UI.alert('nslookup ' + ip, out);
    }, 'Send query');
  };

  /* ======================= URIs ======================= */
  V.uris = function (main) {
    if (!st.idx) { needIndex(main, 'URI stems'); return; }
    var cfg = st.uriCfg || (st.uriCfg = { q: '', exec: false, pub200: false, after: '', sort: 'n' }), idx = st.idx;
    var b = page(main, 'URI stems', null, U.fmtNum(idx.counts.stems) + ' distinct stems in the index' + (idx.caps.stemEvicted ? ' (' + U.fmtNum(idx.caps.stemEvicted) + ' rare non-executable stems evicted)' : ''));
    var q = UI.input(cfg.q, { placeholder: 'substring', style: { width: '240px' } }), after = UI.input(cfg.after, { placeholder: 'YYYY-MM-DD', style: { width: '100px' } });
    var ex = h('input', { type: 'checkbox', checked: cfg.exec }), p2 = h('input', { type: 'checkbox', checked: cfg.pub200 });
    var go = function () { cfg.q = q.value; cfg.exec = ex.checked; cfg.pub200 = p2.checked; cfg.after = after.value; A.nav('uris'); };
    q.onkeydown = after.onkeydown = function (e) { if ((e || window.event).keyCode === 13) { go(); } };
    b.appendChild(h('div', { className: 'row' }, [UI.field('Search', q), h('label', { className: 'chk' }, [ex, ' executable only']), h('label', { className: 'chk' }, [p2, ' with public 200']), UI.field('First seen on/after', after),
      UI.field('Sort', UI.select([['n', 'Requests'], ['first', 'First seen (newest)'], ['firstAsc', 'First seen (oldest)'], ['ips', 'Fewest clients'], ['s5', '5xx']], cfg.sort, function (v) { cfg.sort = v; A.nav('uris'); })), UI.btn('Apply', go, 'primary')]));
    var list = [], k, s, ql = cfg.q.toLowerCase(), af = cfg.after ? U.parseDateInput(cfg.after, 0) : NaN;
    for (k in idx.stems) {
      s = idx.stems[k];
      if (cfg.exec && !s.exec) { continue; }
      if (cfg.pub200 && !s.okPub) { continue; }
      if (!isNaN(af) && s.first < af) { continue; }
      if (ql && k.indexOf(ql) < 0) { continue; }
      list.push(k);
    }
    var sorters = { n: function (a, c) { return idx.stems[c].n - idx.stems[a].n; }, first: function (a, c) { return idx.stems[c].first - idx.stems[a].first; }, firstAsc: function (a, c) { return idx.stems[a].first - idx.stems[c].first; },
      ips: function (a, c) { return (idx.stems[a].ipN + idx.stems[a].ipOv * 100) - (idx.stems[c].ipN + idx.stems[c].ipOv * 100) || idx.stems[c].n - idx.stems[a].n; }, s5: function (a, c) { return idx.stems[c].s5 - idx.stems[a].s5; } };
    list.sort(sorters[cfg.sort] || sorters.n);
    if (list.length > 200000) { list.length = 200000; }
    b.appendChild(h('div', { className: 'muted small' }, U.fmtNum(list.length) + ' match \u00b7 double-click for profile'));
    var host = h('div', { className: 'grid-host tall' }); b.appendChild(host);
    var cols = [{ key: 'stem', label: 'URI stem', w: 460 }, { key: 'n', label: 'Requests', w: 80, num: true }, { key: 'first', label: 'First (UTC)', w: 135 }, { key: 'last', label: 'Last (UTC)', w: 135 }, { key: 'fip', label: 'First client', w: 120 },
      { key: 'ips', label: 'Clients', w: 60, num: true }, { key: 'pub', label: 'Public', w: 55, num: true }, { key: 'post', label: 'POST', w: 65, num: true }, { key: 'ok', label: '200', w: 65, num: true }, { key: 'okp', label: 'Pub 200', w: 60, num: true },
      { key: 's4', label: '4xx', w: 60, num: true }, { key: 's5', label: '5xx', w: 50, num: true }, { key: 'flags', label: 'Flags', w: 110 }, { key: 'tags', label: 'Tags', w: 100 }];
    new UI.VGrid(host, { columns: cols, count: function () { return list.length; },
      cell: function (ri, c) {
        var x = idx.stems[list[ri]];
        switch (c) {
          case 'stem': return x.raw; case 'n': return U.fmtNum(x.n); case 'first': return tsCell(x.first); case 'last': return tsCell(x.last); case 'fip': return x.fIp;
          case 'ips': return x.ipN + (x.ipOv ? '+' : ''); case 'pub': return '' + x.pubN; case 'post': return U.fmtNum(x.post); case 'ok': return U.fmtNum(x.ok); case 'okp': return U.fmtNum(x.okPub);
          case 's4': return U.fmtNum(x.s4); case 's5': return U.fmtNum(x.s5); case 'flags': return (x.exec ? 'exec ' : '') + (x.upDir ? 'upload-dir' : ''); case 'tags': return C.getTags('stems', list[ri]).join(', ');
        }
        return '';
      },
      rowClass: function (ri) { var x = idx.stems[list[ri]]; return (x.exec && x.okPub ? 'hit2' : '') + (C.getTags('stems', list[ri]).length ? ' tagged' : ''); },
      onActivate: function (ri) { A.nav('uriProfile', list[ri]); }
    });
  };
  V.uriProfile = function (main, key) {
    if (!st.idx) { needIndex(main, 'URI profile'); return; }
    var idx = st.idx, s = idx.stems[key];
    var b = page(main, 'URI profile', [UI.btn('\u2190 URI stems', function () { A.nav('uris'); }), UI.btn('Load all rows for this stem', function () { A.load({ fileIds: s ? A.fileIdsForRange(s.first, s.last) : A.allFileIds(), preModel: { conds: [{ f: 'stem', op: 'eq', v: [key], text: 'stem:=' + key }] }, label: 'stem ' + key }); }, 'primary'),
      st.store ? UI.btn('Filter grid to stem', function () { A.pivot('stem:="' + key.replace(/"/g, '') + '"'); }) : null, UI.btn('Copy', function () { UI.copy(s ? s.raw : key); })]);
    b.appendChild(h('div', { className: 'mono big' }, s ? s.raw : key));
    if (!s) { b.appendChild(h('p', null, 'Stem not in the index (it may have been evicted as a rare non-executable path).')); return; }
    var d = new NS.parser.Deriver(st.lists).stem(s.raw);
    var ipsEl = h('span'); Object.keys(s.ips).forEach(function (ip, i) { if (i) { ipsEl.appendChild(document.createTextNode(', ')); } ipsEl.appendChild(ipLink(ip)); });
    var hitRules = []; for (var rid in idx.ruleHits) { if (idx.ruleHits[rid].stems[key]) { hitRules.push(rid + '\u00d7' + idx.ruleHits[rid].stems[key]); } }
    var fsList = idx.findings.filter(function (f) { return f.entity === 'stem' && f.key === key; });
    b.appendChild(UI.kv([
      ['First seen', U.fmtTs(s.first) + ' UTC by ' + s.fIp + '  (' + (idx.files[s.fFile] || {}).name + ' line ' + s.fLine + ')'], ['Last seen', U.fmtTs(s.last) + ' UTC'],
      ['Requests', U.fmtNum(s.n) + '  \u00b7  POST ' + U.fmtNum(s.post) + '  \u00b7  200 ' + U.fmtNum(s.ok) + ' (public ' + U.fmtNum(s.okPub) + ')  \u00b7  4xx ' + U.fmtNum(s.s4) + '  \u00b7  5xx ' + U.fmtNum(s.s5)],
      ['Statuses', Object.keys(s.sts).map(function (x) { return x + ': ' + U.fmtNum(s.sts[x]); }).join(', ')],
      ['Clients', [ipsEl, s.ipOv ? '  (more than ' + s.ipN + '; list truncated)' : '']],
      ['Classification', 'extension ' + (d.ext || '(none)') + (d.exec ? ', executable' : '') + (d.stat ? ', static' : '') + (d.upDir ? ', in upload/static directory' : '') + (d.loginEp ? ', login endpoint' : '') + (d.dlEp ? ', download endpoint' : '') + (d.sens ? ', sensitive path' : '') + (d.exPath ? ', known exploit path' : '')],
      ['Rule hits on this stem', hitRules.join('  ') || 'none'],
      fsList.length ? ['Findings', fsList.map(function (f) { return f.id + ' ' + f.ruleId + ' ' + f.severity; }).join(', '), 'warn'] : null
    ]));
    b.appendChild(h('div', { className: 'row' }, [UI.btn('Raw context of first occurrence', function () { A.rawContext(s.fFile, s.fLine); }), h('b', null, ' Tags: '), tagChips('stems', key, function () { A.nav('uriProfile', key); })]));
    b.appendChild(notesBox('stem', key));
    if (st.store) {
      var vv = [], j;
      for (j = 0; j < st.store.n; j++) { if (st.store.stemInfo[st.store.stem[j]].key === key) { vv.push(j); } }
      if (vv.length) {
        var qs = St.topN(st.store, vv, 'query'), us = St.topN(st.store, vv, 'ua'), cs = St.topN(st.store, vv, 'eip');
        qs.sort(function (a, c) { return c.rows - a.rows; }); us.sort(function (a, c) { return c.rows - a.rows; }); cs.sort(function (a, c) { return c.rows - a.rows; });
        var tl = h('div', { className: 'chart-host' });
        b.appendChild(UI.section('Loaded rows for this stem: ' + U.fmtNum(vv.length), [tl, h('div', { className: 'cols2' }, [
          UI.section('Top queries (decoded)', UI.table(['Query', 'Rows', 'Clients'], qs.slice(0, 25).map(function (g) { return [U.pctDecode(g.key, true).t || '(none)', U.fmtNum(g.rows), g.ipN]; }))),
          h('div', null, [UI.section('Clients', UI.table(['IP', 'Rows', '4xx', 'First', 'Last'], cs.slice(0, 25).map(function (g) { return [ipLink(g.key), U.fmtNum(g.rows), g.s4, tsCell(g.first), tsCell(g.last)]; }))),
            UI.section('User agents', UI.table(['User agent', 'Rows'], us.slice(0, 15).map(function (g) { return [g.key, U.fmtNum(g.rows)]; })))])])]));
        setTimeout(function () {
          var mn = Infinity, mx = -Infinity; vv.forEach(function (x) { var tt = st.store.ts[x]; if (tt < mn) { mn = tt; } if (tt > mx) { mx = tt; } });
          var bk = [60000, 900000, 3600000, 86400000, 604800000].filter(function (x) { return (mx - mn) / x <= 400; })[0] || 604800000, t0 = Math.floor(mn / bk) * bk, nb = Math.floor((mx - t0) / bk) + 1, vals = [], lab = [], k2;
          for (k2 = 0; k2 < nb; k2++) { vals.push(0); lab.push(U.fmtTs(t0 + k2 * bk).substr(0, 16)); }
          vv.forEach(function (x) { vals[Math.floor((st.store.ts[x] - t0) / bk)]++; });
          UI.barChart(tl, { labels: lab, series: [{ name: 'requests per ' + U.fmtDuration(bk), color: UI.COLORS.ext, values: vals }], height: 130 });
        }, 10);
      }
    }
  };

  /* ======================= USER AGENTS ======================= */
  var UAN = NS.useragent;
  var UA_NONBROWSER = { scanner: 1, library: 1, bot: 1, 'webshell-client': 1, empty: 1, other: 1 };
  var UA_WEIGHT = { inject: 6, impossible: 5, headless: 3, malformed: 3, eol: 2, 'eol-os': 2, stale: 1, rare: 1 };
  /* Quick filter that selects exactly this user agent (exact match on the decoded string). */
  V.uaFilter = function (dec) {
    if (!dec) { return 'ua:empty'; }
    if (dec.indexOf('"') < 0) { return 'ua:="' + dec + '"'; }
    var parts = dec.split('"').sort(function (a, b) { return b.length - a.length; }); // quotes cannot be quoted: longest quote-free part, contains
    return 'ua:"' + parts[0] + '"';
  };
  /* One row per distinct user agent: index scope from idx.uas, loaded scope grouped from the grid view. */
  V.uaRows = function (scope) {
    var out = [], k, u, i;
    function finish(r) {
      r.info = UAN.info(r.dec); var at = UAN.at(r.info, r.first);
      r.age = at.age; r.flags = at.flags.slice(); r.why = at.why;
      if (r.dec && r.rare) { r.flags.push('rare'); r.why.rare = 'seen from ' + r.ipN + ' client' + (r.ipN === 1 ? '' : 's') + ' (' + r.pubN + ' public) in ' + (scope === 'index' ? 'the whole corpus' : 'the loaded rows'); }
      r.nonBrowser = UA_NONBROWSER[r.fam] === 1;
      r.score = (r.nonBrowser && r.fam !== 'bot' ? 1 : 0) + (r.xok > 0 && (r.flags.length || r.nonBrowser) ? 2 : 0);
      for (i = 0; i < r.flags.length; i++) { r.score += UA_WEIGHT[r.flags[i]] || 0; }
      out.push(r);
    }
    if (scope === 'index') {
      for (k in st.idx.uas) {
        u = st.idx.uas[k];
        var ips = []; for (i in u.ips) { ips.push(i); }
        finish({ key: k, dec: UAN.decodeKey(k), fam: u.fam, n: u.n, ipN: u.ipN, ipOv: u.ipOv, pubN: u.pubN, s2: u.s2, s3: u.s3, s4: u.s4, s5: u.s5, post: u.post, exec: u.exec, xok: u.xok, hits: u.hits,
          first: u.first, last: u.last, fFile: u.fFile, fLine: u.fLine, fIp: u.fIp, ips: ips, rare: UAN.isRare(u) });
      }
      return out;
    }
    var s = st.store, view = st.grid.view || F.apply(s, null), g = {}, j, ix, id, x, scl, pub, post = s.t.method.find('POST'), ipv = s.t.ip.vals;
    for (j = 0; j < view.length; j++) {
      ix = view[j]; id = s.ua[ix]; x = g[id];
      if (!x) { var ui = s.uaInfo[id]; x = g[id] = { key: s.t.ua.vals[id], dec: ui.dec, fam: ui.fam, n: 0, ipSet: {}, ipN: 0, ipOv: 0, pubN: 0, s2: 0, s3: 0, s4: 0, s5: 0, post: 0, exec: 0, xok: 0, hits: 0, first: s.ts[ix], last: s.ts[ix], fFile: s.file[ix], fLine: s.line[ix], fIp: ipv[s.eip[ix]] }; }
      x.n++; scl = s.status[ix] >= 0 ? Math.floor(s.status[ix] / 100) : 0; pub = (s.flags[ix] & St.FLAGS.PUB) !== 0;
      if (s.ts[ix] < x.first) { x.first = s.ts[ix]; x.fFile = s.file[ix]; x.fLine = s.line[ix]; x.fIp = ipv[s.eip[ix]]; } if (s.ts[ix] > x.last) { x.last = s.ts[ix]; }
      if (x.ipSet[s.eip[ix]] === undefined) { x.ipSet[s.eip[ix]] = 1; x.ipN++; if (pub) { x.pubN++; } }
      if (scl === 2) { x.s2++; } else if (scl === 3) { x.s3++; } else if (scl === 4) { x.s4++; } else if (scl === 5) { x.s5++; }
      if (s.method[ix] === post) { x.post++; }
      if (s.flags[ix] & St.FLAGS.EXEC) { x.exec++; if (scl === 2 && pub) { x.xok++; } }
      if (s.flags[ix] & St.FLAGS.HITS) { x.hits++; }
    }
    for (k in g) { x = g[k]; x.ips = Object.keys(x.ipSet).map(function (q) { return ipv[+q]; }); delete x.ipSet; x.rare = UAN.isRare(x); finish(x); }
    return out;
  };
  V.uas = function (main, focusKey) {
    if (!st.idx && !st.store) { needIndex(main, 'User agents'); return; }
    var cfg = st.uaCfg || (st.uaCfg = { scope: st.idx ? 'index' : 'loaded', show: 'unusual', q: '' });
    if (cfg.scope === 'index' && !st.idx) { cfg.scope = 'loaded'; }
    if (cfg.scope === 'loaded' && !st.store) { cfg.scope = 'index'; }
    var b = page(main, 'User agents', null, 'Each distinct user agent with its browser, how old that browser version was when first seen, the operating system and flags. Double-click a row to filter the rows to it.');
    var q = UI.input(cfg.q, { placeholder: 'substring', style: { width: '220px' } });
    var staleIn = UI.input(UAN.cfg.staleDays, { style: { width: '55px' }, title: 'A browser version older than this many days at the time of the request is flagged stale' });
    var rareIn = UI.input(UAN.cfg.rareIps, { style: { width: '40px' }, title: 'A user agent seen from no more than this many clients is flagged rare' });
    var go = function () {
      cfg.q = q.value;
      var sd = parseInt(staleIn.value, 10), rr = parseInt(rareIn.value, 10);
      if (sd > 0 && rr > 0 && (sd !== UAN.cfg.staleDays || rr !== UAN.cfg.rareIps)) {
        st.settings.uaStaleDays = sd; st.settings.uaRareIps = rr; UAN.configure(st.settings);
        try { C.saveSettings(st.settings); } catch (e) { }
        if (st.store) { A.applyGrid(); } // uaflag: filters depend on the thresholds
      }
      A.nav('uas');
    };
    q.onkeydown = staleIn.onkeydown = rareIn.onkeydown = function (e) { if ((e || window.event).keyCode === 13) { go(); } };
    var shows = [['unusual', 'Unusual (any flag or non-browser)'], ['all', 'All user agents'], ['outdated', 'Outdated: stale or end of support'], ['spoofed', 'Spoofed: impossible, malformed, automation'],
      ['inject', 'Exploit payloads'], ['rare', 'Rare'], ['nonbrowser', 'Non-browser families'], ['execok', 'Unusual and reaching executable handlers (public 2xx)']];
    UAN.FLAGS.forEach(function (f) { shows.push(['flag:' + f, 'Flag: ' + f]); });
    b.appendChild(h('div', { className: 'row' }, [
      UI.field('Scope', UI.select([['index', 'Whole corpus (index)'], ['loaded', 'Loaded rows (current grid filter)']], cfg.scope, function (v) { cfg.scope = v; A.nav('uas'); })),
      UI.field('Show', UI.select(shows, cfg.show, function (v) { cfg.show = v; A.nav('uas'); })),
      UI.field('Search', q), UI.field('Stale after (days)', staleIn), UI.field('Rare: clients ≤', rareIn), UI.btn('Apply', go, 'primary'),
      UI.btn('Export CSV', function () { V.exportDialog(); })
    ]));
    if (!UAN.loaded) { b.appendChild(h('div', { className: 'warn' }, 'lists\\browser-releases.txt was not found: browser ages, stale and future-version checks are unavailable.')); }
    var all = cfg.scope === 'index' ? V.uaRows('index') : V.uaRows('loaded');
    var counts = { nonbrowser: 0 }, i, ql = cfg.q.toLowerCase();
    UAN.FLAGS.forEach(function (f) { counts[f] = 0; });
    all.forEach(function (r) { r.flags.forEach(function (f) { counts[f]++; }); if (r.nonBrowser) { counts.nonbrowser++; } });
    function has(r, list) { for (var z = 0; z < list.length; z++) { if (r.flags.indexOf(list[z]) >= 0) { return true; } } return false; }
    var pick = {
      all: function () { return true; }, unusual: function (r) { return r.flags.length > 0 || r.nonBrowser; }, outdated: function (r) { return has(r, ['stale', 'eol', 'eol-os']); },
      spoofed: function (r) { return has(r, ['impossible', 'malformed', 'headless']); }, inject: function (r) { return has(r, ['inject']); }, rare: function (r) { return has(r, ['rare']); },
      nonbrowser: function (r) { return r.nonBrowser; }, execok: function (r) { return r.xok > 0 && (r.flags.length > 0 || r.nonBrowser); }
    };
    var pf = cfg.show.indexOf('flag:') === 0 ? (function (f) { return function (r) { return r.flags.indexOf(f) >= 0; }; }(cfg.show.substr(5))) : (pick[cfg.show] || pick.unusual);
    function isFocus(r) { return !!focusKey && (r.key === focusKey || r.dec === focusKey); } // raw index key or decoded string
    var list = all.filter(function (r) { return isFocus(r) || (pf(r) && (!ql || r.dec.toLowerCase().indexOf(ql) >= 0)); }); // the user agent asked for is always listed
    list.sort(function (a, c) { return c.score - a.score || c.xok - a.xok || a.n - c.n || (a.dec < c.dec ? -1 : 1); });
    // flag summary: click a count to show those user agents
    var chips = h('div', { className: 'row' }, [h('span', { className: 'muted' }, U.fmtNum(all.length) + ' user agents: ')]);
    UAN.FLAGS.concat(['nonbrowser']).forEach(function (f) {
      var key = f === 'nonbrowser' ? 'nonbrowser' : 'flag:' + f, on = cfg.show === key;
      chips.appendChild(h('span', { className: 'chip' + (on ? ' on' : ''), style: on ? { background: '#2b6cb0', borderColor: '#2b6cb0' } : null, title: f === 'nonbrowser' ? 'scanner, library, bot, web shell client, empty or unrecognised' : UAN.FLAG_HELP[f],
        onclick: function () { cfg.show = on ? 'unusual' : key; A.nav('uas'); } }, (f === 'nonbrowser' ? 'non-browser' : f) + ' ' + U.fmtNum(counts[f])));
    });
    b.appendChild(chips);
    var idx = st.idx, ev = cfg.scope === 'index' && idx && idx.caps.uaEvicted ? ' · ' + U.fmtNum(idx.caps.uaEvicted) + ' rarely seen user agents without rule hits were dropped at the index cap (' + U.fmtNum(idx.caps.uaCap) + '); load rows for the complete picture' : '';
    b.appendChild(h('div', { className: 'muted small' }, U.fmtNum(list.length) + ' shown, most unusual first' + (cfg.scope === 'index' ? ' · clients and public clients are counted up to 20' : ' · grouped from ' + U.fmtNum((st.grid.view || []).length || st.store.n) + ' loaded rows') + ev));
    var split = h('div', { className: 'split-v' }), top = h('div', { className: 'split-top' }), detail = h('div', { className: 'split-bottom detail' });
    split.appendChild(top); split.appendChild(detail); b.appendChild(split);
    var cols = [{ key: 'ua', label: 'User agent', w: 400 }, { key: 'flags', label: 'Flags', w: 170 }, { key: 'browser', label: 'Browser', w: 125 }, { key: 'os', label: 'OS', w: 120 },
      { key: 'rel', label: 'Released', w: 85 }, { key: 'age', label: 'Age at first (d)', w: 85, num: true }, { key: 'fam', label: 'Family', w: 80 }, { key: 'n', label: 'Requests', w: 75, num: true },
      { key: 'ips', label: 'Clients', w: 58, num: true }, { key: 'pub', label: 'Public', w: 55, num: true }, { key: 's2', label: '2xx', w: 60, num: true }, { key: 's4', label: '4xx', w: 60, num: true },
      { key: 's5', label: '5xx', w: 50, num: true }, { key: 'xok', label: 'Exec 2xx pub', w: 80, num: true }, { key: 'hits', label: 'Hit rows', w: 65, num: true },
      { key: 'first', label: 'First (UTC)', w: 135 }, { key: 'last', label: 'Last (UTC)', w: 135 }];
    function cellv(r, c) {
      var x = list[r];
      switch (c) {
        case 'ua': return x.dec || '(empty)'; case 'flags': return x.flags.join(' '); case 'browser': return x.info.name; case 'os': return x.info.os;
        case 'rel': return x.info.rel ? (x.info.rel.est === 2 ? '~' : '') + UAN.fmtDate(x.info.rel.ms) : ''; case 'age': return x.age === null ? '' : U.fmtNum(x.age); case 'fam': return x.fam;
        case 'n': return U.fmtNum(x.n); case 'ips': return x.ipN + (x.ipOv ? '+' : ''); case 'pub': return '' + x.pubN; case 's2': return U.fmtNum(x.s2); case 's4': return U.fmtNum(x.s4);
        case 's5': return U.fmtNum(x.s5); case 'xok': return U.fmtNum(x.xok); case 'hits': return U.fmtNum(x.hits); case 'first': return tsCell(x.first); case 'last': return tsCell(x.last);
      }
      return '';
    }
    st.uaLast = { title: 'User agents (' + cfg.scope + ', ' + cfg.show + (cfg.q ? ', "' + cfg.q + '"' : '') + ')', headers: ['User agent', 'Raw', 'Flags', 'Reasons', 'Browser', 'OS', 'Released', 'Age at first (days)', 'Family', 'Requests', 'Clients', 'Public clients', '2xx', '3xx', '4xx', '5xx', 'POST', 'Executable', 'Executable 2xx public', 'Rule-hit rows', 'First UTC', 'Last UTC', 'First client', 'First file', 'First line', 'Clients (up to 20)'],
      rows: list.map(function (x) { return [x.dec, x.key, x.flags.join(' '), x.flags.map(function (f) { return f + ': ' + x.why[f]; }).join('; '), x.info.name, x.info.os, x.info.rel ? UAN.fmtDate(x.info.rel.ms) + (x.info.rel.est === 2 ? ' (extrapolated)' : '') : '', x.age === null ? '' : x.age, x.fam,
        x.n, x.ipN + (x.ipOv ? '+' : ''), x.pubN, x.s2, x.s3, x.s4, x.s5, x.post, x.exec, x.xok, x.hits, U.fmtIso(x.first), U.fmtIso(x.last), x.fIp, ((cfg.scope === 'index' ? st.idx.files : st.store.files)[x.fFile] || {}).name || '', x.fLine, x.ips.slice(0, 20).join(' ')]; }) };
    function pivot(x) { A.pivot(V.uaFilter(x.dec), 'user agent'); }
    function loadRows(x) { A.load({ fileIds: A.fileIdsForRange(x.first, x.last), preText: V.uaFilter(x.dec), label: 'user agent ' + (x.info.name || x.fam) }); }
    var grid = new UI.VGrid(top, { columns: cols, count: function () { return list.length; }, cell: cellv,
      rowClass: function (r) { var f = list[r].flags; return f.indexOf('inject') >= 0 || f.indexOf('impossible') >= 0 ? 'sevrow-high' : (f.indexOf('eol') >= 0 || f.indexOf('headless') >= 0 || f.indexOf('malformed') >= 0 ? 'sevrow-medium' : '') + (list[r].xok > 0 && f.length ? ' hit2' : ''); },
      onSelect: function (r) { showDetail(list[r]); },
      onActivate: function (r) { pivot(list[r]); },
      onContext: function (r, key, x, y) {
        var u = list[r];
        UI.menu(x, y, [{ label: st.store ? 'Filter grid to this user agent' : 'Load rows with this user agent', onClick: function () { pivot(u); } }, { label: 'Load all rows with this user agent', onClick: function () { loadRows(u); } },
          { label: 'Raw context of first occurrence', onClick: function () { A.rawContext(u.fFile, u.fLine); } }, { label: 'IP profile of first client ' + u.fIp, disabled: !st.idx || !u.fIp, onClick: function () { A.nav('ipProfile', u.fIp); } },
          { sep: true }, { label: 'Copy user agent', onClick: function () { UI.copy(u.dec); } }, { label: 'Copy quick filter', onClick: function () { UI.copy(V.uaFilter(u.dec)); } }]);
      }
    });
    function showDetail(x) {
      UI.clear(detail);
      var ipsEl = h('span');
      x.ips.slice(0, 20).forEach(function (ip, j) { if (j) { ipsEl.appendChild(document.createTextNode(', ')); } ipsEl.appendChild(st.idx ? ipLink(ip) : document.createTextNode(ip)); });
      var fs = st.idx ? st.idx.findings.filter(function (f) { return f.entity === 'ua' && f.key === x.dec; }) : [];
      var why = h('div'); x.flags.forEach(function (f) { why.appendChild(h('div', null, [h('b', null, f + ': '), x.why[f]])); });
      detail.appendChild(h('div', { className: 'row' }, [UI.btn(st.store ? 'Filter grid to this user agent' : 'Load rows with this user agent', function () { pivot(x); }, 'primary'), UI.btn('Load all rows', function () { loadRows(x); }),
        UI.btn('Raw context of first occurrence', function () { A.rawContext(x.fFile, x.fLine); }), UI.btn('Copy', function () { UI.copy(x.dec); })]));
      detail.appendChild(UI.kv([['User agent', x.dec || '(empty)', 'mono'], ['Flags', x.flags.length ? why : 'none'],
        ['Parsed', (x.info.name || 'not a recognised browser') + (x.info.os ? ' on ' + x.info.os : '') + ' · family ' + x.fam + (x.info.rel ? ' · released ' + (x.info.rel.est === 2 ? 'about ' : '') + UAN.fmtDate(x.info.rel.ms) + (x.info.rel.est === 1 ? ' (interpolated)' : x.info.rel.est === 2 ? ' (extrapolated: add newer releases to lists\\browser-releases.txt)' : '') : '') + (x.age !== null ? ' · ' + U.fmtNum(x.age) + ' days old when first seen' : '')],
        ['Seen', tsCell(x.first) + '  →  ' + tsCell(x.last) + ' UTC · first by ' + x.fIp],
        ['Requests', U.fmtNum(x.n) + ' · 2xx ' + U.fmtNum(x.s2) + ' · 3xx ' + U.fmtNum(x.s3) + ' · 4xx ' + U.fmtNum(x.s4) + ' · 5xx ' + U.fmtNum(x.s5) + ' · POST ' + U.fmtNum(x.post) + ' · executable ' + U.fmtNum(x.exec) + ' (public 2xx ' + U.fmtNum(x.xok) + ') · rule-hit rows ' + U.fmtNum(x.hits)],
        ['Clients', [ipsEl, x.ipOv ? '  (more than ' + x.ipN + '; list truncated)' : '', '  · ' + x.pubN + ' public']],
        fs.length ? ['Findings', h('span', null, fs.map(function (f, j) { return h('span', null, [j ? ', ' : '', UI.link(f.id + ' ' + f.ruleId + ' ' + f.severity, function () { A.nav('findings', f.id); })]); })), 'warn'] : null]));
    }
    if (list.length) {
      var sel = 0; if (focusKey) { for (i = 0; i < list.length; i++) { if (isFocus(list[i])) { sel = i; } } }
      grid.select(sel);
    } else { detail.appendChild(h('p', { className: 'muted' }, 'No user agents match. Choose "All user agents" under Show to list every one.')); }
  };

  /* ======================= SESSIONS ======================= */
  V.sessions = function (main) {
    if (!st.store) { needRows(main, 'Sessions'); return; }
    var idle = UI.input(st.settings.sessionIdleMinutes || 30, { style: { width: '50px' } });
    var b = page(main, 'Sessions', [UI.field('Idle timeout (min)', idle), UI.btn('Recompute', function () { st.settings.sessionIdleMinutes = Math.max(1, parseInt(idle.value, 10) || 30); st.sessions = null; A.nav('sessions'); })],
      'Rows from the current grid view grouped by effective client IP + user agent; a gap longer than the idle timeout starts a new session.');
    if (!st.sessions) { var t0 = Date.now(); st.sessions = St.sessions(st.store, st.grid.view, st.settings.sessionIdleMinutes); st.sessionsMs = Date.now() - t0; }
    var cfg = st.sesCfg || (st.sesCfg = { sort: 'start', pub: false });
    var list = st.sessions.slice(0);
    if (cfg.pub) { list = list.filter(function (s) { return s.cls === 'public'; }); }
    var sorters = { start: function (a, c) { return a.start - c.start; }, rows: function (a, c) { return c.rows - a.rows; }, dur: function (a, c) { return c.duration - a.duration; }, hits: function (a, c) { return c.hits - a.hits; }, execPost: function (a, c) { return c.execPost - a.execPost; } };
    list.sort(sorters[cfg.sort]);
    var pubCb = h('input', { type: 'checkbox', checked: cfg.pub }); pubCb.onclick = function () { cfg.pub = pubCb.checked; A.nav('sessions'); };
    b.appendChild(h('div', { className: 'row' }, [UI.field('Sort', UI.select([['start', 'Start'], ['rows', 'Rows'], ['dur', 'Duration'], ['hits', 'Rule-hit rows'], ['execPost', 'Exec POST']], cfg.sort, function (v) { cfg.sort = v; A.nav('sessions'); })),
      h('label', { className: 'chk' }, [pubCb, ' public clients only']), h('span', { className: 'muted small' }, U.fmtNum(list.length) + ' sessions (' + U.fmtNum(st.sessions.length) + ' total) computed in ' + U.fmtDuration(st.sessionsMs))]));
    var split = h('div', { className: 'split-v' }), top = h('div', { className: 'split-top' }), bot = h('div', { className: 'split-bottom' });
    split.appendChild(top); split.appendChild(bot); b.appendChild(split);
    var cols = [{ key: 'id', label: '#', w: 50, num: true }, { key: 'ip', label: 'Client', w: 130 }, { key: 'cls', label: 'Class', w: 70 }, { key: 'fam', label: 'UA family', w: 80 }, { key: 'start', label: 'Start (UTC)', w: 135 }, { key: 'end', label: 'End (UTC)', w: 135 },
      { key: 'dur', label: 'Duration', w: 80 }, { key: 'rows', label: 'Rows', w: 60, num: true }, { key: 'stems', label: 'Stems', w: 55, num: true }, { key: 'mix', label: '2xx/4xx/5xx', w: 100 }, { key: 'xp', label: 'Exec POST', w: 70, num: true },
      { key: 'hits', label: 'Hit rows', w: 60, num: true }, { key: 'tags', label: 'Tags', w: 90 }, { key: 'ua', label: 'User agent', w: 360 }];
    function skey(s) { return s.ip + '|' + s.ua + '|' + s.start; }
    new UI.VGrid(top, { columns: cols, count: function () { return list.length; },
      cell: function (r, k) {
        var s = list[r];
        switch (k) { case 'id': return '' + s.id; case 'ip': return s.ip; case 'cls': return s.cls; case 'fam': return s.fam; case 'start': return tsCell(s.start); case 'end': return tsCell(s.end); case 'dur': return U.fmtDuration(s.duration);
          case 'rows': return U.fmtNum(s.rows); case 'stems': return '' + s.stems; case 'mix': return s.s2 + '/' + s.s4 + '/' + s.s5; case 'xp': return '' + s.execPost; case 'hits': return '' + s.hits; case 'tags': return C.getTags('sessions', skey(s)).join(', '); case 'ua': return s.ua; }
        return '';
      },
      rowClass: function (r) { return (list[r].hits ? 'hit2' : '') + (C.getTags('sessions', skey(list[r])).length ? ' tagged' : ''); },
      onSelect: function (r) { showSession(list[r]); }
    });
    function showSession(s) {
      UI.clear(bot);
      bot.appendChild(h('div', { className: 'row' }, [h('b', null, 'Session ' + s.id + ': ' + s.ip + ' \u00b7 ' + U.fmtNum(s.rows) + ' requests over ' + U.fmtDuration(s.duration)), tagChips('sessions', skey(s), function () { showSession(s); }),
        UI.btn('IP profile', function () { A.nav('ipProfile', s.ip); }), UI.btn('Filter grid to session', function () { A.setGridFilterText('cip:' + s.ip + ' after:"' + U.fmtTs(s.start) + 'Z" before:"' + U.fmtTs(s.end + 1000) + 'Z"'); A.nav('grid'); })]));
      var mini = h('div', { className: 'grid-host' }); bot.appendChild(mini);
      var store = st.store, rc = ['ts', 'method', 'stem', 'query', 'status', 'taken', 'hits'].map(function (k) { return U.extend({}, St.colByKey[k]); });
      rc.unshift({ key: 'dt', label: '+time', w: 70 });
      new UI.VGrid(mini, { columns: rc, count: function () { return s.idx.length; },
        cell: function (r, k) { var i = s.idx[r]; if (k === 'dt') { return '+' + U.fmtDuration(store.ts[i] - s.start); } return St.colByKey[k].get(store, i); },
        rowClass: function (r) { var i = s.idx[r]; return (store.status[i] >= 500 ? 's5' : store.status[i] >= 400 ? 's4' : '') + (store.flags[i] & St.FLAGS.HITS ? ' hit3' : ''); },
        onActivate: function (r) { var i = s.idx[r]; A.rawContext(store.file[i], store.line[i], st.scope ? st.scope.files : null); } });
    }
    if (list.length) { showSession(list[0]); }
  };

  /* ======================= INTEGRITY ======================= */
  V.integrity = function (main) {
    if (!st.idx) { needIndex(main, 'Integrity'); return; }
    var idx = st.idx;
    var b = page(main, 'Log integrity', [UI.btn(idx.hashes && idx.hashes.done ? 'Re-verify SHA-256' : 'Compute SHA-256', function () { A.hashFiles(); }, 'primary')]);
    var hashed = idx.files.filter(function (f) { return f.sha256; }).length;
    var man = idx.files.filter(function (f) { return f.manifest; }), manBad = man.filter(function (f) { return f.manifest.status === 'mismatch'; });
    var tail = idx.files.filter(function (f) { return f.tailNoEol; }), back = idx.files.filter(function (f) { return f.backSteps; }), mal = idx.files.filter(function (f) { return f.malformed; }), errs = idx.files.filter(function (f) { return f.openError; });
    var lf = idx.files.filter(function (f) { return f.lfOnly; });
    b.appendChild(h('div', { className: 'cards' }, [UI.card('SHA-256', hashed + ' / ' + idx.files.length, idx.hashes && idx.hashes.when ? idx.hashes.when : 'not computed', hashed < idx.files.length ? 'warm' : ''),
      UI.card('Manifest', man.length ? (man.length - manBad.length) + ' ok / ' + manBad.length + ' mismatch' : 'n/a', st.manifest ? st.manifest.sources.length + ' source(s)' : 'no Velociraptor manifest', manBad.length ? 'hot' : ''),
      UI.card('Restarts', U.fmtNum(idx.restarts.length), 'mid-file header blocks'), UI.card('Gaps', '' + idx.gaps.length, idx.missingFiles.length + ' missing daily files', idx.gaps.length || idx.missingFiles.length ? 'warm' : ''),
      UI.card('Truncated tails', '' + tail.length, 'files ending without newline', tail.length ? 'warm' : ''), UI.card('Backwards time', '' + back.length, 'files with backwards steps', back.length ? 'hot' : ''),
      UI.card('Malformed', U.fmtNum(idx.totals.malformed), mal.length + ' files', mal.length ? 'warm' : ''), UI.card('Line endings', lf.length ? lf.length + ' LF-only files' : 'CRLF', ''), errs.length ? UI.card('Unreadable', '' + errs.length, 'files failed to open', 'hot') : null]));
    // restarts per day
    var rd = {}, k; idx.restarts.forEach(function (r) { var d = r.date ? r.date.substr(0, 10) : U.dayKey(r.ts); rd[d] = (rd[d] || 0) + 1; });
    var days = Object.keys(idx.perDay).sort(), ch = h('div', { className: 'chart-host' });
    b.appendChild(UI.section('Worker-process / logging restarts per day (extra #Fields blocks)', ch));
    setTimeout(function () { UI.barChart(ch, { labels: days, series: [{ name: 'restarts', color: UI.COLORS.s3, values: days.map(function (d) { return rd[d] || 0; }) }], height: 130, onClick: function (i) { var a = U.dayKeyToMs(days[i]); V.loadDialog({ from: a, to: a + 86399999, label: 'restarts ' + days[i] }); } }); }, 10);
    if (idx.gaps.length || idx.missingFiles.length) {
      b.appendChild(UI.section('Gaps and missing files', [idx.gaps.length ? UI.table(['From (UTC)', 'To (UTC)', 'Hours', 'Resumes in'], idx.gaps.slice(0, 500).map(function (g) { return [U.fmtTs(g.from), U.fmtTs(g.to), g.hours.toFixed(1), UI.link((idx.files[g.fileId] || {}).name + ':' + g.line, function () { A.rawContext(g.fileId, g.line); })]; })) : null,
        idx.missingFiles.length ? h('p', null, 'Missing daily files: ' + idx.missingFiles.join(', ')) : null]));
    }
    var samples = []; idx.files.forEach(function (f, fi) { (f.malformedSamples || []).forEach(function (m) { samples.push([fi, f.name, m]); }); });
    if (samples.length) {
      b.appendChild(UI.section('Malformed row samples', UI.table(['File', 'Line', 'Reason', 'Raw'], samples.slice(0, 200).map(function (x) { return [x[1], UI.link('' + x[2].line, function () { A.rawContext(x[0], x[2].line); }), x[2].reason, x[2].raw]; }))));
    }
    if (st.manifest) { b.appendChild(h('div', { className: 'small muted' }, 'Manifest: ' + st.manifest.root + ' \u2014 ' + st.manifest.sources.join('; '))); }
    var host = h('div', { className: 'grid-host tall' });
    b.appendChild(UI.section('Files (' + idx.files.length + ') \u2014 double-click opens the first lines', host));
    var cols = [{ key: 'name', label: 'File', w: 120 }, { key: 'size', label: 'Bytes', w: 90, num: true }, { key: 'rows', label: 'Rows', w: 75, num: true }, { key: 'blocks', label: 'Blocks', w: 55, num: true },
      { key: 'min', label: 'First (UTC)', w: 135 }, { key: 'max', label: 'Last (UTC)', w: 135 }, { key: 'mal', label: 'Malformed', w: 70, num: true }, { key: 'na', label: 'Non-ASCII', w: 70, num: true },
      { key: 'issues', label: 'Issues', w: 200 }, { key: 'man', label: 'Manifest', w: 90 }, { key: 'sha', label: 'SHA-256', w: 470 }, { key: 'mdet', label: 'Manifest detail', w: 400 }];
    var files = idx.files;
    new UI.VGrid(host, { columns: cols, count: function () { return files.length; },
      cell: function (r, c) {
        var f = files[r];
        switch (c) {
          case 'name': return f.name; case 'size': return U.fmtNum(f.size); case 'rows': return f.scanned ? U.fmtNum(f.rows) : '(not scanned)'; case 'blocks': return f.blocks ? '' + f.blocks.length : '';
          case 'min': return tsCell(f.minTs); case 'max': return tsCell(f.maxTs); case 'mal': return f.malformed ? '' + f.malformed : ''; case 'na': return f.nonAscii ? '' + f.nonAscii : '';
          case 'issues': return [f.openError ? 'OPEN ERROR ' + f.openError : '', f.tailNoEol ? 'truncated tail' : '', f.backSteps ? f.backSteps + ' backwards' : '', f.notW3C ? 'no W3C header' : '', f.lfOnly ? 'LF-only lines' : '', f.sha256Prev ? 'HASH CHANGED' : ''].filter(function (x) { return x; }).join('; ');
          case 'man': return f.manifest ? f.manifest.status : ''; case 'sha': return f.sha256 || ''; case 'mdet': return f.manifest ? f.manifest.detail : '';
        }
        return '';
      },
      rowClass: function (r) { var f = files[r]; return (f.manifest && f.manifest.status === 'mismatch') || f.sha256Prev || f.openError ? 's5' : (f.tailNoEol || f.backSteps || f.malformed ? 's4' : ''); },
      onActivate: function (r) { A.rawContext(r, 1); }
    });
  };

  /* ======================= IOCs ======================= */
  V.iocs = function (main) {
    if (!A.requireCase()) { return; }
    var b = page(main, 'IOCs', null, 'One indicator per line: "type,value,note" (types ip, cidr, path, query, ua, text, regex, user) or a bare value (auto-detected).');
    var ta = h('textarea', { className: 'iocbox', rows: 12 }); ta.value = C.cur.data.ioc.text || '';
    // The case's IOC file: <case workspace>\<CaseID>-IOCs.txt by default, written on every save.
    var fileIn = UI.input(C.iocFilePath(), { style: { width: '760px' }, title: 'IOC file of this case (written by Save & compile)' });
    var impIn = UI.input(C.cur.data.ioc.lastImport || '', { style: { width: '760px' }, placeholder: 'path of an indicator list to append, e.g. a file from another case or tool' });
    var save = function () {
      var path = U.trim(U.expandEnv(fileIn.value)) || C.iocFilePath(true), err = C.saveIocFile(ta.value, path);
      if (err) { UI.alert('IOC file', err); return; }
      C.cur.data.ioc.text = ta.value; C.save(); A.compileIocs();
      C.audit('ioc.update', { count: st.iocs.length, errors: st.iocErrors.length, file: C.cur.data.ioc.file });
      UI.toast('Saved ' + st.iocs.length + ' IOCs to ' + C.cur.data.ioc.file);
      A.nav('iocs');
    };
    b.appendChild(ta);
    b.appendChild(h('div', { className: 'row' }, [UI.btn('Save & compile', save, 'primary', 'Compile the list and write it to the IOC file'), UI.field('IOC file', fileIn),
      UI.btn('Reload from file', function () {
        var p = U.expandEnv(fileIn.value), t = C.readListFile(p);
        if (t === null) { UI.toast('File not found: ' + p, 'error'); return; }
        UI.confirm('Reload IOCs', 'Replace the list with the contents of\n' + p + '?', function () { ta.value = t; C.audit('ioc.reload', { path: p }); save(); }, 'Reload');
      }, '', 'Replace the list with the IOC file (after editing it outside the tool)'),
      h('span', { className: 'muted' }, st.iocs ? st.iocs.length + ' IOCs compiled' : '')]));
    b.appendChild(h('div', { className: 'row' }, [UI.field('Import from', impIn), UI.btn('Import (append)', function () {
      var p = U.expandEnv(U.trim(impIn.value));
      if (!p) { UI.toast('Enter the path of a file to import', 'warn'); return; }
      if (p.toLowerCase() === U.expandEnv(fileIn.value).toLowerCase()) { UI.toast('That is this case\'s own IOC file; use Reload from file instead.', 'warn'); return; }
      var t = C.readListFile(p); if (t === null) { UI.toast('File not found: ' + p, 'error'); return; }
      ta.value = (ta.value ? ta.value + '\r\n' : '') + '# imported from ' + p + ' ' + U.nowIso() + '\r\n' + t;
      C.cur.data.ioc.lastImport = impIn.value; C.audit('ioc.import', { path: p }); save();
    })]));
    if (st.iocErrors && st.iocErrors.length) { b.appendChild(h('div', { className: 'warn pre-wrap' }, st.iocErrors.join('\n'))); }
    b.appendChild(h('div', { className: 'row mt' }, [
      UI.btn('Sweep index', function () { V.iocSweepIndex(); A.nav('iocs'); }, '', 'Match IOCs against index IPs, stems, user agents and retained rule-hit rows (instant)'),
      UI.btn('Sweep loaded rows', function () { if (!st.store) { UI.toast('No rows loaded', 'warn'); return; } A.setGridFilterText('ioc:any'); A.nav('grid'); }),
      UI.btn('Full corpus sweep (load matches)', function () { if (!st.iocMatcher) { UI.toast('No IOCs', 'warn'); return; } A.loadWhere('ioc:any', 'IOC sweep'); }, '', 'Streams every file and loads all rows matching any IOC')]));
    if (st.iocHits) {
      b.appendChild(UI.section('Index sweep results (' + st.iocHits.length + ')', UI.table(['Type', 'IOC', 'Note', 'Matched in', 'Hits', 'First (UTC)', 'Last (UTC)', 'Sample'], st.iocHits.map(function (r) {
        return [r.type, r.where === 'ip' ? ipLink(r.sample) : r.value, r.note, r.where, U.fmtNum(r.n), tsCell(r.first), tsCell(r.last), r.where === 'stem' ? stemLink(r.sample.toLowerCase(), r.sample) : r.sample];
      }))));
    }
  };
  V.iocSweepIndex = function () {
    if (!st.idx || !st.iocMatcher) { UI.toast('Need an index and IOCs', 'warn'); return; }
    var idx = st.idx, m = st.iocMatcher, out = [], k, h2;
    for (k in idx.ips) { h2 = m.ipHit(k); if (h2) { out.push({ type: h2.type, value: h2.value, note: h2.note, where: 'ip', n: idx.ips[k].n, first: idx.ips[k].first, last: idx.ips[k].last, sample: k }); } }
    for (k in idx.stems) { var s = idx.stems[k]; h2 = m.stemHit(U.pctDecode(s.raw, false).t.toLowerCase()); if (h2) { out.push({ type: h2.type, value: h2.value, note: h2.note, where: 'stem', n: s.n, first: s.first, last: s.last, sample: s.raw }); } }
    for (k in idx.uas) { h2 = m.uaHit(k.replace(/\+/g, ' ')); if (h2) { out.push({ type: h2.type, value: h2.value, note: h2.note, where: 'user agent', n: idx.uas[k].n, first: idx.uas[k].first, last: idx.uas[k].last, sample: k.replace(/\+/g, ' ') }); } }
    st.iocHits = out;
    C.audit('ioc.sweep.index', { iocs: st.iocs.length, hits: out.length });
    UI.toast(out.length + ' IOC matches in the index');
  };

  /* ======================= LOG PARSER ======================= */
  V.runLogParser = function (sql, cp, cb) {
    var exe = NS.logparser.find(st.settings), scope = st.scope || st.site;
    if (!exe) { if (cb) { cb(new Error('Log Parser not found')); } return; }
    var whole = (!st.scope || st.scope.files.length === st.site.files.length) ? st.site.path : null;
    var full = NS.logparser.expand(sql, NS.logparser.fromClause(scope.files, whole)), token = { cancelled: false };
    var prog = UI.progress('Log Parser running over ' + scope.files.length + ' file(s)', function () { token.cancelled = true; });
    prog.update({ file: 0, files: 0, current: exe });
    var epoch = st.epoch;
    NS.logparser.run({ exe: exe, sql: full, workDir: C.cur.tmp, iCodepage: cp }, function (err, res) {
      prog.close();
      if (st.epoch !== epoch) { UI.toast('Log Parser result discarded: the case or evidence selection changed while it ran.', 'warn'); return; }
      if (err) { C.audit('logparser.error', { exe: exe, error: err.message }); UI.alert('Log Parser', err.message); if (cb) { cb(err); } return; }
      res.sql = full; st.lpResult = res;
      C.audit('logparser.query', { exe: exe, sql: full.substr(0, 4000), files: scope.files.length, rows: res.rows.length, ms: res.ms, exitCode: res.exitCode });
      UI.toast('Log Parser returned ' + U.fmtNum(res.rows.length) + ' rows in ' + U.fmtDuration(res.ms));
      if (st.view === 'logparser' && !st.autotest) { A.nav('logparser'); }
      if (cb) { cb(null, res); }
    }, token);
  };
  /* ======================= UPDATES ======================= */
  /* Opens an https address in the default browser (explorer.exe hands it to the registered browser). */
  V.openUrl = function (url) {
    if (!/^https:\/\//i.test(url)) { return false; }
    try { U.shell().Run('explorer.exe "' + url + '"', 1, false); return true; } catch (e) { UI.alert('Open web page', 'The browser could not be started: ' + e.message + '\n\nOpen this address manually:\n' + url); return false; }
  };
  /* Version check. auto = start-up check enabled in Settings (no confirmation, silent unless an update exists). */
  V.checkUpdates = function (auto) {
    var UP = NS.update;
    function run() {
      if (C.cur) { C.audit('network.updateCheck', { url: UP.API, auto: !!auto, current: UP.current() }); }
      if (!auto) { UI.toast('Checking GitHub for a newer version...'); }
      UP.latest(function (err, info) {
        if (err) {
          if (!auto) { UI.alert('Check for updates', 'The check failed: ' + err.message + '\n\nReleases: ' + UP.RELEASES); } else { NS.trace('update check failed: ' + err.message); }
          return;
        }
        st.updateInfo = info;
        st.settings.updateLatest = { version: info.version, checked: U.nowIso() }; // remembered so the label stays amber after a restart
        try { C.saveSettings(st.settings); } catch (eS) { }
        A.renderToolbar();
        if (UP.compare(info.version, UP.current()) <= 0) { if (!auto) { UI.alert('Check for updates', 'You have the latest version (' + UP.current() + ').'); } return; }
        V.updateDialog(info);
      });
    }
    if (auto) { run(); return; }
    UI.confirm('Check for updates', 'This contacts api.github.com to read the latest release of IIS Log Analyzer (' + UP.REPO + '). GitHub sees this workstation\'s public IP address and the app version; nothing else is sent. The check is recorded in the audit log of the open case.\n\nAutomatic checks at start-up can be turned on in Settings.', run, 'Check now');
  };
  V.updateDialog = function (info) {
    var UP = NS.update, single = UP.isSingleFile(), notes = (info.notes || '').replace(/\r/g, '');
    if (notes.length > 1500) { notes = notes.substr(0, 1500) + '\n...'; }
    var body = h('div', null, [
      h('p', null, 'Version ' + info.version + ' is available. This copy is version ' + UP.current() + '.'),
      h('div', { className: 'muted small' }, (info.name || info.tag) + (info.published ? ' \u00b7 published ' + info.published.substr(0, 10) : '')),
      h('div', { className: 'upd-notes' }, notes),
      h('p', { className: 'muted small' }, single ?
        'Download and replace checks the download (size, SHA-256 published with the release, embedded version), keeps the current file next to it as a backup, and offers to restart. Nothing is changed if any check fails.' :
        'This copy runs from the source folder (IISLogAnalyzer.hta with lib\\), which one file cannot replace. Download saves the verified single-file HTA to your Downloads folder.')
    ]);
    UI.dialog({ title: 'Update available', width: 660, body: body, buttons: [
      { label: single ? 'Download and replace' : 'Download', primary: true, onClick: function () { V.applyUpdate(info, single); } },
      { label: 'Open release page', onClick: function () { V.openUrl(/^https:\/\/github\.com\//i.test(info.url) ? info.url : UP.RELEASES); return false; } },
      { label: 'Not now' }] });
  };
  V.applyUpdate = function (info, single) {
    var UP = NS.update;
    if (st.busy) { UI.alert('Update', 'A scan or load is running. Finish or cancel it first.'); return; }
    var target = UP.selfPath(), work = C.cur ? C.cur.tmp : U.env('TEMP');
    var dest = single ? target + '.download' : U.joinPath(U.joinPath(U.env('USERPROFILE'), 'Downloads'), 'IISLogAnalyzer-' + info.version + '.hta');
    var prog = UI.progress('Downloading IIS Log Analyzer ' + info.version, null);
    prog.update({ file: 0, files: 0, current: info.asset ? info.asset.url : '', msg: 'Downloading and verifying...' });
    if (C.cur) { C.audit('network.updateDownload', { version: info.version, url: info.asset ? info.asset.url : '', dest: dest }); }
    UP.download(info, dest, work, function (err, d) {
      prog.close();
      if (err && single && /^Cannot write/.test(err.message)) { UI.toast('The application folder is not writable; saving the new version to Downloads instead.', 'warn'); V.applyUpdate(info, false); return; }
      if (err) {
        if (C.cur) { C.audit('app.update.error', { version: info.version, error: err.message }); }
        UI.alert('Update failed', err.message + '\n\nNothing was changed. Releases: ' + UP.RELEASES);
        return;
      }
      if (!single) {
        if (C.cur) { C.audit('app.update.downloaded', { version: info.version, path: d.path, sha256: d.sha256 }); }
        UI.alert('Update downloaded', 'IIS Log Analyzer ' + info.version + ' was saved and verified:\n' + d.path + '\nSHA-256 ' + d.sha256 + '\n\nUnblock it (Properties > Unblock) and use it in place of this copy.');
        return;
      }
      var r;
      try { r = UP.replace(d.path, target, UP.current()); } catch (e) {
        UI.alert('Update failed', 'The download was verified, but ' + target + ' could not be replaced: ' + e.message + '\n\nThe new version is at ' + d.path);
        return;
      }
      if (C.cur) { C.audit('app.update', { from: UP.current(), to: info.version, path: target, sha256: d.sha256, backup: r.backup }); }
      st.updateApplied = { version: info.version, sha256: d.sha256, backup: r.backup };
      UI.confirm('Updated to ' + info.version, 'This file was replaced with IIS Log Analyzer ' + info.version + ' (SHA-256 ' + d.sha256 + ').\nThe previous version is kept as:\n' + r.backup + '\n\nRestart now to use it? Loaded rows are not kept; the case, its index and the audit log are on disk.', function () { V.restartApp(target); }, 'Restart now');
    });
  };
  V.restartApp = function (path) {
    try { U.shell().Run('mshta.exe "' + path + '"', 1, false); } catch (e) { UI.alert('Restart', 'Start ' + path + ' manually: ' + e.message); return; }
    window.close();
  };

  /* Opens Microsoft's download page in the default browser after confirmation; audited as a network action. */
  V.openLogParserDownload = function () {
    var url = NS.logparser.DOWNLOAD_URL;
    UI.confirm('Download Log Parser 2.2', 'This opens the official Microsoft download page in your default web browser:\n\n' + url + '\n\nDownload LogParser.msi (version 2.2.10, 1.4 MB), install it, then press Re-check. Opening the page is a network action from this workstation; the tool itself downloads and installs nothing.', function () {
      try { U.shell().Run('explorer.exe "' + url + '"', 1, false); } catch (e) { UI.alert('Download Log Parser 2.2', 'The browser could not be started: ' + e.message + '\n\nOpen this address manually:\n' + url); return; }
      if (C.cur) { C.audit('network.logParserDownloadPage', { url: url }); }
    }, 'Open download page');
  };
  V.logparser = function (main) {
    var b = page(main, 'Log Parser 2.2', null, 'Ad-hoc SQL over the evidence with Microsoft Log Parser 2.2, if it is installed. The tool itself never downloads or installs anything.');
    var lps = NS.logparser.status(st.settings), exe = lps.exe;
    b.appendChild(h('div', { className: 'lp-status' }, [UI.trafficLight(lps.state, lps.label), h('div', { className: 'lp-status-t' }, [h('b', null, lps.label), h('div', { className: 'muted small' }, lps.detail)]),
      UI.btn('Download Log Parser 2.2...', V.openLogParserDownload, exe ? '' : 'primary', 'Opens the official Microsoft download page in your web browser'),
      UI.btn('Re-check', function () { A.renderNav(); A.nav('logparser'); }, '', 'Look for LogParser.exe again (after installing it)')]));
    if (!exe) {
      var pin = UI.input(st.settings.logParserPath || '', { style: { width: '560px' }, placeholder: 'C:\\Program Files (x86)\\Log Parser 2.2\\LogParser.exe' });
      b.appendChild(h('p', null, 'LogParser.exe was not found. Checked: ' + NS.logparser.candidates(st.settings).join('; ')));
      b.appendChild(h('div', { className: 'row' }, [UI.field('LogParser.exe path', pin), UI.btn('Save path', function () { st.settings.logParserPath = U.trim(pin.value); try { C.saveSettings(st.settings); } catch (e) { } A.nav('logparser'); }, 'primary')]));
      b.appendChild(h('p', { className: 'muted small' }, 'Everything else in the tool works without Log Parser; this view only adds free-form SQL.'));
      return;
    }
    if (!st.site) { b.appendChild(h('p', null, ['Open evidence first. ', UI.link('Case & evidence', function () { A.nav('home'); })])); return; }
    var scope = st.scope || st.site;
    var ta = h('textarea', { rows: 9, className: 'iocbox' }); ta.value = st.lpSql || NS.logparser.TEMPLATES[0].sql;
    var tpl = UI.select([['', 'Templates...']].concat(NS.logparser.TEMPLATES.map(function (t, i) { return [i, t.name]; })), '', function (v) { if (v !== '') { ta.value = NS.logparser.TEMPLATES[+v].sql; } });
    var cp = UI.select([['-1', 'Input code page: system ANSI'], ['65001', 'UTF-8'], ['1252', 'Windows-1252']], st.lpCp || '65001');
    b.appendChild(h('div', { className: 'muted small' }, 'Using ' + exe + '. {files} expands to the ' + scope.files.length + ' file(s) in the current scope. Timestamps are UTC as logged.'));
    b.appendChild(h('div', { className: 'row' }, [tpl, cp, UI.btn('Run query', function () { st.lpSql = ta.value; st.lpCp = cp.value; V.runLogParser(ta.value, +cp.value); }, 'primary')]));
    b.appendChild(ta);
    var r = st.lpResult;
    if (r) {
      b.appendChild(h('div', { className: 'muted small' }, U.fmtNum(r.rows.length) + ' rows \u00b7 ' + U.fmtDuration(r.ms) + (r.stderr ? ' \u00b7 messages: ' + r.stderr.substr(0, 300) : '') + ' \u00b7 export via Export\u2026'));
      var host = h('div', { className: 'grid-host tall' }); b.appendChild(host);
      var cols = r.header.map(function (hd, i) { return { key: '' + i, label: hd, w: Math.max(70, Math.min(420, hd.length * 9 + 30)) }; });
      new UI.VGrid(host, { columns: cols, count: function () { return r.rows.length; }, cell: function (ri, k) { return r.rows[ri][+k]; } });
    }
  };

  /* ======================= TAGS ======================= */
  V.tags = function (main) {
    if (!A.requireCase()) { return; }
    var cd = C.cur.data, b = page(main, 'Tags, notes and bookmarks');
    var counts = C.tagCounts();
    var defs = h('div');
    cd.tagDefs.forEach(function (d, i) {
      var n = UI.input(d.name, { style: { width: '140px' } }), c = UI.input(d.color, { style: { width: '80px' } });
      defs.appendChild(h('div', { className: 'row' }, [h('span', { className: 'chip on', style: { background: d.color } }, d.name), n, c, h('span', { className: 'muted' }, (counts[d.name] || 0) + ' uses'),
        UI.btn('Save', function () { var old = d.name; d.name = U.trim(n.value) || old; d.color = U.trim(c.value) || d.color; if (old !== d.name) { var t = cd.tags, kk, kind; for (kind in t) { for (kk in t[kind]) { var ix = t[kind][kk].indexOf(old); if (ix >= 0) { t[kind][kk][ix] = d.name; } } } } C.save(); A.nav('tags'); }),
        UI.btn('Delete', function () { UI.confirm('Delete tag', 'Remove tag ' + d.name + ' from ' + (counts[d.name] || 0) + ' item(s)?', function () { var t = cd.tags, kk, kind; for (kind in t) { for (kk in t[kind]) { C.setTag(kind, kk, d.name, false); } } cd.tagDefs.splice(i, 1); C.save(); C.audit('tag.delete', { tag: d.name }); A.nav('tags'); }, 'Delete'); })]));
    });
    defs.appendChild(UI.btn('Add tag', function () { UI.prompt('New tag', 'Tag name', '', function (v) { if (v) { cd.tagDefs.push({ name: v, color: '#3182ce' }); C.save(); A.nav('tags'); } }); }));
    b.appendChild(UI.section('Tag definitions', defs));
    var rows = [], kind, key;
    for (kind in cd.tags) { for (key in cd.tags[kind]) { rows.push([kind, key, cd.tags[kind][key].join(', ')]); } }
    b.appendChild(UI.section('Tagged items (' + rows.length + ')', rows.length ? UI.table(['Kind', 'Key', 'Tags'], rows.map(function (r) {
      var link = r[0] === 'ips' ? ipLink(r[1]) : (r[0] === 'stems' ? stemLink(r[1]) : r[1]);
      return [r[0], link, r[2]];
    })) : h('p', { className: 'muted' }, 'Nothing tagged yet. Use the row detail pane, context menus or profiles.')));
    if (rows.some(function (r) { return r[0] === 'rows'; }) && st.site) { b.appendChild(UI.btn('Load all tagged rows', function () { V.loadTaggedRows(); })); }
    b.appendChild(UI.section('Notes (' + cd.notes.length + ')', cd.notes.length ? UI.table(['Time (UTC)', 'Examiner', 'Target', 'Note'], cd.notes.slice(0).reverse().map(function (n) { return [n.ts, n.examiner || '', n.type + ' ' + n.key, n.text]; })) : h('p', { className: 'muted' }, 'No notes.')));
    b.appendChild(UI.section('Bookmarks (' + cd.bookmarks.length + ')', cd.bookmarks.length ? UI.table(['Time (UTC)', 'Label', 'Row', 'Client'], cd.bookmarks.map(function (x) { return [U.fmtTs(x.ts), x.label, x.ref, x.ip]; })) : h('p', { className: 'muted' }, 'No bookmarks.')));
  };
  V.loadTaggedRows = function () {
    var ptrs = [], k, files = (st.scope || st.site).files, byName = {}, i;
    for (i = 0; i < files.length; i++) { byName[files[i].name.toLowerCase()] = i; }
    for (k in C.cur.data.tags.rows) {
      var m = /^(.*?)\/(.+):(\d+)$/.exec(k);
      if (m && m[1] === st.site.name && byName[m[2].toLowerCase()] !== undefined) { ptrs.push([byName[m[2].toLowerCase()], +m[3]]); }
    }
    if (!ptrs.length) { UI.toast('No tagged rows for this site', 'warn'); return; }
    A.loadPointers(ptrs, 'tagged rows');
  };

  /* ======================= SETTINGS ======================= */
  V.settings = function (main) {
    var s = st.settings, b = page(main, 'Settings', null, 'Saved to ' + C.userSettingsPath() + '. Defaults ship in config\\settings.json.'), defTz = V.tzSelect(s.displayTzId || ('fixed:' + (s.displayTzOffsetMinutes || 0)));
    var f = {};
    function inp(key, label, w, hint) { f[key] = UI.input(s[key] === undefined ? '' : s[key], { style: { width: (w || 120) + 'px' } }); return UI.field(label, f[key], hint); }
    var bhS = UI.input(s.businessHours.start, { style: { width: '60px' } }), bhE = UI.input(s.businessHours.end, { style: { width: '60px' } }), bhD = UI.input(s.businessHours.days.join(','), { style: { width: '90px' } });
    var raw = h('input', { type: 'checkbox', checked: s.keepRaw }), hos = h('input', { type: 'checkbox', checked: s.hashOnScan });
    var cidrs = h('textarea', { rows: 3, style: { width: '420px' } }); cidrs.value = (s.internalCidrs || []).join('\r\n');
    var caps = UI.input(s.indexCaps.ips + ',' + s.indexCaps.stems + ',' + s.indexCaps.uas, { style: { width: '200px' } });
    b.appendChild(UI.section('General', [h('div', { className: 'row' }, [inp('examiner', 'Default examiner', 200), inp('caseWorkspaceRoot', 'Case workspace root', 420)]),
      h('div', { className: 'row' }, [UI.field('Default display time zone for new cases', defTz.el), inp('codepageHint', 'Codepage hint', 60)]),
      h('div', { className: 'row' }, [UI.field('Business hours start', bhS), UI.field('end', bhE), UI.field('days (0=Sun)', bhD), inp('sessionIdleMinutes', 'Session idle (min)', 50)])]));
    b.appendChild(UI.section('Capacity (' + st.bits + '-bit host)', [h('div', { className: 'row' }, [inp('maxRows', 'Max loaded rows', 100), h('label', { className: 'chk' }, [raw, ' keep raw lines']), inp('chunkChars', 'Reader chunk (chars)', 100), inp('streamAboveMB', 'Stream files larger than (MB)', 60, 'Larger files are read incrementally instead of being buffered whole (less memory, slightly slower)'), inp('sliceMs', 'UI slice (ms)', 50)]),
      h('div', { className: 'row' }, [UI.field('Index caps (IPs,stems,UAs)', caps), inp('ruleHitRetention', 'Rule-hit pointers kept per rule', 90), h('label', { className: 'chk' }, [hos, ' hash files during scan'])])]));
    var tnp = h('input', { type: 'checkbox', checked: !!s.testNetsPublic });
    var cuo = h('input', { type: 'checkbox', checked: !!s.checkUpdatesOnStart });
    b.appendChild(UI.section('Updates', h('div', { className: 'row' }, [h('label', { className: 'chk' }, [cuo, ' check GitHub for a newer version when the app starts (network: api.github.com; off by default)']), UI.btn('Check now...', function () { V.checkUpdates(false); })])));
    b.appendChild(UI.section('Networks and lists', [UI.field('Additional internal CIDRs (one per line)', cidrs), h('label', { className: 'chk' }, [tnp, ' treat documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32 as public (training and demo data only; rescan after changing)']), h('div', { className: 'row' }, [inp('allowedIpsFile', 'Allow-listed IPs file (rules suppressed)', 420)]),
      h('div', { className: 'row' }, [inp('logParserPath', 'Log Parser 2.2 path (optional; detected under Program Files)', 520)]),
      h('div', { className: 'row' }, [inp('geoCsv', 'Offline IP enrichment CSV (CIDR,label... e.g. GeoLite2-ASN-Blocks-IPv4.csv)', 520), h('span', { className: 'muted small' }, NS.enrich.loaded ? U.fmtNum(NS.enrich.count) + ' ranges loaded' : (NS.enrich.error || 'not loaded'))]),
      h('div', { className: 'muted small' }, 'Detection lists live in the lists\\ folder next to the HTA; edit them and restart. Allow-listed IPs: ' + (st.allowCount || 0) + ' loaded.')]));
    // rules
    var rl = h('div', { className: 'rulelist' }), ov = C.cur ? C.cur.data.ruleOverrides : s.ruleOverrides;
    st.ruleset.rules.forEach(function (r) {
      var cb = h('input', { type: 'checkbox', checked: r.enabled });
      cb.onclick = function () { ov[r.id] = cb.checked; };
      rl.appendChild(h('div', { className: 'rulerow', title: r.description }, [cb, ' ', UI.sevBadge(r.severity), ' ', h('b', null, r.id), ' ' + r.name + ' ', h('span', { className: 'muted small' }, r.scope + (r.params && U.countKeys(r.params) ? ' ' + JSON.stringify(r.params) : ''))]));
    });
    b.appendChild(UI.section('Rules' + (C.cur ? ' (enable/disable is stored per case)' : ''), [h('div', { className: 'muted small' }, 'Thresholds are edited in rules\\default-rules.json. Row-rule changes need a rescan; aggregate-rule changes apply with "Re-evaluate" in Findings.'), rl]));
    b.appendChild(h('div', { className: 'row' }, [UI.btn('Save settings', function () {
      var k;
      for (k in f) { var v = U.trim(f[k].value); s[k] = /^-?\d+$/.test(v) ? parseInt(v, 10) : v; }
      s.businessHours = { start: U.trim(bhS.value), end: U.trim(bhE.value), days: bhD.value.split(',').map(function (x) { return parseInt(x, 10); }).filter(function (x) { return x >= 0 && x <= 6; }) };
      s.keepRaw = raw.checked; s.hashOnScan = hos.checked; s.checkUpdatesOnStart = cuo.checked;
      var dz = defTz.get(); if (!dz) { return; } s.displayTzId = dz.id; s.displayTzLabel = dz.label; s.displayTzOffsetMinutes = dz.off(Date.now());
      s.internalCidrs = U.parseList(cidrs.value).filter(function (x) { return U.parseCidr(x); });
      s.testNetsPublic = tnp.checked;
      var cp = caps.value.split(',').map(function (x) { return parseInt(x, 10); }); if (cp.length === 3 && cp.every(function (x) { return x > 1000; })) { s.indexCaps = { ips: cp[0], stems: cp[1], uas: cp[2] }; }
      if (st.bits === 32) { s.maxRows32 = s.maxRows; } else { s.maxRows64 = s.maxRows; }
      try { C.saveSettings(s); } catch (e) { UI.alert('Settings', 'Save failed: ' + e.message); return; }
      if (C.cur) { C.save(); C.audit('settings.save', { ruleOverrides: ov }); } else { s.ruleOverrides = ov; C.saveSettings(s); }
      A.applyNetworkLists(); A.loadRules();
      UI.toast('Settings saved'); A.refreshChrome(); A.nav('settings');
    }, 'primary')]));
  };

  /* ======================= HELP ======================= */
  V.help = function (main) {
    var b = page(main, 'Help', [UI.btn('Check for updates...', function () { V.checkUpdates(false); }, '', 'Ask GitHub for the latest release (network)')], 'IIS Log Analyzer ' + NS.VERSION + ' \u00b7 document mode ' + document.documentMode + ' \u00b7 ' + st.bits + '-bit mshta');
    b.appendChild(UI.section('Workflow', h('ol', null, [h('li', null, 'Case & evidence: open or create a case, then open the evidence folder (LogFiles, W3SVCn or a file).'),
      h('li', null, 'Scan: streams every file once and builds the index and findings. The fast engine (compiled C# run through PowerShell) and the built-in engine produce identical indexes; scans can be cancelled and continued.'),
      h('li', null, 'Review Overview and Findings; record dispositions. Use profiles and Top-N against the whole corpus.'),
      h('li', null, 'Load rows for a slice (date range and/or pre-filter) to work row by row in the grid, sessions and timeline.'),
      h('li', null, 'Tag, note, export (CSV / Timeline Explorer / JSONL / raw lines) and generate the HTML report. Everything is hashed and audited.')])));
    b.appendChild(UI.section('Quick filter syntax', UI.table(['Example', 'Meaning'], F.HELP)));
    b.appendChild(UI.section('Keyboard', UI.table(['Key', 'Action'], [['Ctrl+F', 'Focus quick filter'], ['Ctrl+L', 'Load rows dialog'], ['Ctrl+E', 'Export dialog'], ['Alt+1..9', 'Switch view'], ['\u2191 \u2193 PgUp PgDn Ctrl+Home/End', 'Move in grid'],
      ['Shift/Ctrl+click', 'Multi-select'], ['Ctrl+C / Ctrl+Shift+C', 'Copy selected rows as TSV / raw lines'], ['Enter / double-click', 'Raw context from the evidence file'], ['Right-click', 'Pivot menu'], ['F5', 'Disabled (would discard loaded state)']])));
    b.appendChild(UI.section('Forensic handling', h('ul', null, [h('li', null, 'Evidence files are opened read-only; nothing is written under the evidence folder. Reading may update NTFS last-access times unless disabled; work from a copy or mounted image as usual.'),
      h('li', null, 'SHA-256 of every file is computed with PowerShell Get-FileHash and compared with Velociraptor results where present.'),
      h('li', null, 'All times are stored and exported in UTC; the display time zone is shown alongside.'),
      h('li', null, 'Log fields are attacker-controlled. The tool renders them as text only and neutralises spreadsheet formulas in CSV exports.'),
      h('li', null, 'Audit log: ' + (C.cur ? U.joinPath(C.cur.ws, 'audit.log') : '(open a case)'))])));
    b.appendChild(UI.section('Files', UI.kv([['Application folder', IO.appFolder()], ['User settings', C.userSettingsPath()], ['Case workspace', C.cur ? C.cur.ws : '(none)'], ['Rule set', st.ruleset.version + ' / ' + st.ruleset.hash]])));
  };
}(IISLA));
