/* IIS Log Analyzer - export.js
 * CSV / Timeline Explorer CSV / JSONL / raw-line exports with SHA-256 sidecars,
 * and the self-contained HTML case report. All evidence text is escaped.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io, C = NS.caseMgr, St = NS.store, R = NS.rules, X = NS.exporter = {};

  X.outPath = function (kind, ext, dir) {
    var cid = C.cur ? U.safeName(C.cur.data.caseId) : 'case';
    return U.joinPath(dir || (C.cur ? C.cur.exports : U.env('TEMP')), cid + '_' + U.safeName(kind) + '_' + U.stampForFile() + '.' + ext);
  };
  /* Hashes the output, writes <file>.sha256, appends to the audit log. */
  X.finalize = function (path, kind, meta) {
    var h = '';
    try { h = IO.hashFileSync(path, C.cur ? C.cur.tmp : U.env('TEMP')); } catch (e) { h = ''; }
    if (h) { try { U.writeTextUtf8(path + '.sha256', h + '  ' + U.baseOf(path) + '\r\n', false); } catch (e2) { } }
    var size = 0; try { size = U.fso().GetFile(path).Size; } catch (e3) { }
    C.audit('export', U.extend({ kind: kind, path: path, sha256: h, bytes: size }, meta || {}));
    return { path: path, sha256: h, bytes: size };
  };
  X.openFolder = function (path) { try { U.shell().Run('explorer.exe /select,"' + path + '"', 1, false); } catch (e) { } };

  /* ---------- rows ---------- */
  X.TLE_COLS = ['Timestamp (UTC)', 'Timestamp (Local)', 'Client IP', 'IP Class', 'Method', 'Status', 'Stem', 'Query (decoded)', 'User-Agent (decoded)', 'Time-Taken', 'Rule Hits', 'Tags', 'Source File', 'Line', 'Raw'];
  /* format: 'csv' | 'tle' | 'jsonl'. cols: column defs (csv). done(err, info) */
  X.rows = function (store, view, cols, format, path, tz, tzLabel, done, progress, meta) {
    // Record the completeness of the load these rows came from with the export.
    meta = U.extend({ loadCapped: !!store.capped, loadCancelled: !!store.cancelled }, meta || {});
    if (store.failed && store.failed.length) { meta.loadIncomplete = true; meta.unreadableFiles = store.failed.map(function (f) { return f.name + ': ' + f.error; }); }
    var w = U.utf8Writer(path, format !== 'jsonl'), n = view.length, i = 0, buf = [], A = NS.filter.storeAccessor(store);
    var tagText = St.tagText || function () { return ''; };
    if (format === 'csv') { w.write(cols.map(function (c) { return U.csvCell(c.label); }).join(',') + '\r\n'); } else if (format === 'tle') {
      var hdr = X.TLE_COLS.slice(0); hdr[1] = 'Timestamp (' + (tzLabel || (tz && tz.label) || U.fmtOffset(U.tzOff(tz, Date.now()))) + ')';
      w.write(hdr.map(U.csvCell).join(',') + '\r\n');
    }
    IO.runSliced(function () {
      var end = Math.min(n, i + 2000), r, ix, line;
      for (; i < end; i++) {
        ix = view[i];
        if (format === 'csv') {
          line = []; for (var j = 0; j < cols.length; j++) { line.push(U.csvCell(cols[j].get(store, ix))); }
          buf.push(line.join(','));
        } else if (format === 'tle') {
          A.i = ix;
          var q = A.qi(), u = A.ui();
          r = [U.fmtTs(store.ts[ix]), U.fmtTs(store.ts[ix], tz), A.cip(), A.cls(), A.method(), St.colByKey.status.get(store, ix), A.stem(), q.dec, u.dec,
            store.taken[ix] < 0 ? '' : store.taken[ix], A.hits(), tagText(store, ix), store.files[store.file[ix]].name, store.line[ix], store.raw ? store.raw[ix] : ''];
          buf.push(r.map(U.csvCell).join(','));
        } else {
          A.i = ix;
          var o = { ts: U.fmtIso(store.ts[ix]), cip: A.cip(), eip: A.eip(), ipClass: A.cls(), sip: A.sip(), port: store.port[ix], method: A.method(),
            stem: A.stem(), query: A.query(), queryDecoded: A.qi().dec, status: store.status[ix], substatus: store.sub[ix], win32: store.win32[ix],
            timeTaken: store.taken[ix], scBytes: store.scb[ix], csBytes: store.csb[ix], userAgent: A.ua(), uaDecoded: A.ui().dec, uaFamily: A.ui().fam,
            user: A.user(), ruleHits: A.hits() ? A.hits().split(',') : [], tags: tagText(store, ix) ? tagText(store, ix).split(', ') : [],
            sourceFile: store.files[store.file[ix]].name, sourcePath: store.files[store.file[ix]].path, line: store.line[ix] };
          if (store.raw) { o.raw = store.raw[ix]; }
          buf.push(JSON.stringify(o));
        }
      }
      w.write(buf.join('\r\n') + (buf.length ? '\r\n' : '')); buf = [];
      if (progress) { progress({ file: 0, files: 0, rows: i, bytesDone: i, bytesTotal: n }); }
      return i >= n;
    }, function (err) {
      if (err) { done(err); return; }
      try { w.close(); } catch (e) { done(e); return; }
      done(null, X.finalize(path, 'rows-' + format, U.extend({ rows: n }, meta || {})));
    }, 40);
  };
  X.table = function (headers, rows, path, kind, meta) {
    var w = U.utf8Writer(path, true), i;
    w.write(headers.map(U.csvCell).join(',') + '\r\n');
    for (i = 0; i < rows.length; i++) { w.write(rows[i].map(U.csvCell).join(',') + '\r\n'); }
    w.close();
    return X.finalize(path, kind, U.extend({ rows: rows.length }, meta || {}));
  };
  X.json = function (obj, path, kind, meta) {
    U.writeTextUtf8(path, JSON.stringify(obj, null, 1), false);
    return X.finalize(path, kind, meta);
  };
  /* Original raw lines grouped by source file. Each line is written byte-for-byte as stored in the evidence file:
   * the reader maps every byte to one Windows-1252 character and this writer maps it back, so UTF-8 or any other
   * bytes are untouched (the grid shows the UTF-8-decoded form). Every line is followed by CRLF; a source line
   * that ended differently is marked in its "# line N" header. Header text is ASCII, non-ASCII escaped as \\uXXXX. */
  X.rawBundle = function (store, idxs, path) {
    if (!store.raw) { throw new Error('Raw lines were not retained for this load (Settings > keep raw lines).'); }
    var byFile = {}, order = [], i, ix, f, CRLF = String.fromCharCode(13, 10), BS = String.fromCharCode(92);
    for (i = 0; i < idxs.length; i++) {
      ix = idxs[i]; f = store.file[ix];
      if (!byFile[f]) { byFile[f] = []; order.push(f); }
      byFile[f].push(ix);
    }
    order.sort(function (a, b) { return a - b; });
    function hdr(s) { return s.replace(/[^ -~]/g, function (c) { return BS + 'u' + ('000' + c.charCodeAt(0).toString(16)).slice(-4); }) + CRLF; }
    var EOL_NOTE = { lf: ' (source line ended with LF only)', cr: ' (source line ended with CR only, at end of file)', none: ' (no line terminator in source: last line of a truncated file)' };
    var st = new ActiveXObject('ADODB.Stream');
    st.Type = 2; st.Charset = 'windows-1252'; st.Open();
    try {
      st.WriteText(hdr('# IIS Log Analyzer raw line bundle - ' + U.nowIso() + ' - ' + idxs.length + ' line(s)'));
      st.WriteText(hdr('# Each source line is reproduced byte-for-byte as stored in the evidence file and followed by CRLF.'));
      st.WriteText(hdr('# "# file:" gives the source path (non-ASCII as ' + BS + 'uXXXX) and "# line N" the 1-based line number.'));
      for (i = 0; i < order.length; i++) {
        var rows = byFile[order[i]].sort(function (a, b) { return store.line[a] - store.line[b]; });
        st.WriteText(hdr('# file: ' + store.files[order[i]].path));
        for (var j = 0; j < rows.length; j++) {
          ix = rows[j];
          st.WriteText(hdr('# line ' + store.line[ix] + (store.rawEol[ix] ? EOL_NOTE[store.rawEol[ix]] : '')));
          st.WriteText((store.rawOrig[ix] !== undefined ? store.rawOrig[ix] : store.raw[ix]) + CRLF);
        }
      }
      st.SaveToFile(path, 2);
    } finally { st.Close(); }
    return X.finalize(path, 'raw-bundle', { rows: idxs.length, encoding: 'original bytes (Windows-1252 byte mapping)' });
  };

  /* Zips the case workspace (minus tmp) with a hidden PowerShell Compress-Archive; polls for completion. */
  X.caseBundle = function (cb) {
    var out = X.outPath('case-bundle', 'zip'), ws = C.cur.ws, done = out + '.done', ps1 = U.joinPath(C.cur.tmp, 'bundle-' + Date.now() + '.ps1'), fso = U.fso();
    function q(s) { return "'" + s.replace(/'/g, "''") + "'"; }
    U.writeTextUtf8(ps1, [
      '$ErrorActionPreference = "Stop"',
      'try {',
      '  $items = Get-ChildItem -LiteralPath ' + q(ws) + ' | Where-Object { $_.Name -ne "tmp" -and $_.FullName -ne ' + q(U.parentOf(out)) + ' }',
      '  $ex = Get-ChildItem -LiteralPath ' + q(U.parentOf(out)) + ' -File | Where-Object { $_.Extension -ne ".zip" -and $_.Name -notlike "*.done" }',
      '  Compress-Archive -Path (@($items.FullName) + @($ex.FullName)) -DestinationPath ' + q(out) + ' -CompressionLevel Optimal',
      '  [IO.File]::WriteAllText(' + q(done) + ', "ok")',
      '} catch { [IO.File]::WriteAllText(' + q(done) + ', "ERROR " + $_.Exception.Message) }'
    ].join('\r\n'), true);
    U.shell().Run('powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + ps1 + '"', 0, false);
    var t0 = Date.now();
    (function poll() {
      if (fso.FileExists(done)) {
        var r = U.readTextUtf8(done); try { fso.DeleteFile(done, true); fso.DeleteFile(ps1, true); } catch (e) { }
        if (r.indexOf('ok') < 0) { cb(new Error(r)); return; }
        cb(null, X.finalize(out, 'case-bundle', { workspace: ws }));
        return;
      }
      if (Date.now() - t0 > 1800000) { cb(new Error('Timed out creating bundle')); return; }
      setTimeout(poll, 500);
    }());
  };

  /* ---------- HTML report ---------- */
  var E = U.escHtml;
  function tbl(headers, rows, cls) {
    var s = '<table class="' + (cls || '') + '"><thead><tr>', i, j;
    for (i = 0; i < headers.length; i++) { s += '<th>' + E(headers[i]) + '</th>'; }
    s += '</tr></thead><tbody>';
    for (i = 0; i < rows.length; i++) { s += '<tr>'; for (j = 0; j < rows[i].length; j++) { s += '<td>' + E(rows[i][j]) + '</td>'; } s += '</tr>'; }
    return s + '</tbody></table>';
  }
  function perDaySvg(idx) {
    var days = Object.keys(idx.perDay).sort(), n = days.length;
    if (!n) { return ''; }
    if (n > 400) { // aggregate by month
      var m = {}, keys = [], i;
      for (i = 0; i < n; i++) { var mk = days[i].substr(0, 7); if (!m[mk]) { m[mk] = [0, 0, 0, 0, 0, 0]; keys.push(mk); } for (var j = 0; j < 6; j++) { m[mk][j] += idx.perDay[days[i]][j]; } }
      return barsSvg(keys, keys.map(function (k) { return m[k]; }), 'month');
    }
    return barsSvg(days, days.map(function (d) { return idx.perDay[d]; }), 'day');
  }
  function barsSvg(labels, vals, unit) {
    var W = 980, H = 190, pl = 50, pb = 26, pt = 8, n = labels.length, max = 1, i;
    for (i = 0; i < n; i++) { max = Math.max(max, vals[i][0]); }
    var bw = (W - pl - 10) / n, ph = H - pb - pt, s = '<svg xmlns="http://www.w3.org/2000/svg" width="' + W + '" height="' + H + '" style="font:10px sans-serif">';
    var cols = ['#38a169', '#718096', '#dd6b20', '#c53030'];
    for (i = 0; i < n; i++) {
      var base = 0, x = pl + i * bw;
      for (var c = 0; c < 4; c++) {
        var v = vals[i][c + 1] || 0; if (!v) { continue; }
        var y1 = pt + ph - (base + v) / max * ph, hh = v / max * ph; base += v;
        s += '<rect x="' + x.toFixed(1) + '" y="' + y1.toFixed(1) + '" width="' + Math.max(0.8, bw - 0.6).toFixed(1) + '" height="' + Math.max(0.4, hh).toFixed(1) + '" fill="' + cols[c] + '"><title>' + E(labels[i]) + ': ' + v + '</title></rect>';
      }
    }
    var every = Math.max(1, Math.ceil(n / 12));
    for (i = 0; i < n; i += every) { s += '<text x="' + (pl + i * bw).toFixed(1) + '" y="' + (H - 8) + '">' + E(labels[i]) + '</text>'; }
    s += '<text x="0" y="12">' + E(U.fmtNum(max)) + '</text><text x="0" y="' + (pt + ph) + '">0</text>';
    s += '<text x="' + (W - 260) + '" y="12">rows per ' + unit + ': <tspan fill="#38a169">2xx</tspan> <tspan fill="#718096">3xx</tspan> <tspan fill="#dd6b20">4xx</tspan> <tspan fill="#c53030">5xx</tspan></text>';
    return s + '</svg>';
  }
  function fileName(idx, id) { return (idx.files[id] || {}).name || ('#' + id); }

  /* ctx: { caseData, idx, site, disc, manifest, ruleset, settings, auditEntries } */
  X.reportHtml = function (ctx) {
    var cd = ctx.caseData, idx = ctx.idx, tz = ctx.tz || NS.tz.forCase(cd), tzL = (tz && tz.label) || cd.displayTzLabel || '', i, f, d;
    var findings = idx.findings || [], disp = cd.dispositions || {};
    function dispOf(fi) { var x = disp[R.findingSig(fi)]; return x ? x.state : 'Needs review'; }
    function ts2(ms) { return ms ? U.fmtTs(ms) + ' UTC' : ''; }
    var css = 'body{font:13px/1.45 Segoe UI,Arial,sans-serif;color:#1a202c;margin:24px auto;max-width:1100px;padding:0 16px;background:#fff}' +
      'h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;border-bottom:2px solid #2b6cb0;padding-bottom:3px;margin-top:28px}h3{font-size:14px;margin:18px 0 6px}' +
      'table{border-collapse:collapse;width:100%;margin:6px 0 12px;font-size:12px}th,td{border:1px solid #cbd5e0;padding:3px 6px;text-align:left;vertical-align:top}' +
      'th{background:#edf2f7}td{word-break:break-all}.kv th{width:220px;word-break:normal}.mono,pre{font-family:Consolas,monospace;font-size:11.5px}' +
      'pre{background:#f7fafc;border:1px solid #e2e8f0;padding:6px;white-space:pre-wrap;word-break:break-all}' +
      '.sev{display:inline-block;padding:0 6px;border-radius:3px;color:#fff;font-size:11px}.critical{background:#742a2a}.high{background:#c53030}.medium{background:#dd6b20}.low{background:#d69e2e}.info{background:#718096}' +
      '.muted{color:#718096}.note{background:#fffbea;border-left:3px solid #d69e2e;padding:6px 10px;margin:8px 0}@media print{h2{page-break-after:avoid}}';
    var h = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' + E(cd.caseId) + ' - IIS log analysis</title><style>' + css + '</style></head><body>';
    h += '<h1>IIS Web Server Log Analysis</h1><div class="muted">Case ' + E(cd.caseId) + ' &middot; generated ' + E(U.nowIso()) + ' by IIS Log Analyzer ' + E(NS.VERSION) + '</div>';

    // 1. header
    h += '<h2>1. Case information</h2>' + tbl(['Field', 'Value'], [
      ['Case ID', cd.caseId], ['Examiner', cd.examiner], ['Evidence ID', cd.evidenceId], ['Source host', cd.sourceHost], ['Collection time (UTC)', cd.collectionUtc],
      ['Case description', cd.description], ['Report generated (UTC)', U.nowIso()], ['Tool version', NS.VERSION],
      ['Rule set', ctx.ruleset.version + ' (fingerprint ' + ctx.ruleset.hash + ')'], ['Display time zone', tzL + (tz && tz.kind === 'windows' ? ' (DST-aware: local times use the offset in force at each instant)' : '') + '; all times below are UTC unless labelled']
    ], 'kv');

    // 2. evidence
    var t = idx.totals, hashed = 0, man = 0, manBad = 0;
    for (i = 0; i < idx.files.length; i++) { f = idx.files[i]; if (f.sha256) { hashed++; } if (f.manifest) { man++; if (f.manifest.status !== 'match') { manBad++; } } }
    h += '<h2>2. Evidence summary</h2>' + tbl(['Item', 'Value'], [
      ['Evidence path (as collected)', idx.sitePath], ['Original path on source host', idx.siteDisplayPath], ['Site', idx.site + ' (' + idx.siteKind + ')'],
      ['Files', U.fmtNum(idx.files.length) + ' (' + U.fmtBytes(t.bytes) + ')'], ['Time span', ts2(t.firstTs) + '  to  ' + ts2(t.lastTs)],
      ['Rows (requests)', U.fmtNum(t.rows)], ['Lines read', U.fmtNum(t.lines)], ['Header blocks (#Fields)', U.fmtNum(t.blocks) + ' (' + U.fmtNum(idx.restarts.length) + ' mid-file restarts)'],
      ['Malformed rows', U.fmtNum(t.malformed)], ['Distinct client IPs / URI stems / user agents', U.fmtNum(idx.counts.ips) + ' / ' + U.fmtNum(idx.counts.stems) + ' / ' + U.fmtNum(idx.counts.uas)],
      ['IIS software', Object.keys(idx.softwares).join('; ')], ['Field layouts', idx.schemas.map(function (s) { return s.fields; }).join(' | ')],
      ['SHA-256 computed', hashed + ' of ' + idx.files.length + ' files' + (idx.hashes && idx.hashes.when ? ' at ' + idx.hashes.when : '')],
      ['Collector manifest cross-check', man ? (man - manBad) + ' match, ' + manBad + ' mismatch/missing (' + (ctx.manifest ? ctx.manifest.sources.join('; ') : '') + ')' : 'not available'],
      ['Scan status', idx.partial ? 'PARTIAL (' + idx.filesDone + ' of ' + idx.files.length + ' files)' : 'complete ' + idx.completedUtc]
    ], 'kv');
    h += perDaySvg(idx);

    // 3. methodology
    var lim = [];
    var absent = ['cs(Referer)', 'cs-host', 'sc-bytes', 'cs-bytes', 'cs(Cookie)', 'X-Forwarded-For'].filter(function (fl) { return idx.schemas.every(function (s) { return s.fields.toLowerCase().indexOf(fl.toLowerCase()) < 0; }); });
    if (absent.length) { lim.push('The following fields were not logged by the server and could not be analysed: ' + absent.join(', ') + '.'); }
    if (!idx.users || !U.countKeys(idx.users)) { lim.push('cs-username was empty for every request; application-level (forms) authentication cannot be attributed to accounts from these logs.'); }
    if (idx.caps.ipEvicted || idx.caps.stemEvicted || idx.caps.uaEvicted) { lim.push('Index cardinality caps were reached; low-frequency entries were evicted (IPs ' + idx.caps.ipEvicted + ', stems ' + idx.caps.stemEvicted + ', user agents ' + idx.caps.uaEvicted + '). Top-N tables are approximate for those dimensions.'); }
    var disabled = ctx.ruleset.rules.filter(function (r) { return !r.enabled; }).map(function (r) { return r.id; });
    if (disabled.length) { lim.push('Rules disabled for this case: ' + disabled.join(', ') + '.'); }
    if (idx.partial) { lim.push('The scan was not completed; results cover only the files processed.'); }
    h += '<h2>3. Methodology and limitations</h2><p>Log files were opened read-only from the evidence location and parsed as W3C Extended format, re-binding the field list at every #Fields directive. ' +
      'Every row was evaluated against the rule set listed in section 1; aggregate rules ran over the resulting index. Times in IIS W3C logs are recorded in UTC. ' +
      'Client classification uses address ranges only; no online enrichment (GeoIP, DNS, threat intelligence) was performed by the tool. Findings are leads for examiner review; dispositions recorded by the examiner are shown with each finding.</p>';
    if (lim.length) { h += '<ul>' + lim.map(function (l) { return '<li>' + E(l) + '</li>'; }).join('') + '</ul>'; }

    // 4. executive findings
    var tp = findings.filter(function (fi) { return dispOf(fi) === 'True positive'; });
    var review = findings.filter(function (fi) { return dispOf(fi) === 'Needs review' && (fi.severity === 'critical' || fi.severity === 'high'); });
    h += '<h2>4. Key findings</h2>';
    if (tp.length) {
      h += '<h3>Confirmed by examiner (true positive)</h3>' + tbl(['ID', 'Severity', 'Rule', 'Entity', 'First / last (UTC)', 'Detail', 'Examiner note'], tp.map(function (fi) {
        var dd = disp[R.findingSig(fi)];
        return [fi.id, fi.severity, fi.ruleId + ' ' + fi.name, fi.entity + ': ' + fi.key, U.fmtTs(fi.first) + ' / ' + U.fmtTs(fi.last), fi.detail, dd ? dd.note : ''];
      }));
    } else { h += '<p class="muted">No finding has been marked true positive yet.</p>'; }
    if (review.length) {
      h += '<h3>Critical / high findings awaiting review</h3>' + tbl(['ID', 'Severity', 'Rule', 'Entity', 'First / last (UTC)', 'Detail'], review.slice(0, 200).map(function (fi) {
        return [fi.id, fi.severity, fi.ruleId + ' ' + fi.name, fi.entity + ': ' + fi.key, U.fmtTs(fi.first) + ' / ' + U.fmtTs(fi.last), fi.detail];
      }));
    }
    var sevCount = {}; findings.forEach(function (fi) { sevCount[fi.severity] = (sevCount[fi.severity] || 0) + 1; });
    h += '<p>All findings: ' + R.SEV_NAMES.map(function (s) { return E(s) + ' ' + (sevCount[s] || 0); }).join(', ') + '.</p>';

    // 5. infrastructure
    var infra = {}, k;
    var ipTags = cd.tags.ips || {};
    for (k in ipTags) { infra[k] = { tags: ipTags[k].join(', '), why: 'tagged' }; }
    tp.forEach(function (fi) { (fi.ips || []).slice(0, 25).forEach(function (ip) { if (!infra[ip]) { infra[ip] = { tags: '', why: '' }; } infra[ip].why += (infra[ip].why ? ', ' : '') + fi.id; }); });
    var infraRows = [];
    for (k in infra) {
      var ir = idx.ips[k] || {};
      infraRows.push([k, ir.cls || U.classifyIp(k), infra[k].tags, infra[k].why, ts2(ir.first), ts2(ir.last), U.fmtNum(ir.n || 0), ir.n ? U.pct(ir.s4, ir.n) : '', U.countKeys(ir.hits || {}) ? Object.keys(ir.hits).join(' ') : '']);
    }
    infraRows.sort(function (a, b) { return a[4] < b[4] ? -1 : 1; });
    h += '<h2>5. Attacker infrastructure</h2>' + (infraRows.length ? tbl(['IP', 'Class', 'Tags', 'Source', 'First seen', 'Last seen', 'Requests', '4xx share', 'Rule hits'], infraRows) : '<p class="muted">No IPs tagged or linked to true-positive findings.</p>');

    // 6. timeline
    var ev = [];
    for (k in idx.ruleHits) {
      if (R.EXPLOIT_RULES[k] || /^R-WS/.test(k)) { var rh = idx.ruleHits[k], ex = rh.kept[0]; ev.push([rh.first, 'First ' + k + ' hit', ex ? ex[3] + ' ' + fileName(idx, ex[0]) + ':' + ex[1] : '']); }
    }
    findings.forEach(function (fi) { if ((fi.severity === 'critical' || dispOf(fi) === 'True positive') && fi.first) { ev.push([fi.first, fi.id + ' ' + fi.name, fi.entity + ': ' + fi.key]); } });
    idx.gaps.forEach(function (g) { ev.push([g.from, 'Logging gap ' + g.hours.toFixed(1) + ' h begins', 'resumes ' + U.fmtTs(g.to)]); });
    (cd.notes || []).forEach(function (n) { if (n.type === 'time') { ev.push([+n.key, 'Examiner note', n.text]); } });
    (cd.bookmarks || []).forEach(function (b) { ev.push([b.ts, 'Bookmark: ' + (b.label || ''), b.ref || '']); });
    ev.sort(function (a, b) { return a[0] - b[0]; });
    h += '<h2>6. Timeline of key events</h2>' + (ev.length ? tbl(['Time (UTC)', 'Time (' + tzL + ')', 'Event', 'Detail'], ev.slice(0, 500).map(function (e) { return [U.fmtTs(e[0]), U.fmtTs(e[0], tz), e[1], e[2]]; })) : '<p class="muted">No events.</p>');

    // 7. detailed findings
    h += '<h2>7. Findings detail</h2>';
    var shown = findings.filter(function (fi) { return dispOf(fi) !== 'False positive'; }).slice(0, 300);
    for (i = 0; i < shown.length; i++) {
      f = shown[i]; d = disp[R.findingSig(f)];
      h += '<h3>' + E(f.id) + ' <span class="sev ' + E(f.severity) + '">' + E(f.severity) + '</span> ' + E(f.ruleId) + ' &ndash; ' + E(f.name) + '</h3>';
      h += tbl(['Field', 'Value'], [['Entity', f.entity + ': ' + f.key], ['Count', U.fmtNum(f.count)], ['First / last (UTC)', U.fmtTs(f.first) + ' / ' + U.fmtTs(f.last)],
        ['Detail', f.detail], ['ATT&CK', (f.attack || []).join(', ')], ['Disposition', (d ? d.state + (d.note ? ' - ' + d.note : '') + ' (' + d.examiner + ', ' + d.ts + ')' : 'Needs review')],
        ['Clients', (f.ips || []).slice(0, 25).join(', ')], ['Paths', (f.stems || []).slice(0, 15).join('  ')], ['Description', f.description], ['False positive notes', f.falsePositives]], 'kv');
      if (f.examples && f.examples.length) {
        h += '<pre>' + f.examples.slice(0, 10).map(function (x) { return E(fileName(idx, x[0]) + ':' + x[1] + '  ' + (x[5] !== undefined ? (x[5] >= 0 ? x[5] : '-') + '  ' : '') + (x[4] || U.fmtTs(x[2]) + ' UTC  ' + x[3] + '  (raw line not kept)')); }).join('\n') + '</pre>';
      }
    }
    if (findings.length > shown.length) { h += '<p class="muted">' + (findings.length - shown.length) + ' further finding(s) omitted (false positives or beyond the first 300).</p>'; }

    // 8. integrity
    var integ = findings.filter(function (fi) { return /^R-INF/.test(fi.ruleId); });
    var manRows = [];
    for (i = 0; i < idx.files.length; i++) { f = idx.files[i]; if (f.manifest && f.manifest.status !== 'match') { manRows.push([f.name, f.manifest.status, f.manifest.detail || '']); } }
    h += '<h2>8. Log integrity observations</h2>';
    h += integ.length ? tbl(['ID', 'Rule', 'Entity', 'Detail'], integ.slice(0, 300).map(function (fi) { return [fi.id, fi.ruleId + ' ' + fi.name, fi.entity + ': ' + fi.key, fi.detail]; })) : '<p>No integrity rule fired.</p>';
    if (manRows.length) { h += '<h3>Manifest discrepancies</h3>' + tbl(['File', 'Status', 'Detail'], manRows); }
    if (idx.missingFiles.length) { h += '<p>Missing daily files: ' + E(idx.missingFiles.join(', ')) + '</p>'; }

    // 9. appendix
    h += '<h2>9. Appendix</h2>';
    var audits = ctx.auditEntries || [];
    var exportsA = audits.filter(function (a) { return a.action === 'export'; });
    h += '<h3>Exports produced</h3>' + (exportsA.length ? tbl(['Time (UTC)', 'Kind', 'Path', 'SHA-256', 'Rows'], exportsA.map(function (a) { return [a.ts, a.params.kind, a.params.path, a.params.sha256, a.params.rows === undefined ? '' : a.params.rows]; })) : '<p class="muted">None.</p>');
    var filt = audits.filter(function (a) { return a.action === 'grid.filter' || a.action === 'load'; });
    h += '<h3>Filters and loads applied</h3>' + (filt.length ? tbl(['Time (UTC)', 'Action', 'Parameters'], filt.slice(-200).map(function (a) { return [a.ts, a.action, JSON.stringify(a.params)]; })) : '<p class="muted">None.</p>');
    var hashRows = [];
    for (i = 0; i < idx.files.length; i++) { f = idx.files[i]; hashRows.push([f.name, U.fmtNum(f.size), f.sha256 || '', f.manifest ? f.manifest.status : '', U.fmtNum(f.rows || 0)]); }
    h += '<h3>Evidence files and hashes</h3>' + tbl(['File', 'Bytes', 'SHA-256', 'Manifest', 'Rows'], hashRows, 'mono');
    h += '<h3>Audit log (last 300 entries)</h3><pre>' + audits.slice(-300).map(function (a) { return E(a.ts + '  ' + a.action + '  ' + JSON.stringify(a.params)); }).join('\n') + '</pre>';
    h += '</body></html>';
    return h;
  };
  X.report = function (ctx) {
    var p = X.outPath('report', 'html', C.cur.reports);
    U.writeTextUtf8(p, X.reportHtml(ctx), true);
    return X.finalize(p, 'report', { findings: (ctx.idx.findings || []).length });
  };
}(IISLA));
