/* IIS Log Analyzer - io.js
 * Evidence discovery, Velociraptor manifest cross-check, chunked line reader,
 * time-sliced task runner and out-of-process hashing.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io = {};

  function each(coll, fn) {
    var e = new Enumerator(coll);
    for (; !e.atEnd(); e.moveNext()) { fn(e.item()); }
  }
  IO.each = each;

  /* ---------- Velociraptor path decoding ---------- */
  /* Maps an on-disk path inside a Velociraptor collection back to the original
   * path on the source host, e.g. ...\uploads\file\C%3A\inetpub\... -> C:\inetpub\... */
  IO.originalPath = function (p) {
    var m = /\\uploads\\(?:file|auto|ntfs|mft)\\(.+)$/i.exec(p);
    if (!m) { return ''; }
    var parts = m[1].split('\\'), i, out = [];
    for (i = 0; i < parts.length; i++) { out.push(U.pctDecode(parts[i], false).t); }
    var s = out.join('\\');
    s = s.replace(/^\\\\\.\\/, '').replace(/^\\\\\?\\/, '');
    return s;
  };
  IO.collectionRoot = function (p) {
    var m = /^(.*?)\\uploads\\/i.exec(p);
    return m ? m[1] : '';
  };
  IO.parseCollectionName = function (root) {
    // Collection-<host>-<YYYY-MM-DDTHH_MM_SS_...>
    var b = U.baseOf(root || ''), m = /^Collection-(.+?)-(\d{4}-\d{2}-\d{2}T\d{2}_\d{2}_\d{2})/.exec(b);
    if (!m) { return null; }
    return { host: m[1], time: m[2].replace(/_/g, ':').replace('T', ' ') };
  };

  /* ---------- discovery ---------- */
  var SITE_RE = /^(W3SVC|FTPSVC|SMTPSVC)(\d+)$/i;
  IO.siteKind = function (name) {
    var m = SITE_RE.exec(name);
    if (m) { return m[1].toUpperCase() === 'W3SVC' ? 'web' : (m[1].toUpperCase() === 'FTPSVC' ? 'ftp' : 'smtp'); }
    if (/^HTTPERR$/i.test(name)) { return 'httperr'; }
    return 'other';
  };
  IO.FILE_PATTERNS = [
    { re: /^u_ex(\d{2})(\d{2})(\d{2})(\d{2})\.log$/i, kind: 'hourly' },
    { re: /^u_ex(\d{2})(\d{2})(\d{2})\.log$/i, kind: 'daily' },
    { re: /^u_ex(\d{2})(\d{2})\.log$/i, kind: 'monthly' },
    { re: /^u_extend\d+\.log$/i, kind: 'unlimited' },
    { re: /^httperr\d+\.log$/i, kind: 'httperr' },
    { re: /^(u_)?(in|nc)\d+\.log$/i, kind: 'unsupported' }
  ];
  IO.nameInfo = function (name) {
    var i, m;
    for (i = 0; i < IO.FILE_PATTERNS.length; i++) {
      m = IO.FILE_PATTERNS[i].re.exec(name);
      if (m) {
        var k = IO.FILE_PATTERNS[i].kind, d = null;
        if (k === 'daily' || k === 'hourly') { d = '20' + m[1] + '-' + m[2] + '-' + m[3]; }
        if (k === 'monthly') { d = '20' + m[1] + '-' + m[2]; }
        return { kind: k, date: d, hour: k === 'hourly' ? +m[4] : -1 };
      }
    }
    return { kind: 'unknown', date: null, hour: -1 };
  };

  /* Returns { root, isFile, sites:[{name,kind,path,displayPath,files:[...]}], warnings:[] } */
  IO.discover = function (root, maxDepth) {
    var fso = U.fso(), res = { root: root, isFile: false, sites: [], warnings: [], totalBytes: 0, totalFiles: 0 };
    var groups = {}, order = [];
    if (maxDepth === undefined) { maxDepth = 3; }
    function addFile(folderPath, f) {
      var key = folderPath.toLowerCase();
      if (!groups[key]) {
        var nm = U.baseOf(folderPath);
        groups[key] = { name: nm, kind: IO.siteKind(nm), path: folderPath, displayPath: IO.originalPath(folderPath) || folderPath, files: [] };
        order.push(key);
      }
      var name = f.Name, ni = IO.nameInfo(name);
      groups[key].files.push({ name: name, path: f.Path, size: +f.Size, mtime: +new Date(f.DateLastModified),
        ctime: +new Date(f.DateCreated), nameKind: ni.kind, nameDate: ni.date, nameHour: ni.hour,
        displayPath: IO.originalPath(f.Path) || f.Path });
    }
    function walk(folder, depth) {
      var subs = [];
      try {
        each(folder.Files, function (f) { if (/\.log$/i.test(f.Name)) { addFile(folder.Path, f); } });
        each(folder.SubFolders, function (sf) { subs.push(sf); });
      } catch (e) { res.warnings.push('Cannot list ' + folder.Path + ': ' + e.message); return; }
      if (depth >= maxDepth) { return; }
      subs.sort(function (a, b) { return a.Name < b.Name ? -1 : 1; });
      var i;
      for (i = 0; i < subs.length; i++) { walk(subs[i], depth + 1); }
    }
    if (fso.FileExists(root)) {
      res.isFile = true;
      var f = fso.GetFile(root);
      addFile(fso.GetParentFolderName(root), f);
    } else if (fso.FolderExists(root)) {
      walk(fso.GetFolder(root), 0);
    } else {
      throw new Error('Path not found: ' + root);
    }
    var i, g;
    for (i = 0; i < order.length; i++) {
      g = groups[order[i]];
      g.files.sort(function (a, b) { return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1; });
      g.totalBytes = 0;
      for (var j = 0; j < g.files.length; j++) { g.totalBytes += g.files[j].size; }
      res.totalBytes += g.totalBytes; res.totalFiles += g.files.length;
      res.sites.push(g);
    }
    // Most specific / largest site first.
    res.sites.sort(function (a, b) { return (a.kind === 'web' ? 0 : 1) - (b.kind === 'web' ? 0 : 1) || b.totalBytes - a.totalBytes; });
    return res;
  };

  /* ---------- Velociraptor manifests ---------- */
  /* Searches ancestors for uploads.json and results\*.json carrying SHA256 values.
   * Returns { root, entries: { lowerOriginalPath: {fileSize, uploadedSize, sha256, md5, recordedSize} }, sources: [] } */
  IO.loadManifest = function (anyPath) {
    var fso = U.fso(), dir = fso.FolderExists(anyPath) ? anyPath : fso.GetParentFolderName(anyPath), i, found = null;
    for (i = 0; i < 8 && dir; i++) {
      if (fso.FileExists(U.joinPath(dir, 'uploads.json'))) { found = dir; break; }
      var p = fso.GetParentFolderName(dir); if (!p || p === dir) { break; } dir = p;
    }
    if (!found) { return null; }
    var man = { root: found, entries: U.newMap(), sources: [], hashCount: 0 };
    function key(p) { return ('' + p).replace(/^\\\\\.\\/, '').replace(/^\\\\\?\\/, '').toLowerCase(); }
    function ent(p) { var k = key(p); if (!man.entries[k]) { man.entries[k] = {}; } return man.entries[k]; }
    // Velociraptor JSONL is read with FSO (fast); only lines mentioning .log are parsed. Non-ASCII path bytes may be
    // mis-decoded, which only means such files are reported as not found in the manifest.
    function eachJsonLine(path, fn) {
      var t = U.readTextAnsi(path), lines = t.split('\n'), j, o;
      for (j = 0; j < lines.length; j++) {
        if (lines[j].length < 2 || lines[j].toLowerCase().indexOf('.log') < 0) { continue; }
        try { o = JSON.parse(lines[j]); } catch (e) { continue; }
        fn(o);
      }
    }
    try {
      eachJsonLine(U.joinPath(found, 'uploads.json'), function (o) {
        if (!o.vfs_path || !/\.log$/i.test(o.vfs_path)) { return; }
        var e = ent(o.vfs_path); e.fileSize = +o.file_size; e.uploadedSize = +o.uploaded_size;
      });
      man.sources.push('uploads.json');
    } catch (e1) { man.error = 'uploads.json: ' + e1.message; }
    var rdir = U.joinPath(found, 'results');
    if (fso.FolderExists(rdir)) {
      each(fso.GetFolder(rdir).Files, function (f) {
        if (!/\.json$/i.test(f.Name) || f.Size > 400 * 1024 * 1024) { return; }
        var hits = 0;
        try {
          // Cheap pre-check before parsing large result files.
          eachJsonLine(f.Path, function (o) {
            var p = o.FullPath || o.OSPath || o.SourceFile || o.Path;
            var h = o.SHA256 || o.Sha256 || (o.Hash && (o.Hash.SHA256 || o.Hash.Sha256));
            if (!p || !h || !/\.log$/i.test(p)) { return; }
            var e = ent(p); e.sha256 = ('' + h).toLowerCase(); if (o.Md5 || o.MD5) { e.md5 = ('' + (o.Md5 || o.MD5)).toLowerCase(); }
            if (o.Size !== undefined) { e.recordedSize = +o.Size; }
            hits++;
          });
        } catch (e2) { /* ignore unreadable result file */ }
        if (hits) { man.sources.push('results\\' + f.Name + ' (' + hits + ' hashes)'); man.hashCount += hits; }
      });
    }
    return man;
  };
  IO.manifestLookup = function (man, file) {
    if (!man || !file.displayPath) { return null; }
    return man.entries[file.displayPath.toLowerCase()] || null;
  };

  /* ---------- applicationHost.config (optional site id -> name/bindings) ---------- */
  IO.findAppHostConfig = function (collectionRoot) {
    if (!collectionRoot) { return ''; }
    var tail = '\\Windows\\System32\\inetsrv\\config\\applicationHost.config';
    var rels = ['uploads\\file\\C%3A' + tail, 'uploads\\auto\\C%3A' + tail, 'uploads\\ntfs\\%5C%5C.%5CC%3A' + tail], i, p;
    for (i = 0; i < rels.length; i++) { p = U.joinPath(collectionRoot, rels[i]); if (U.fileExists(p)) { return p; } }
    return '';
  };
  /* Returns { path, sites: { id: {name, id, bindings:[], logDir, apps:[]} } } or null. DTDs are prohibited. */
  IO.loadAppHostConfig = function (path) {
    if (!path || !U.fileExists(path)) { return null; }
    var x = new ActiveXObject('MSXML2.DOMDocument.6.0');
    x.async = false; x.resolveExternals = false; x.validateOnParse = false;
    try { x.setProperty('ProhibitDTD', true); } catch (e) { }
    if (!x.load(path)) { throw new Error(x.parseError.reason + ' (line ' + x.parseError.line + ')'); }
    var out = { path: path, sites: {} }, nodes = x.selectNodes('//system.applicationHost/sites/site'), i, j, n, b, s, lf, apps, vd;
    for (i = 0; i < nodes.length; i++) {
      n = nodes[i];
      s = { name: n.getAttribute('name') || '', id: n.getAttribute('id') || '', bindings: [], logDir: '', apps: [] };
      b = n.selectNodes('bindings/binding');
      for (j = 0; j < b.length; j++) { s.bindings.push((b[j].getAttribute('protocol') || '') + ' ' + (b[j].getAttribute('bindingInformation') || '')); }
      lf = n.selectSingleNode('logFile'); if (lf) { s.logDir = lf.getAttribute('directory') || ''; }
      apps = n.selectNodes('application');
      for (j = 0; j < apps.length; j++) { vd = apps[j].selectSingleNode('virtualDirectory'); s.apps.push((apps[j].getAttribute('path') || '') + ' -> ' + (vd ? vd.getAttribute('physicalPath') : '')); }
      out.sites[s.id] = s;
    }
    return out;
  };
  IO.siteInfo = function (appHost, siteName) {
    var m = /^(?:W3SVC|FTPSVC)(\d+)$/i.exec(siteName || '');
    return appHost && m ? appHost.sites[m[1]] || null : null;
  };

  /* ---------- chunked line reader ---------- */
  /* Reads the file as Windows-1252 (lossless for every byte) in 64 KB reads, about 1-4 MB per call, and returns
   * arrays of complete lines (CR stripped). Two backends with identical output:
   *  - ADODB.Stream (fast), but LoadFromFile buffers the whole file in memory, so it is used only for files up to
   *    settings.streamAboveMB;
   *  - Scripting.FileSystemObject text stream, which reads incrementally (memory bounded by the chunk size), for
   *    larger files, provided a one-time self-test shows it decodes all 256 byte values exactly like ADODB
   *    windows-1252 (the case when the system ANSI code page is 1252). Otherwise ADODB is used for every file.
   * UTF-8 re-decoding of non-ASCII lines happens in the parser (U.fixUtf8). */
  IO.STREAM_ABOVE_MB = 32;
  var fsoStreamOk = null;
  IO.fsoStreamOk = function () {
    if (fsoStreamOk !== null) { return fsoStreamOk; }
    fsoStreamOk = false;
    var fso = U.fso(), p = U.joinPath(U.env('TEMP'), 'iisla-cp1252-' + Date.now() + '.bin'), chars = [], b, st, ref, got, ts;
    try {
      for (b = 0; b < 256; b++) { chars.push(String.fromCharCode(b >= 0x80 && b < 0xA0 ? U.CP1252_HIGH[b - 0x80] : b)); }
      st = new ActiveXObject('ADODB.Stream'); st.Type = 2; st.Charset = 'windows-1252'; st.Open();
      st.WriteText(chars.join('')); st.SaveToFile(p, 2); st.Close();
      st = new ActiveXObject('ADODB.Stream'); st.Type = 2; st.Charset = 'windows-1252'; st.Open(); st.LoadFromFile(p); ref = st.ReadText(-1); st.Close();
      ts = fso.OpenTextFile(p, 1, false, 0); got = ts.Read(4096); ts.Close();
      fsoStreamOk = ref.length === 256 && got === ref;
    } catch (e) { fsoStreamOk = false; }
    try { if (fso.FileExists(p)) { fso.DeleteFile(p, true); } } catch (e2) { }
    return fsoStreamOk;
  };
  IO.LineReader = function (path, chunkChars, size, settings) {
    this.path = path;
    this.chunk = Math.min(chunkChars || 1048576, 4194304);
    if (size === undefined || size === null) { size = U.fso().GetFile(path).Size; }
    var limMB = IO.streamOverrideMB > 0 ? IO.streamOverrideMB : (settings && settings.streamAboveMB > 0 ? settings.streamAboveMB : IO.STREAM_ABOVE_MB);
    this.streaming = size > limMB * 1048576 && IO.fsoStreamOk();
    if (this.streaming) {
      this.ts = U.fso().OpenTextFile(path, 1, false, 0);
    } else {
      var st = new ActiveXObject('ADODB.Stream');
      st.Type = 2; st.Charset = 'windows-1252'; st.Open();
      try { st.LoadFromFile(path); } catch (e) { try { st.Close(); } catch (e2) { } throw e; }
      this.ts = st;
    }
    this.rest = '';
    this.done = false;
    this.charsRead = 0;
    this.tailNoEol = false;
    this.crlf = 0;
    this.lfOnly = 0;
  };
  IO.LineReader.prototype.next = function () {
    if (this.done) { return null; }
    var parts = [], got = 0, piece;
    if (this.streaming) {
      while (!this.ts.AtEndOfStream && got < this.chunk) { piece = this.ts.Read(65536); parts.push(piece); got += piece.length; }
    } else {
      while (!this.ts.EOS && got < this.chunk) { piece = this.ts.ReadText(65536); parts.push(piece); got += piece.length; }
    }
    this.charsRead += got;
    var text = this.rest + parts.join(''), lines, last;
    if (this.streaming ? this.ts.AtEndOfStream : this.ts.EOS) {
      this.done = true;
      if (!text) { this.close(); return []; }
      lines = text.split('\n');
      last = lines.pop();
      if (last !== '') { this.tailNoEol = true; lines.push(last); }
      this.close();
    } else {
      lines = text.split('\n');
      this.rest = lines.pop();
    }
    // eolExc: index -> 'lf' | 'cr' | 'none' for lines of this batch that did not end with CRLF (exact raw export)
    var i, l, n = lines.length, exc = null, tail;
    for (i = 0; i < n; i++) {
      l = lines[i]; tail = this.done && this.tailNoEol && i === n - 1;
      if (l.charCodeAt(l.length - 1) === 13) { lines[i] = l.substr(0, l.length - 1); this.crlf++; if (tail) { (exc || (exc = {}))[i] = 'cr'; } } else if (!tail) { this.lfOnly++; (exc || (exc = {}))[i] = 'lf'; } else { (exc || (exc = {}))[i] = 'none'; }
    }
    this.eolExc = exc;
    return lines;
  };
  IO.LineReader.prototype.close = function () {
    if (this.ts) { try { this.ts.Close(); } catch (e) { } this.ts = null; }
  };

  /* Reads lines [from, to] (1-based, inclusive) of a file asynchronously. */
  IO.readLineRange = function (path, from, to, cb) {
    var rd, lineNo = 0, out = [];
    try { rd = new IO.LineReader(path, 2097152); } catch (e) { cb(e, null); return; }
    IO.runSliced(function () {
      var lines = rd.next(), i;
      if (lines === null) { return true; }
      for (i = 0; i < lines.length; i++) {
        lineNo++;
        if (lineNo >= from && lineNo <= to) { out.push({ n: lineNo, t: lines[i] }); }
      }
      if (lineNo >= to) { rd.close(); return true; }
      return false;
    }, function (err) { cb(err, out); }, 30);
  };

  /* ---------- time-sliced runner ---------- */
  /* step() returns true when complete. Runs step repeatedly for ~sliceMs, then yields. */
  IO.runSliced = function (step, done, sliceMs, token) {
    sliceMs = sliceMs || 25;
    function tick() {
      var t0 = Date.now(), fin = false;
      try {
        while (!fin && Date.now() - t0 < sliceMs) {
          if (token && token.cancelled) { done(null, true); return; }
          fin = step();
        }
      } catch (e) { done(e, false); return; }
      if (fin) { done(null, false); } else { setTimeout(tick, 0); }
    }
    setTimeout(tick, 0);
  };

  /* ---------- hashing (out of process, hidden, async) ---------- */
  /* Hashes paths with PowerShell Get-FileHash (SHA-256) in a hidden process.
   * cb(err, map lowerPath -> hash, failures[]) ; progress(nDone, nTotal) */
  IO.hashFiles = function (paths, workDir, cb, progress, token) {
    var fso = U.fso();
    U.ensureFolder(workDir);
    var id = 'hash-' + Date.now() + '-' + Math.floor(Math.random() * 1e6);
    var list = U.joinPath(workDir, id + '.list'), out = U.joinPath(workDir, id + '.out'),
      prog = U.joinPath(workDir, id + '.progress'), doneF = U.joinPath(workDir, id + '.done'), ps1 = U.joinPath(workDir, id + '.ps1');
    U.writeTextUtf8(list, paths.join('\r\n'), true);
    function q(s) { return "'" + s.replace(/'/g, "''") + "'"; }
    var script = [
      '$ErrorActionPreference = "Continue"',
      '$o = New-Object System.Collections.Generic.List[string]',
      '$n = 0',
      'foreach ($p in [IO.File]::ReadAllLines(' + q(list) + ', [Text.Encoding]::UTF8)) {',
      '  if (-not $p) { continue }',
      '  try { $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash; $o.Add($h + "|" + $p) }',
      '  catch { $o.Add("ERROR|" + $p) }',
      '  $n++; if ($n % 25 -eq 0) { [IO.File]::WriteAllText(' + q(prog) + ', [string]$n) }',
      '}',
      '[IO.File]::WriteAllLines(' + q(out) + ', $o, (New-Object Text.UTF8Encoding($false)))',
      '[IO.File]::WriteAllText(' + q(doneF) + ', "1")'
    ].join('\r\n');
    U.writeTextUtf8(ps1, script, true);
    var cmd = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + ps1 + '"';
    try { U.shell().Run(cmd, 0, false); } catch (e) { cb(e, null, []); return; }
    var t0 = Date.now();
    function cleanup() {
      var fs = [list, out, prog, doneF, ps1], i;
      for (i = 0; i < fs.length; i++) { try { if (fso.FileExists(fs[i])) { fso.DeleteFile(fs[i], true); } } catch (e) { } }
    }
    function poll() {
      if (token && token.cancelled) { cleanup(); cb(new Error('Cancelled'), null, []); return; }
      if (fso.FileExists(doneF)) {
        var map = U.newMap(), fails = [], lines = U.readTextUtf8(out).split(/\r?\n/), i, l, bar;
        for (i = 0; i < lines.length; i++) {
          l = lines[i]; if (l.charCodeAt(0) === 0xFEFF) { l = l.substr(1); }
          bar = l.indexOf('|'); if (bar < 0) { continue; }
          if (l.substr(0, bar) === 'ERROR') { fails.push(l.substr(bar + 1)); } else { map[l.substr(bar + 1).toLowerCase()] = l.substr(0, bar).toLowerCase(); }
        }
        cleanup(); cb(null, map, fails); return;
      }
      if (progress && fso.FileExists(prog)) { try { progress(+U.readTextUtf8(prog), paths.length); } catch (e) { } }
      if (Date.now() - t0 > 6 * 3600 * 1000) { cleanup(); cb(new Error('Hashing timed out'), null, []); return; }
      setTimeout(poll, 400);
    }
    setTimeout(poll, 300);
  };
  /* Synchronous single-file hash via certutil (used for export sidecars). */
  IO.hashFileSync = function (path, workDir) {
    var tmp = U.joinPath(workDir, 'certutil-' + Date.now() + '.txt'), fso = U.fso();
    U.ensureFolder(workDir);
    var cmd = 'cmd.exe /c certutil -hashfile "' + path + '" SHA256 > "' + tmp + '" 2>&1';
    U.shell().Run(cmd, 0, true);
    var t = '';
    try { var ts = fso.OpenTextFile(tmp, 1, false, 0); t = ts.AtEndOfStream ? '' : ts.ReadAll(); ts.Close(); fso.DeleteFile(tmp, true); } catch (e) { }
    var m = /^\s*([0-9a-f]{2}(?:\s?[0-9a-f]{2}){31})\s*$/im.exec(t);
    return m ? m[1].replace(/\s/g, '').toLowerCase() : '';
  };

  /* ---------- app folder / resources ---------- */
  IO.appFolder = function () {
    var p = decodeURIComponent(('' + document.location.pathname).replace(/^\/+/, '')).replace(/\//g, '\\');
    if (/^[A-Za-z]:/.test(p) === false && document.location.host) { p = '\\\\' + document.location.host + '\\' + p; }
    return U.parentOf(p);
  };
  /* Loads a text resource: embedded <script type="text/plain" data-res="name"> first, else file. */
  IO.resource = function (relPath) {
    var els = document.getElementsByTagName('script'), i;
    for (i = 0; i < els.length; i++) {
      if (els[i].getAttribute('data-res') === relPath) { return els[i].text; }
    }
    var p = U.joinPath(IO.appFolder(), relPath.replace(/\//g, '\\'));
    if (!U.fileExists(p)) { return null; }
    var t = U.readTextUtf8(p);
    if (t.charCodeAt(0) === 0xFEFF) { t = t.substr(1); }
    return t;
  };
}(IISLA));
