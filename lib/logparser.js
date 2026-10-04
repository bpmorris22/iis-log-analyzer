/* IIS Log Analyzer - logparser.js
 * Optional bridge to Microsoft Log Parser 2.2 (LogParser.exe) for ad-hoc SQL over the evidence logs.
 * Nothing is downloaded or installed by the tool: Log Parser is used only if it is already present.
 * The examiner's SQL is written to a query file (LogParser file:<query.sql>), so query text never
 * reaches a command line; the batch file only contains workspace paths.
 */
(function (NS) {
  'use strict';
  var U = NS.util, LP = NS.logparser = {};

  LP.candidates = function (settings) {
    var out = [], p = U.expandEnv((settings && settings.logParserPath) || '');
    if (p) { out.push(p); }
    var pf86 = U.env('ProgramFiles(x86)'), pf = U.env('ProgramFiles');
    if (pf86) { out.push(U.joinPath(pf86, 'Log Parser 2.2\\LogParser.exe')); }
    if (pf) { out.push(U.joinPath(pf, 'Log Parser 2.2\\LogParser.exe')); }
    return out;
  };
  LP.find = function (settings) {
    var c = LP.candidates(settings), i;
    for (i = 0; i < c.length; i++) { if (U.fileExists(c[i])) { return c[i]; } }
    return '';
  };
  /* Official Microsoft download page (Log Parser 2.2.10, LogParser.msi). Opened in the user's browser on request only. */
  LP.DOWNLOAD_URL = 'https://www.microsoft.com/en-us/download/details.aspx?id=24659';
  /* Traffic-light status: green = LogParser.exe found; amber = a path is set in Settings but nothing is there and no
   * default install exists; red = not installed. */
  LP.status = function (settings) {
    var exe = LP.find(settings), set = U.trim((settings && settings.logParserPath) || '');
    if (exe) { return { state: 'green', exe: exe, label: 'Log Parser 2.2 installed', detail: exe }; }
    if (set) { return { state: 'amber', exe: '', label: 'Log Parser path not found', detail: 'The path set in Settings does not exist: ' + set + '. No default installation was found either.' }; }
    return { state: 'red', exe: '', label: 'Log Parser 2.2 not installed', detail: 'Install it from Microsoft (LogParser.msi) to enable free-form SQL. Everything else works without it.' };
  };

  /* {files} expands to the FROM list of the current scope. */
  LP.TEMPLATES = [
    { name: 'Top 50 client IPs', sql: 'SELECT TOP 50 c-ip, COUNT(*) AS Hits, MIN(TO_TIMESTAMP(date, time)) AS FirstSeen, MAX(TO_TIMESTAMP(date, time)) AS LastSeen\nFROM {files}\nGROUP BY c-ip\nORDER BY Hits DESC' },
    { name: 'Requests per hour (UTC)', sql: 'SELECT QUANTIZE(TO_TIMESTAMP(date, time), 3600) AS HourUtc, COUNT(*) AS Hits\nFROM {files}\nGROUP BY HourUtc\nORDER BY HourUtc' },
    { name: 'Status / substatus breakdown', sql: 'SELECT sc-status, sc-substatus, COUNT(*) AS Hits\nFROM {files}\nGROUP BY sc-status, sc-substatus\nORDER BY Hits DESC' },
    { name: 'Executable paths returning 200 to non-RFC1918 clients', sql: "SELECT cs-uri-stem, COUNT(*) AS Hits, COUNT(DISTINCT c-ip) AS Clients, MIN(TO_TIMESTAMP(date, time)) AS FirstSeen\nFROM {files}\nWHERE sc-status = 200 AND (EXTRACT_EXTENSION(cs-uri-stem) IN ('aspx'; 'ashx'; 'asmx'; 'asp'; 'php'; 'jsp'))\n  AND NOT (c-ip LIKE '10.%' OR c-ip LIKE '192.168.%' OR c-ip LIKE '127.%' OR c-ip = '::1')\nGROUP BY cs-uri-stem\nORDER BY FirstSeen DESC" },
    { name: 'All requests from one IP (edit the address)', sql: "SELECT TO_TIMESTAMP(date, time) AS TimeUtc, cs-method, cs-uri-stem, cs-uri-query, sc-status, sc-substatus, time-taken, cs(User-Agent)\nFROM {files}\nWHERE c-ip = '203.0.113.45'\nORDER BY TimeUtc" },
    { name: 'Server errors (5xx)', sql: 'SELECT TO_TIMESTAMP(date, time) AS TimeUtc, c-ip, cs-method, cs-uri-stem, cs-uri-query, sc-status, sc-substatus, sc-win32-status\nFROM {files}\nWHERE sc-status >= 500\nORDER BY TimeUtc' },
    { name: 'Longest requests', sql: 'SELECT TOP 100 TO_TIMESTAMP(date, time) AS TimeUtc, c-ip, cs-method, cs-uri-stem, sc-status, time-taken\nFROM {files}\nORDER BY time-taken DESC' }
  ];

  /* FROM clause: a wildcard for whole site folders, otherwise a comma-separated quoted list. */
  LP.fromClause = function (files, wholeSiteFolder) {
    if (wholeSiteFolder) { return "'" + U.joinPath(wholeSiteFolder, '*.log').replace(/'/g, "''") + "'"; }
    var parts = [], i;
    for (i = 0; i < files.length; i++) { parts.push("'" + files[i].path.replace(/'/g, "''") + "'"); }
    return parts.join(', ');
  };
  LP.expand = function (sql, from) { return sql.replace(/\{files\}/g, from); };

  /* Minimal RFC 4180 CSV parser. */
  LP.parseCsv = function (text) {
    var rows = [], row = [], cell = '', i = 0, n = text.length, c, q = false;
    if (text.charCodeAt(0) === 0xFEFF) { i = 1; }
    for (; i < n; i++) {
      c = text.charAt(i);
      if (q) { if (c === '"') { if (text.charAt(i + 1) === '"') { cell += '"'; i++; } else { q = false; } } else { cell += c; } continue; }
      if (c === '"') { q = true; } else if (c === ',') { row.push(cell); cell = ''; } else if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; } else if (c !== '\r') { cell += c; }
    }
    if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
    return rows;
  };

  /* Runs a query asynchronously. opts: { exe, sql, workDir, iCodepage }. cb(err, { header, rows, csvPath, stderr, ms, exitCode }) */
  LP.run = function (opts, cb, token) {
    var fso = U.fso(), id = 'lp-' + Date.now(), base = U.joinPath(opts.workDir, id);
    U.ensureFolder(opts.workDir);
    var sqlPath = base + '.sql', out = base + '.csv', err = base + '.err', done = base + '.done', bat = base + '.cmd';
    var ts = fso.CreateTextFile(sqlPath, true, false);
    try { ts.Write(opts.sql); } finally { ts.Close(); }
    function pct(s) { return s.replace(/%/g, '%%'); }
    var lines = ['@echo off',
      (/\.exe$/i.test(opts.exe) ? '' : 'call ') + '"' + pct(opts.exe) + '" -i:IISW3C -iCodepage:' + (+opts.iCodepage || -1) + ' -o:CSV -headers:ON -q:ON -stats:OFF file:"' + pct(sqlPath) + '" > "' + pct(out) + '" 2> "' + pct(err) + '"',
      'echo %ERRORLEVEL% > "' + pct(done) + '"'];
    var bt = fso.CreateTextFile(bat, true, false);
    try { bt.Write(lines.join('\r\n') + '\r\n'); } finally { bt.Close(); }
    var t0 = Date.now();
    U.shell().Run('cmd.exe /c "' + bat + '"', 0, false);
    function poll() {
      if (token && token.cancelled) { cb(new Error('Cancelled (Log Parser keeps running in the background until it finishes).')); return; }
      if (!fso.FileExists(done)) {
        if (Date.now() - t0 > 4 * 3600000) { cb(new Error('Log Parser timed out')); return; }
        setTimeout(poll, 400); return;
      }
      var code = 0, stderr = '', text = '';
      try { code = parseInt(U.readTextAnsi(done), 10); } catch (e) { setTimeout(poll, 300); return; }
      try { stderr = fso.FileExists(err) ? U.readTextAnsi(err) : ''; } catch (e2) { }
      try { text = fso.FileExists(out) ? U.readTextUtf8(out) : ''; } catch (e3) { cb(e3); return; }
      var rows = LP.parseCsv(text), header = rows.length ? rows.shift() : [];
      try { fso.DeleteFile(bat, true); fso.DeleteFile(done, true); fso.DeleteFile(err, true); } catch (e4) { }
      if (code !== 0 && !rows.length) { cb(new Error('Log Parser exit code ' + code + (stderr ? ': ' + stderr.substr(0, 1000) : ''))); return; }
      cb(null, { header: header, rows: rows, csvPath: out, sqlPath: sqlPath, stderr: stderr, ms: Date.now() - t0, exitCode: code });
    }
    setTimeout(poll, 300);
  };
}(IISLA));
