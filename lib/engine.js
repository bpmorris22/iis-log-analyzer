/* IIS Log Analyzer - engine.js
 * Fast scan engine bridge. Builds a job file from the HTA's own rules, lists, parser tables,
 * regex sources and time-zone table, runs engine\Scan-IISLogs.ps1 (compiled C#) in a hidden
 * PowerShell process, polls its progress, supports cancel, and merges the result into an index
 * that is finished by the same JavaScript post-processing as the built-in scanner.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io, P = NS.parser, S = NS.scan, E = NS.engine = {};

  E.VERSION = 1;
  function reSpec(re) { return { src: re.source, flags: (re.ignoreCase ? 'i' : '') + (re.global ? 'g' : '') }; }

  /* o: { files, settings, ruleset, lists, zone, output, progress, cancel } */
  E.buildJob = function (o) {
    var s = o.settings, rs = o.ruleset, i, k, files = [], regex = {}, fams = [], zone = o.zone;
    for (i = 0; i < o.files.length; i++) { files.push({ path: o.files[i].path, name: o.files[i].name, size: o.files[i].size }); }
    for (k in P.RE) { if (Object.prototype.hasOwnProperty.call(P.RE, k)) { regex[k] = reSpec(P.RE[k]); } }
    for (i = 0; i < P.UA_FAMILIES.length; i++) { var f = reSpec(P.UA_FAMILIES[i][1]); fams.push([P.UA_FAMILIES[i][0], f.src, f.flags]); }
    if (typeof zone === 'number' || !zone) { zone = NS.tz.fixed(+zone || 0); }
    var sp = S.scanParams(rs);
    return {
      version: E.VERSION, files: files, rules: rs.rules, lists: o.lists,
      parser: { fieldMap: P.FIELD_MAP, numeric: Object.keys(P.NUMERIC), stringKeys: P.STRING_KEYS, numKeys: P.NUM_KEYS, defaultFields: P.DEFAULT_FIELDS,
        methodsValid: U.METHODS_VALID, regex: regex, uaFamilies: fams },
      settings: { chunkChars: s.chunkChars || 4194304, ruleHitRetention: s.ruleHitRetention || 50000, ipCap: s.indexCaps.ips, stemCap: s.indexCaps.stems,
        uaCap: s.indexCaps.uas, gapMs: sp.gapMs, businessHours: s.businessHours, internalCidrs: s.internalCidrs || [], allowlist: U.getAllowlist(), testNetsPublic: U.testNetsPublic() },
      consts: { IP_STEM_CAP: S.IP_STEM_CAP, IP_UA_CAP: S.IP_UA_CAP, WIN_PURGE_ROWS: S.WIN_PURGE_ROWS, KEEP_RAW: S.KEEP_RAW },
      scanParams: { s7win: sp.s7win, a1win: sp.a1win, a2win: sp.a2win, a2count: sp.a2count, a4rows: sp.a4rows, s1dayMin: sp.s1dayMin, s1ratio: sp.s1ratio },
      tz: { id: zone.id, t: zone.table.t, o: zone.table.o },
      output: o.output, progress: o.progress, cancel: o.cancel
    };
  };

  var TOP = ['schemas', 'softwares', 'totals', 'perDay', 'perHour', 'ips', 'stems', 'uas', 'users', 'statuses', 'methods', 'sports', 'exts', 'uaFams', 'restarts', 'gaps', 'lbKeys', 'ruleHits', 'counts'];
  /* Merges engine output into an index skeleton from S.newIndex and runs the shared post-processing. */
  E.merge = function (idx, out, ruleset, settings) {
    var i;
    for (i = 0; i < TOP.length; i++) { idx[TOP[i]] = out[TOP[i]]; }
    idx.caps.ipEvicted = out.caps.ipEvicted; idx.caps.stemEvicted = out.caps.stemEvicted; idx.caps.uaEvicted = out.caps.uaEvicted; idx.caps.lbOv = out.caps.lbOv;
    for (i = 0; i < idx.files.length && i < out.files.length; i++) { U.extend(idx.files[i], out.files[i]); }
    idx.filesDone = out.filesDone; idx.partialFile = out.partialFile; idx.partialLine = out.partialLine;
    idx.resumeState = out.partial ? (out.resumeState || null) : null; // detection state at the cancel point (resumed by the built-in engine)
    idx.scanMs += out.scanMs; idx.engine = out.engine;
    if (out.partial) { idx.cancelledAt = U.nowIso(); } else { idx.completedUtc = U.nowIso(); }
    S.finishIndex(idx, ruleset, settings, out.partial);
    return idx;
  };

  /* ---------- HTA runtime ---------- */
  E.dir = function () { return U.joinPath(U.joinPath(U.env('LOCALAPPDATA') || U.env('TEMP'), 'IISLogAnalyzer'), 'engine'); };
  E.powershell = function () { return U.joinPath(U.env('WINDIR'), 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'); };
  /* True when PowerShell and the engine sources are present. (Policy can still block it; run() reports that.) */
  E.available = function () {
    try { return U.fileExists(E.powershell()) && IO.resource('engine/IISScanEngine.cs') !== null && IO.resource('engine/Scan-IISLogs.ps1') !== null; } catch (e) { return false; }
  };
  /* Copies the engine sources (from the app folder or the single-file build) to %LOCALAPPDATA%. */
  E.install = function () {
    var src = U.joinPath(E.dir(), 'src');
    U.ensureFolder(src);
    U.writeTextUtf8(U.joinPath(src, 'IISScanEngine.cs'), IO.resource('engine/IISScanEngine.cs'), false);
    U.writeTextUtf8(U.joinPath(src, 'Scan-IISLogs.ps1'), IO.resource('engine/Scan-IISLogs.ps1'), true);
    return U.joinPath(src, 'Scan-IISLogs.ps1');
  };
  /* Runs a scan job. o as for buildJob minus the paths; workDir for job files.
   * onProgress({file, files, current, rows, bytesDone, bytesTotal, rate, eta}); done(err, out, cancelled) */
  E.run = function (o, workDir, onProgress, done, token) {
    var fso = U.fso(), id = 'scan-' + Date.now(), base = U.joinPath(workDir, id);
    var job = E.buildJob(U.extend({}, o, { output: base + '.out.json', progress: base + '.progress.json', cancel: base + '.cancel' }));
    U.ensureFolder(workDir);
    var jobPath = base + '.job.json', ts = fso.CreateTextFile(jobPath, true, false);
    try { ts.Write(U.asciiJson(job)); } finally { ts.Close(); }
    var ps1 = E.install();
    var cmd = '"' + E.powershell() + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + ps1 + '" -Job "' + jobPath + '"';
    U.shell().Run(cmd, 0, false);
    // Watchdog: the heartbeat only advances when the progress file's content changes; the engine writes its PID
    // (pidF) on start so a process that died without a completion marker is detected within seconds; a cancel
    // that is not honoured, a start that never happens, or a stall each end the wait with an error.
    var t0 = Date.now(), lastSeen = t0, lastText = null, cancelSent = 0, doneF = job.output + '.done', pidF = job.output + '.pid',
      pid = 0, lastAlive = 0, finished = false;
    function cleanup() {
      var fs = [jobPath, job.progress, job.cancel, doneF, job.output, pidF], i;
      for (i = 0; i < fs.length; i++) { try { if (fso.FileExists(fs[i])) { fso.DeleteFile(fs[i], true); } } catch (e) { } }
    }
    function finish(err, out, cancelled) {
      if (finished) { return; }
      finished = true; cleanup(); done(err, out, cancelled);
    }
    function fail(msg, kill) {
      if (kill && pid) { E.killProcess(pid, id); }
      finish(new Error(msg));
    }
    function poll() {
      if (finished) { return; }
      var now = Date.now();
      if (token && token.cancelled && !cancelSent) { cancelSent = now; try { fso.CreateTextFile(job.cancel, true).Close(); } catch (e) { } }
      if (fso.FileExists(doneF)) {
        var status = '';
        try { status = U.readTextAnsi(doneF); } catch (e) { setTimeout(poll, 300); return; }
        if (/^ERROR/.test(status)) { finish(new Error('Fast engine failed: ' + status.substr(0, 600))); return; }
        var out;
        try { out = U.readJsonAscii(job.output); } catch (e2) { finish(new Error('Fast engine output unreadable: ' + e2.message)); return; }
        finish(null, out, status.indexOf('cancelled') === 0);
        return;
      }
      if (!pid && fso.FileExists(pidF)) { try { pid = parseInt(U.readTextAnsi(pidF), 10) || 0; } catch (eP) { pid = 0; } }
      if (fso.FileExists(job.progress)) {
        try {
          var txt = U.readTextAnsi(job.progress);
          if (txt !== lastText) {
            lastText = txt; lastSeen = now;
            var p = JSON.parse(txt), el = (now - t0) / 1000;
            p.rate = el > 0 ? p.rows / el : 0; p.eta = p.bytesDone > 0 ? (p.bytesTotal - p.bytesDone) * el / p.bytesDone : 0;
            if (onProgress) { onProgress(p); }
          }
        } catch (e3) { /* file being replaced */ }
      } else if (onProgress && now - t0 < 30000) { onProgress({ file: 0, files: o.files.length, rows: 0, bytesDone: 0, bytesTotal: 1, current: 'compiling / starting fast engine...' }); }
      if (pid && now - lastAlive >= 5000) {
        lastAlive = now;
        if (E.processAlive(pid, id) === false && !fso.FileExists(doneF)) { fail('The fast engine process (PID ' + pid + ') ended without finishing; no results were produced. Use the built-in engine.'); return; }
      }
      if (!pid && lastText === null && now - t0 > E.START_MS) { fail('The fast engine did not start within ' + Math.round(E.START_MS / 1000) + ' seconds. PowerShell may be blocked by policy; use the built-in engine.'); return; }
      if (cancelSent && now - cancelSent > E.CANCEL_MS) { fail('The fast engine did not stop within ' + Math.round(E.CANCEL_MS / 1000) + ' seconds of cancelling and was terminated. No partial index was kept.', true); return; }
      if (now - lastSeen > E.STALL_MS) { fail('The fast engine made no progress for ' + Math.round(E.STALL_MS / 60000) + ' minutes and was terminated. Use the built-in engine.', true); return; }
      setTimeout(poll, 400);
    }
    setTimeout(poll, 500);
  };
  E.START_MS = 120000; E.CANCEL_MS = 180000; E.STALL_MS = 600000;

  /* WMI process checks, restricted to the engine's own PowerShell process (command line contains the job id),
   * so a reused PID can never be mistaken for the engine or terminated. Return null when WMI is unavailable. */
  var wmiSvc = null;
  function engineProcs(pid, jobId) {
    if (!wmiSvc) { wmiSvc = new ActiveXObject('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\cimv2'); }
    var out = [];
    IO.each(wmiSvc.ExecQuery('SELECT ProcessId, CommandLine FROM Win32_Process WHERE ProcessId = ' + (+pid)), function (p) {
      if (('' + (p.CommandLine || '')).indexOf(jobId) >= 0) { out.push(p); }
    });
    return out;
  }
  E.processAlive = function (pid, jobId) { try { return engineProcs(pid, jobId).length > 0; } catch (e) { return null; } };
  E.killProcess = function (pid, jobId) {
    try { var ps = engineProcs(pid, jobId), i; for (i = 0; i < ps.length; i++) { ps[i].Terminate(); } return ps.length > 0; } catch (e) { return false; }
  };
}(IISLA));
