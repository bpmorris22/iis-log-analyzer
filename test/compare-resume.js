/* Cancel-and-resume equivalence test.
 * For each cancel point, a scan is cancelled after N rows (built-in JavaScript engine, and the fast C# engine),
 * the partial index goes through a JSON save/load round trip as in the HTA, the built-in engine resumes it, and
 * the final index (every aggregate and every finding) is compared with an uninterrupted built-in scan.
 *   node test/compare-resume.js <siteFolder> [fileRegex] [--points 0.13,0.5,0.91] [--chunk 65536] [--js-only]
 * Exit code 0 when every resumed index is identical, 1 otherwise. */
'use strict';
var NS = require('./node-harness.js'), U = NS.util, fs = require('fs'), path = require('path'), cp = require('child_process'), os = require('os');
var args = process.argv.slice(2), siteDir = args[0], re = args[1] && args[1].charAt(0) !== '-' ? new RegExp(args[1], 'i') : null;
var pi = args.indexOf('--points'), points = pi >= 0 ? args[pi + 1].split(',').map(Number) : [0.13, 0.5, 0.91];
var jsOnly = args.indexOf('--js-only') >= 0;
var settings = NS.defaultSettings();
// small read chunks so cancel points fall inside files (cancellation happens at chunk boundaries)
var ci = args.indexOf('--chunk'); settings.chunkChars = ci >= 0 ? +args[ci + 1] : 65536;
var site = NS.io.discover(siteDir, 3).sites[0];
if (re) { site.files = site.files.filter(function (f) { return re.test(f.name); }); }
var rs = NS.rules.loadRuleset(fs.readFileSync(path.join(__dirname, '..', 'rules', 'default-rules.json'), 'utf8')), lists = NS.loadLists();
var zone = NS.tz.fixed(settings.displayTzOffsetMinutes || 0);

function scanJs(extra, cb) {
  var token = { cancelled: false };
  var sc = new NS.scan.Scanner(U.extend({ site: site, settings: settings, ruleset: rs, lists: lists, tz: zone }, extra));
  sc.run(function (err, idx, cancelled) { if (err) { throw err; } cb(idx, cancelled); }, token);
}
function scanCsPartial(cancelAfterRows) {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'iisla-res-')), base = path.join(tmp, 'scan');
  var job = NS.engine.buildJob({ files: site.files, settings: settings, ruleset: rs, lists: lists, zone: zone, output: base + '.out.json', progress: base + '.progress.json', cancel: base + '.cancel' });
  job.cancelAfterRows = cancelAfterRows;
  fs.writeFileSync(base + '.job.json', JSON.stringify(job));
  var r = cp.spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(__dirname, '..', 'engine', 'Scan-IISLogs.ps1'), '-Job', base + '.job.json'], { encoding: 'utf8', maxBuffer: 1 << 26 });
  if (r.status !== 0) { console.error('engine failed', r.status, r.stderr); process.exit(2); }
  var out = JSON.parse(fs.readFileSync(job.output, 'utf8'));
  fs.rmSync(tmp, { recursive: true, force: true });
  var idx = NS.scan.newIndex(site, site.files, settings, rs);
  NS.engine.merge(idx, out, rs, settings);
  return idx;
}
function roundTrip(idx) { return JSON.parse(JSON.stringify(idx)); } // what A.saveIndex + readJsonAscii do
function canon(idx) {
  var c = JSON.parse(JSON.stringify(idx));
  ['createdUtc', 'completedUtc', 'scanMs', 'cancelledAt', 'engine', 'resumeState'].forEach(function (k) { delete c[k]; });
  c.files.forEach(function (f) { delete f.openError; });
  return c;
}
function diff(a, b, p, out) {
  if (out.length >= 30 || a === b) { return; }
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') {
    if (typeof a === 'number' && typeof b === 'number' && isNaN(a) && isNaN(b)) { return; }
    out.push(p + ': uninterrupted=' + JSON.stringify(a).slice(0, 140) + '  resumed=' + JSON.stringify(b).slice(0, 140)); return;
  }
  var ka = Object.keys(a), kb = Object.keys(b), sa = {}, i;
  if (Array.isArray(a) && a.length !== b.length) { out.push(p + ': length ' + a.length + ' vs ' + b.length); }
  ka.forEach(function (k) { sa[k] = 1; });
  for (i = 0; i < kb.length; i++) { if (!sa[kb[i]]) { out.push(p + '.' + kb[i] + ': only in resumed'); } }
  for (i = 0; i < ka.length; i++) { if (!Object.prototype.hasOwnProperty.call(b, ka[i])) { out.push(p + '.' + ka[i] + ': only in uninterrupted'); continue; } diff(a[ka[i]], b[ka[i]], p + '.' + ka[i], out); }
}

var failures = 0;
scanJs({}, function (ref) {
  var refC = canon(ref), total = ref.totals.rows, jobs = [];
  console.log('uninterrupted: ' + U.fmtNum(total) + ' rows, ' + ref.findings.length + ' findings, ' + site.files.length + ' files');
  points.forEach(function (f) {
    var n = Math.max(1, Math.round(total * f));
    jobs.push({ label: 'built-in cancel at ' + U.fmtNum(n) + ' rows', partial: function (cb) { scanJs({ cancelAfterRows: n }, function (idx, cancelled) { cb(idx, cancelled); }); } });
    if (!jsOnly) { jobs.push({ label: 'fast engine cancel at ' + U.fmtNum(n) + ' rows', partial: function (cb) { var idx = scanCsPartial(n); cb(idx, idx.partial); } }); }
  });
  (function next(i) {
    if (i >= jobs.length) { console.log(failures ? failures + ' RESUME CASE(S) DIFFER' : 'IDENTICAL: every resumed index matches the uninterrupted scan'); process.exit(failures ? 1 : 0); }
    var j = jobs[i];
    j.partial(function (part, cancelled) {
      if (!cancelled || !part.partial) { console.log(j.label + ': scan finished before the cancel point (skipped)'); next(i + 1); return; }
      var hadState = !!part.resumeState, rows0 = part.totals.rows, file0 = part.partialFile, line0 = part.partialLine;
      scanJs({ resumeIndex: roundTrip(part) }, function (fin) {
        var d = []; diff(refC, canon(fin), 'idx', d);
        console.log(j.label + ': partial ' + U.fmtNum(rows0) + ' rows (file ' + file0 + ', line ' + line0 + ', state ' + (hadState ? 'saved' : 'MISSING') + ') -> resumed ' + U.fmtNum(fin.totals.rows) + ' rows, ' + fin.findings.length + ' findings: ' + (d.length ? 'DIFFERENT' : 'identical'));
        if (d.length) { failures++; d.forEach(function (x) { console.log('    ' + x); }); }
        next(i + 1);
      });
    });
  }(0));
});
