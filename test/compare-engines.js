/* Runs the built-in JavaScript scanner and the fast C# engine on the same files and compares the
 * resulting indexes value by value (after the shared post-processing, so findings are compared too).
 *   node test/compare-engines.js <siteFolder> [fileRegex] [--skip-js]
 * Exit code 0 when identical (ignoring run metadata), 1 otherwise. */
'use strict';
var NS = require('./node-harness.js'), U = NS.util, fs = require('fs'), path = require('path'), cp = require('child_process'), os = require('os');
var args = process.argv.slice(2), siteDir = args[0], re = args[1] && args[1].charAt(0) !== '-' ? new RegExp(args[1], 'i') : null;
var settings = NS.defaultSettings();
if (args.indexOf('--testnets') >= 0) { NS.util.setTestNetsPublic(true); } // demo data: documentation ranges count as public
var site = NS.io.discover(siteDir, 3).sites[0];
if (re) { site.files = site.files.filter(function (f) { return re.test(f.name); }); }
var rs = NS.rules.loadRuleset(fs.readFileSync(path.join(__dirname, '..', 'rules', 'default-rules.json'), 'utf8')), lists = NS.loadLists();
var zone = NS.tz.fixed(settings.displayTzOffsetMinutes || 0);

function runJs(cb) {
  var t0 = Date.now();
  var sc = new NS.scan.Scanner({ site: site, settings: settings, ruleset: rs, lists: lists, tz: zone });
  sc.run(function (err, idx) { if (err) { throw err; } cb(idx, Date.now() - t0); });
}
function runCs() {
  var t0 = Date.now(), tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'iisla-cmp-')), base = path.join(tmp, 'scan');
  var job = NS.engine.buildJob({ files: site.files, settings: settings, ruleset: rs, lists: lists, zone: zone, output: base + '.out.json', progress: base + '.progress.json', cancel: base + '.cancel' });
  if (process.env.PROFILE) { job.profile = true; }
  fs.writeFileSync(base + '.job.json', JSON.stringify(job));
  var r = cp.spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(__dirname, '..', 'engine', 'Scan-IISLogs.ps1'), '-Job', base + '.job.json'], { encoding: 'utf8', maxBuffer: 1 << 26 });
  if (r.status !== 0) { console.error('engine failed', r.status, r.stderr, fs.existsSync(job.output + '.done') ? fs.readFileSync(job.output + '.done', 'utf8') : ''); process.exit(2); }
  var out = JSON.parse(fs.readFileSync(job.output, 'utf8'));
  if (out.profile) { console.log('profile', JSON.stringify(out.profile), 'total', out.scanMs); }
  var idx = NS.scan.newIndex(site, site.files, settings, rs);
  NS.engine.merge(idx, out, rs, settings);
  var ms = Date.now() - t0;
  fs.rmSync(tmp, { recursive: true, force: true });
  return { idx: idx, ms: ms, engineMs: out.scanMs };
}
function canon(idx) {
  var c = JSON.parse(JSON.stringify(idx));
  ['createdUtc', 'completedUtc', 'scanMs', 'cancelledAt', 'engine'].forEach(function (k) { delete c[k]; });
  c.files.forEach(function (f) { delete f.openError; });
  return c;
}
function diff(a, b, p, out) {
  if (out.length >= 40) { return; }
  if (a === b) { return; }
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') {
    if (typeof a === 'number' && typeof b === 'number' && isNaN(a) && isNaN(b)) { return; }
    out.push(p + ': JS=' + JSON.stringify(a).slice(0, 160) + '  C#=' + JSON.stringify(b).slice(0, 160)); return;
  }
  if (Array.isArray(a) !== Array.isArray(b)) { out.push(p + ': array/object mismatch'); return; }
  var ka = Object.keys(a), kb = Object.keys(b), sa = {}, i;
  if (Array.isArray(a) && a.length !== b.length) { out.push(p + ': length JS=' + a.length + ' C#=' + b.length); }
  ka.forEach(function (k) { sa[k] = 1; });
  for (i = 0; i < kb.length; i++) { if (!sa[kb[i]]) { out.push(p + '.' + kb[i] + ': only in C#'); } }
  for (i = 0; i < ka.length; i++) { if (!Object.prototype.hasOwnProperty.call(b, ka[i])) { out.push(p + '.' + ka[i] + ': only in JS'); continue; } diff(a[ka[i]], b[ka[i]], p + '.' + ka[i], out); }
}
var cs = runCs();
console.log('C# engine: ' + U.fmtNum(cs.idx.totals.rows) + ' rows, engine ' + cs.engineMs + ' ms, total incl. compile/load/merge ' + cs.ms + ' ms (' + Math.round(cs.idx.totals.rows / Math.max(1, cs.engineMs) * 1000) + ' rows/s)');
if (args.indexOf('--skip-js') >= 0) { process.exit(0); }
runJs(function (js, jsMs) {
  console.log('JS engine: ' + U.fmtNum(js.totals.rows) + ' rows, ' + jsMs + ' ms (' + Math.round(js.totals.rows / Math.max(1, jsMs) * 1000) + ' rows/s)');
  var d = []; diff(canon(js), canon(cs.idx), 'idx', d);
  console.log('findings JS=' + js.findings.length + ' C#=' + cs.idx.findings.length + '; ips ' + js.counts.ips + '/' + cs.idx.counts.ips + '; stems ' + js.counts.stems + '/' + cs.idx.counts.stems);
  if (!d.length) { console.log('IDENTICAL: every index value and every finding matches'); process.exit(0); }
  console.log('DIFFERENCES (first ' + d.length + '):'); d.forEach(function (x) { console.log('  ' + x); });
  process.exit(1);
});
