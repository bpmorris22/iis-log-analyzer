/* Regression checks for the fixes made after the 2026-10-03 peer review (run with: node test/regression-review.js).
 * Each check prints PASS/FAIL; exit code 1 if any check fails. Fixtures are written to the OS temp folder. */
'use strict';
var NS = require('./node-harness.js'), U = NS.util, fs = require('fs'), path = require('path'), os = require('os');
var settings = NS.defaultSettings(), lists = NS.loadLists();
var rulesText = fs.readFileSync(path.join(__dirname, '..', 'rules', 'default-rules.json'), 'utf8');
var ruleset = NS.rules.loadRuleset(rulesText);
var tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'iisla-reg-')), failures = 0;
function check(name, ok, detail) { console.log((ok ? 'PASS ' : 'FAIL ') + name + (detail ? ' - ' + detail : '')); if (!ok) { failures++; } }

// 1. rule: wildcards test each rule id of the row, not the joined hit string
(function () {
  var fn = NS.filter.compile(NS.filter.parse('rule:R-EXP-*', 0)), fn2 = NS.filter.compile(NS.filter.parse('rule:R-SCAN-00?', 0));
  check('rule wildcard, hit listed second', fn({ hits: function () { return 'R-SCAN-002,R-EXP-001'; } }) === true);
  check('rule wildcard, no matching id', fn({ hits: function () { return 'R-SCAN-002,R-WS-004'; } }) === false);
  check('rule ? wildcard, no false positive across ids', fn2({ hits: function () { return 'R-SCAN-010,R-EXP-001'; } }) === false);
}());

// 2. impossible dates and junk after the time are malformed rows in both directions of the parser
(function () {
  var row = NS.parser.newRow(), fp = new NS.parser.FileParser(0);
  fp.line('#Fields: date time c-ip cs-method cs-uri-stem sc-status', row);
  var cases = [['2026-02-31 00:00:00', 2], ['2025-02-29 00:00:00', 2], ['2024-02-29 23:59:59', 1], ['2026-13-01 00:00:00', 2], ['0026-01-01 00:00:00', 2],
    ['2026-01-01 12:00:60', 2], ['2026-01-01 12:00:00Z', 2], ['2026-01-01 1a:00:00', 2], ['2026-01-01 12:00:00.125', 1], ['2026-1-01 12:00:00', 2]];
  cases.forEach(function (c) { var code = fp.line(c[0] + ' 8.8.8.8 GET / 200', row); check('date ' + c[0], code === c[1], 'code ' + code); });
}());

// 3. the rule-set fingerprint covers which rules are enabled
(function () {
  var a = NS.rules.loadRuleset(rulesText), b = NS.rules.loadRuleset(rulesText, { 'R-SCAN-007': false });
  check('fingerprint changes when a rule is disabled', a.hash !== b.hash, a.hash + ' vs ' + b.hash);
  check('disabled rules listed', b.disabledIds.indexOf('R-SCAN-007') >= 0);
}());

// 4. a file that cannot be opened is reported, never silently dropped
(function (next) {
  var dir = path.join(tmp, 'W3SVC1'); fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'u_ex260101.log'), '#Fields: date time c-ip cs-method cs-uri-stem sc-status\r\n2026-01-01 00:00:01 8.8.8.8 GET /a 200\r\n');
  var site = NS.io.discover(dir, 0).sites[0];
  site.files.push(U.extend({}, site.files[0], { name: 'u_ex260102.log', path: path.join(dir, 'u_ex260102.log') })); // listed but missing
  NS.store.load({ site: site, fileIds: [0, 1], settings: settings, ruleset: ruleset, lists: lists, maxRows: 100, keepRaw: true }, function (err, st) {
    check('unreadable file recorded', !err && st.incomplete === true && st.failed.length === 1 && st.failed[0].name === 'u_ex260102.log', JSON.stringify(st.failed));
    check('readable file still loaded', st.n === 1);
    next();
  });
}(function () {
  // 5. eviction backoff: a cap filled with protected entries does not trigger a sweep for every new key
  var site = NS.io.discover(path.join(tmp, 'W3SVC1'), 0).sites[0];
  var sc = new NS.scan.Scanner({ site: site, settings: U.extend({}, settings, { indexCaps: { ips: 100, stems: 100, uas: 100 } }), ruleset: ruleset, lists: lists });
  var sweeps = 0, orig = sc.evictStems; sc.evictStems = function () { sweeps++; return orig.call(this); };
  var row = NS.parser.newRow(), fp = new NS.parser.FileParser(0), i, frec = sc.idx.files[0];
  U.extend(frec, { rows: 0, malformedSamples: [], backSamples: [], s500: [], firstTs: 0, minTs: 0, maxTs: 0, lastTs: 0, nonAscii: 0, decodeErr: 0, backSteps: 0 });
  fp.line('#Fields: date time c-ip cs-method cs-uri-stem sc-status', row);
  for (i = 0; i < 400; i++) { fp.line('2026-01-01 00:00:01 10.0.0.1 GET /p' + i + '.aspx 200', row); sc.row(row, frec); } // successful executable paths are protected
  check('stem cap exceeded only with protected entries', sc.counts.stems === 400, 'stems ' + sc.counts.stems);
  check('eviction sweeps bounded by backoff', sweeps <= 31, sweeps + ' sweeps for 300 inserts over the cap');

  // 6. fast-engine watchdog: unchanged progress ends the wait after the stall limit (fake clock)
  var E = NS.engine, oldNow = Date.now, oldTimeout = global.setTimeout, oldFso = U.fso, oldShell = U.shell, oldInstall = E.install, oldJob = E.buildJob, oldEnsure = U.ensureFolder, oldRead = U.readTextAnsi;
  var now = 1000, pending = null, result = null;
  try {
    Date.now = function () { return now; };
    global.setTimeout = function (cb) { pending = cb; };
    U.fso = function () { return { CreateTextFile: function () { return { Write: function () { }, Close: function () { } }; }, FileExists: function (p) { return /progress\.json$/.test(p); }, DeleteFile: function () { } }; };
    U.shell = function () { return { Run: function () { } }; }; U.ensureFolder = function () { };
    U.readTextAnsi = function () { return '{"rows":1,"bytesDone":1,"bytesTotal":100}'; };
    E.install = function () { return 'mock.ps1'; };
    E.buildJob = function (o) { return { output: o.output, progress: o.progress, cancel: o.cancel }; };
    E.run({ files: [] }, tmp, null, function (err) { result = err; });
    for (i = 0; i < 6 && pending; i++) { now += 3 * 60000; var cb = pending; pending = null; cb(); }
  } finally {
    Date.now = oldNow; global.setTimeout = oldTimeout; U.fso = oldFso; U.shell = oldShell; E.install = oldInstall; E.buildJob = oldJob; U.ensureFolder = oldEnsure; U.readTextAnsi = oldRead;
  }
  check('stalled fast engine ends with an error', !!result && /no progress/.test(result.message), result ? result.message : 'still waiting');

  // 7. outcome grading (1.3.0): failed requests drop to low, 2xx/5xx keep the rule severity, 3xx drops one level
  var G = NS.rules.gradeSev;
  check('grade 404 high -> low', G('high', 404) === 'low');
  check('grade 200 high stays', G('high', 200) === 'high');
  check('grade 500 high stays', G('high', 500) === 'high');
  check('grade 302 high -> medium', G('high', 302) === 'medium');
  check('grade status not logged unchanged', G('high', -1) === 'high');
  check('grade info stays info', G('info', 404) === 'info');
  (function () {
    var ev = new NS.rules.Evaluator(ruleset, new NS.parser.Deriver(lists)), row = NS.parser.newRow(), fp = new NS.parser.FileParser(0);
    fp.line('#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status', row);
    fp.line('2026-01-01 00:00:01 203.0.113.9 GET /uploads/shell.php - 404', row); ev.evaluate(row);
    var i404 = ev.hits.slice(0, ev.n).indexOf('R-WS-004'), s404 = i404 >= 0 ? ev.hitSev[i404] : '';
    fp.line('2026-01-01 00:00:02 203.0.113.9 GET /uploads/shell.php - 200', row); ev.evaluate(row);
    var i200 = ev.hits.slice(0, ev.n).indexOf('R-WS-004'), s200 = i200 >= 0 ? ev.hitSev[i200] : '';
    check('R-WS-004 on a 404 graded low', s404 === 'low', s404);
    check('R-WS-004 on a 200 stays high', s200 === 'high', s200);
    check('hitSevString parallels hitString', ev.hitSevString().split(',').length === ev.hitString().split(',').length);
  }());
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failures ? failures + ' CHECK(S) FAILED' : 'ALL CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}));
