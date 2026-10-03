/* node test/run-scan.js <siteFolder> [fileRegex] [--json out.json]
 * Runs the scan pass headless and prints corpus statistics and findings. */
'use strict';
var NS = require('./node-harness.js'), U = NS.util;
var args = process.argv.slice(2), siteDir = args[0], re = args[1] && args[1].charAt(0) !== '-' ? new RegExp(args[1], 'i') : null;
var jsonOut = args.indexOf('--json') >= 0 ? args[args.indexOf('--json') + 1] : null;
if (process.argv.indexOf('--testnets') >= 0) { NS.util.setTestNetsPublic(true); }
var settings = NS.defaultSettings();
var disc = NS.io.discover(siteDir, 3), site = disc.sites[0];
if (re) { site.files = site.files.filter(function (f) { return re.test(f.name); }); }
var rs = NS.rules.loadRuleset(require('fs').readFileSync(require('path').join(__dirname, '..', 'rules', 'default-rules.json'), 'utf8'));
global.setTimeout = global.setTimeout;
var t0 = Date.now();
var lastF = -1, tS = Date.now();
var sc = new NS.scan.Scanner({ site: site, settings: settings, ruleset: rs, lists: NS.loadLists(), onProgress: function (p) {
  if (process.env.MEM && Math.floor(p.file / 250) !== lastF) { lastF = Math.floor(p.file / 250); var m = process.memoryUsage(); console.log('file', p.file, p.current, 'rows', p.rows, 'heapMB', Math.round(m.heapUsed / 1048576), 'rssMB', Math.round(m.rss / 1048576), 's', Math.round((Date.now() - tS) / 1000), 'ips', sc.counts.ips, 'stems', sc.counts.stems, 'uas', sc.counts.uas, 'win', Object.keys(sc.win).length); }
} });
sc.run(function (err, idx) {
  if (err) { console.error('ERROR', err.stack || err); process.exit(1); }
  var ms = Date.now() - t0;
  console.log('files', site.files.length, 'rows', idx.totals.rows, 'lines', idx.totals.lines, 'malformed', idx.totals.malformed, 'blocks', idx.totals.blocks, 'ms', ms, 'rows/s', Math.round(idx.totals.rows / ms * 1000));
  console.log('first', U.fmtTs(idx.totals.firstTs), 'last', U.fmtTs(idx.totals.lastTs));
  console.log('methods', JSON.stringify(idx.methods));
  var st = U.sortedKeys(idx.statuses, function (v) { return v; }, 15).map(function (k) { return k + '=' + idx.statuses[k]; });
  console.log('statuses', st.join(' '));
  console.log('sports', JSON.stringify(idx.sports));
  console.log('exts', U.sortedKeys(idx.exts, function (v) { return v; }, 12).map(function (k) { return k + '=' + idx.exts[k]; }).join(' '));
  console.log('uas', U.countKeys(idx.uas), 'ips', U.countKeys(idx.ips), 'stems', U.countKeys(idx.stems));
  console.log('heartbeat', JSON.stringify(idx.heartbeat));
  console.log('restarts', idx.restarts.length, 'gaps', idx.gaps.length, 'missing', idx.missingFiles.length, 'schemas', idx.schemas.length);
  var crlf = 0, lf = 0, tail = 0, back = 0;
  idx.files.forEach(function (f) { crlf += f.crlf; lf += f.lfOnly; if (f.tailNoEol) { tail++; } back += f.backSteps; });
  console.log('crlf', crlf, 'lfOnly', lf, 'tailNoEol files', tail, 'backSteps', back);
  console.log('ruleHits', Object.keys(idx.ruleHits).sort().map(function (k) { return k + '=' + idx.ruleHits[k].n; }).join(' '));
  console.log('--- findings (' + idx.findings.length + ') ---');
  var bySev = {};
  idx.findings.forEach(function (f) { bySev[f.severity] = (bySev[f.severity] || 0) + 1; });
  console.log(JSON.stringify(bySev));
  var hide = process.env.HIDE ? new RegExp(process.env.HIDE) : null;
  idx.findings.filter(function (f) { return !hide || !hide.test(f.ruleId); }).forEach(function (f) { console.log(f.id, f.severity, f.ruleId, f.entity, f.key.substr(0, 60), '|', f.detail.substr(0, 160)); });
  if (jsonOut) { require('fs').writeFileSync(jsonOut, JSON.stringify(idx)); console.log('index bytes', require('fs').statSync(jsonOut).size); }
});
