/* node test/run-load.js <siteFolder> <fileRegex> "<prefilter>" "<filter>" */
'use strict';
var NS = require('./node-harness.js'), U = NS.util, fs = require('fs'), path = require('path');
var a = process.argv.slice(2), settings = NS.defaultSettings();
var site = NS.io.discover(a[0], 3).sites[0];
var ids = []; site.files.forEach(function (f, i) { if (new RegExp(a[1], 'i').test(f.name)) { ids.push(i); } });
var rs = NS.rules.loadRuleset(fs.readFileSync(path.join(__dirname, '..', 'rules', 'default-rules.json'), 'utf8'));
var pre = a[2] ? NS.filter.compile(NS.filter.parse(a[2], 480), { tz: 480 }) : null;
NS.store.load({ site: site, fileIds: ids, settings: settings, ruleset: rs, lists: NS.loadLists(), maxRows: 2000000, keepRaw: true, prefilter: pre }, function (err, st) {
  if (err) { console.error(err.stack); process.exit(1); }
  console.log('loaded', st.n, 'scanned', st.scanned, 'ms', st.loadMs, 'capped', st.capped, 'estBytes', U.fmtBytes(st.bytesEstimate()));
  var t0 = Date.now(), pred = a[3] ? NS.filter.compile(NS.filter.parse(a[3], 480), { tz: 480, ruleSev: { 'R-EXP-001': 'high' } }) : null;
  var view = NS.filter.apply(st, pred); console.log('filter', a[3], '->', view.length, Date.now() - t0, 'ms');
  t0 = Date.now(); var sv = NS.store.sortView(st, view, 'taken', true); console.log('sort taken desc', Date.now() - t0, 'ms; top =', st.taken[sv[0]], NS.store.colByKey.stem.get(st, sv[0]));
  t0 = Date.now(); var ss = NS.store.sessions(st, view, 30); console.log('sessions', ss.length, Date.now() - t0, 'ms');
  ss.sort(function (x, y) { return y.rows - x.rows; }); ss.slice(0, 5).forEach(function (s) { console.log('  ', s.ip, s.fam, U.fmtTs(s.start), U.fmtDuration(s.duration), s.rows, 'rows', s.stems, 'stems', 's4', s.s4, 'execPost', s.execPost, 'hits', s.hits); });
  var tn = NS.store.topN(st, view, 'stem'); tn.sort(function (x, y) { return y.rows - x.rows; });
  tn.slice(0, 6).forEach(function (g) { console.log('  top stem', g.rows, g.key, 'ips', g.ipN, 'post', g.post, 's4', g.s4); });
});
