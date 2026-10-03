/* IIS Log Analyzer - enrich.js
 * Offline IP enrichment from a user-supplied CSV whose first column is a CIDR
 * (e.g. MaxMind GeoLite2-ASN-Blocks-IPv4.csv: network,autonomous_system_number,autonomous_system_organization,
 * or any "cidr,label,..." file). Nothing is bundled and nothing is fetched from the network.
 */
(function (NS) {
  'use strict';
  var U = NS.util, E = NS.enrich = { loaded: false, path: '', count: 0, error: '' };
  var starts = null, ends = null, labels = null, v6 = [], cache = U.newMap(), cacheN = 0;

  function splitCsv(line) {
    var out = [], cur = '', q = false, i, c;
    for (i = 0; i < line.length; i++) {
      c = line.charAt(i);
      if (q) { if (c === '"') { if (line.charAt(i + 1) === '"') { cur += '"'; i++; } else { q = false; } } else { cur += c; } } else if (c === '"') { q = true; } else if (c === ',') { out.push(cur); cur = ''; } else { cur += c; }
    }
    out.push(cur);
    return out;
  }
  E.load = function (path) {
    E.loaded = false; E.count = 0; E.error = ''; E.path = path || ''; cache = U.newMap(); cacheN = 0; v6 = [];
    path = U.expandEnv(path || '');
    if (!path) { return false; }
    if (!U.fileExists(path)) { E.error = 'Enrichment CSV not found: ' + path; return false; }
    var text = U.readTextUtf8(path), lines = text.split(/\r?\n/), rows = [], i, f, c, lab;
    for (i = 0; i < lines.length; i++) {
      if (!lines[i] || lines[i].charAt(0) === '#') { continue; }
      f = splitCsv(lines[i]);
      c = U.parseCidr(f[0]);
      if (!c) { continue; } // header or junk
      lab = f.slice(1).filter(function (x) { return x !== ''; }).join(' / ');
      if (/^\d+$/.test(f[1] || '') && f[2]) { lab = 'AS' + f[1] + ' ' + f[2]; }
      if (c.v === 4) { rows.push([c.base, c.base + c.size - 1, lab]); } else { v6.push({ c: c, lab: lab }); }
    }
    rows.sort(function (a, b) { return a[0] - b[0]; });
    starts = new Float64Array(rows.length); ends = new Float64Array(rows.length); labels = new Array(rows.length);
    for (i = 0; i < rows.length; i++) { starts[i] = rows[i][0]; ends[i] = rows[i][1]; labels[i] = rows[i][2]; }
    E.count = rows.length + v6.length;
    E.loaded = E.count > 0;
    if (!E.loaded) { E.error = 'No CIDR rows recognised in ' + path; }
    return E.loaded;
  };
  E.lookup = function (ip) {
    if (!E.loaded || !ip) { return ''; }
    var v = cache[ip];
    if (v !== undefined) { return v; }
    v = '';
    var n = U.parseIPv4(ip);
    if (n >= 0) {
      var lo = 0, hi = starts.length - 1, mid;
      while (lo <= hi) { mid = (lo + hi) >> 1; if (starts[mid] <= n) { lo = mid + 1; } else { hi = mid - 1; } }
      if (hi >= 0 && n <= ends[hi]) { v = labels[hi]; }
    } else {
      for (var i = 0; i < v6.length; i++) { if (U.cidrMatch(v6[i].c, ip)) { v = v6[i].lab; break; } }
    }
    if (cacheN++ > 100000) { cache = U.newMap(); cacheN = 0; }
    cache[ip] = v;
    return v;
  };
}(IISLA));
