/* IIS Log Analyzer - parser.js
 * W3C Extended Log File Format parsing with per-block field re-binding,
 * plus cached derivation of stem / query / user-agent / IP attributes.
 */
(function (NS) {
  'use strict';
  var U = NS.util, P = NS.parser = {};

  P.DEFAULT_FIELDS = ['date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query', 's-port', 'cs-username',
    'c-ip', 'cs(User-Agent)', 'sc-status', 'sc-substatus', 'sc-win32-status', 'time-taken'];

  /* W3C field name (lowercase) -> row key */
  P.FIELD_MAP = {
    'date': 'date', 'time': 'time', 's-sitename': 'site', 's-computername': 'computer', 's-ip': 'sip',
    'cs-method': 'method', 'cs-uri-stem': 'stem', 'cs-uri-query': 'query', 's-port': 'port', 'cs-username': 'user',
    'c-ip': 'cip', 'cs(user-agent)': 'ua', 'cs(referer)': 'referer', 'cs(cookie)': 'cookie', 'cs-host': 'host',
    'cs-version': 'version', 'sc-status': 'status', 'sc-substatus': 'sub', 'sc-win32-status': 'win32',
    'sc-bytes': 'scBytes', 'cs-bytes': 'csBytes', 'time-taken': 'taken',
    'cs(x-forwarded-for)': 'xff', 'x-forwarded-for': 'xff', 'cs(x-real-ip)': 'xrealip',
    'c-port': 'cport', 'cs-uri': 'uri', 's-siteid': 'siteid', 's-reason': 'reason', 's-queuename': 'queue', 'streamid': 'streamid'
  };
  P.NUMERIC = { port: 1, status: 1, sub: 1, win32: 1, scBytes: 1, csBytes: 1, taken: 1, cport: 1 };
  P.STRING_KEYS = ['site', 'computer', 'sip', 'method', 'stem', 'query', 'user', 'cip', 'ua', 'referer', 'cookie', 'host',
    'version', 'xff', 'xrealip', 'uri', 'siteid', 'reason', 'queue', 'streamid', 'date', 'time'];
  P.NUM_KEYS = ['port', 'status', 'sub', 'win32', 'scBytes', 'csBytes', 'taken', 'cport'];

  P.newRow = function () {
    var r = {}, i;
    for (i = 0; i < P.STRING_KEYS.length; i++) { r[P.STRING_KEYS[i]] = '-'; }
    for (i = 0; i < P.NUM_KEYS.length; i++) { r[P.NUM_KEYS[i]] = -1; }
    r.ts = 0; r.raw = ''; r.rawOrig = null; r.eol = ''; r.lineNo = 0; r.fileId = 0; r.blockId = 0; r.reason2 = ''; r.nonAscii = false; r.extra = null; r.eip = '-';
    return r;
  };

  var NONASCII = /[^\u0000-\u007F]/;
  var dayCache = U.newMap(), dayCacheN = 0;
  function isDigits(s, a, b) {
    for (var i = a; i < b; i++) { var c = s.charCodeAt(i); if (c < 48 || c > 57) { return false; } }
    return true;
  }
  var MDAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  /* Strict YYYY-MM-DD: Date.UTC would silently roll 2026-02-31 into March and map years 0-99 to 19xx,
   * so impossible dates are rejected (the row is counted as malformed). Mirrored in the fast engine. */
  function dayMs(d) {
    var v = dayCache[d];
    if (v !== undefined) { return v; }
    if (d.length !== 10 || d.charAt(4) !== '-' || d.charAt(7) !== '-' || !isDigits(d, 0, 4) || !isDigits(d, 5, 7) || !isDigits(d, 8, 10)) { return NaN; }
    var y = +d.substr(0, 4), m = +d.substr(5, 2), dd = +d.substr(8, 2), leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
    if (y < 100 || m < 1 || m > 12 || dd < 1 || dd > ((m === 2 && leap) ? 29 : MDAYS[m - 1])) { v = NaN; } else { v = Date.UTC(y, m - 1, dd); }
    if (dayCacheN++ > 20000) { dayCache = U.newMap(); dayCacheN = 0; }
    dayCache[d] = v;
    return v;
  }
  /* Strict HH:MM:SS with an optional .fraction; anything else after the seconds is rejected. */
  function timeMs(t) {
    if (t.length < 8 || t.charAt(2) !== ':' || t.charAt(5) !== ':' || !isDigits(t, 0, 2) || !isDigits(t, 3, 5) || !isDigits(t, 6, 8)) { return NaN; }
    var h = (t.charCodeAt(0) - 48) * 10 + (t.charCodeAt(1) - 48), m = (t.charCodeAt(3) - 48) * 10 + (t.charCodeAt(4) - 48),
      s = (t.charCodeAt(6) - 48) * 10 + (t.charCodeAt(7) - 48), frac = 0;
    if (h > 23 || m > 59 || s > 59) { return NaN; }
    if (t.length > 8) {
      if (t.charAt(8) !== '.' || !isDigits(t, 9, t.length)) { return NaN; }
      if (t.length > 9) { frac = Math.round(+('0' + t.substr(8)) * 1000); }
    }
    return ((h * 60 + m) * 60 + s) * 1000 + frac;
  }
  P.parseW3cDate = function (s) { // "YYYY-MM-DD HH:MM:SS"
    if (!s) { return NaN; }
    var parts = U.trim(s).split(/\s+/);
    return dayMs(parts[0]) + (parts[1] ? timeMs(parts[1]) : 0);
  };

  /* One parser per file. lineFn returns 0=directive/blank, 1=row, 2=malformed. */
  P.FileParser = function (fileId, opts) {
    this.fileId = fileId;
    this.lineNo = 0;
    this.fieldNames = null;
    this.keys = null;
    this.nf = 0;
    this.blocks = [];
    this.software = ''; this.version = ''; this.dateDir = '';
    this.seenContent = false;
    this.notW3C = false;
    this.rowsSinceBind = 0;
    this.unknownFields = [];
    this.splitUri = false;
    this.opts = opts || {};
  };
  P.FileParser.prototype.bind = function (names, r, assumed) {
    var keys = [], i, lname, k;
    this.unknownFields = [];
    this.splitUri = false;
    for (i = 0; i < names.length; i++) {
      lname = names[i].toLowerCase();
      k = Object.prototype.hasOwnProperty.call(P.FIELD_MAP, lname) ? P.FIELD_MAP[lname] : null;
      if (!k) { k = 'x:' + names[i]; this.unknownFields.push(names[i]); }
      if (k === 'uri') { this.splitUri = true; }
      keys.push(k);
    }
    this.fieldNames = names; this.keys = keys; this.nf = names.length;
    this.hasDate = keys.indexOf('date') >= 0;
    this.dIdx = keys.indexOf('date'); this.tIdx = keys.indexOf('time');
    this.blocks.push({ line: this.lineNo, software: this.software, version: this.version, date: this.dateDir,
      dateTs: P.parseW3cDate(this.dateDir), fields: names.join(' '), assumed: !!assumed, rowsBefore: this.rowsSinceBind });
    this.rowsSinceBind = 0;
    // reset reused row so fields absent from this block read as "-"/-1
    var fresh = P.newRow();
    for (k in fresh) { if (fresh.hasOwnProperty(k)) { r[k] = fresh[k]; } }
    r.extra = this.unknownFields.length ? {} : null;
  };
  P.FileParser.prototype.line = function (line, r) {
    this.lineNo++;
    var orig = line; // the line exactly as stored (Windows-1252 view of the bytes), before BOM and UTF-8 handling
    if (this.lineNo === 1 && line.substr(0, 3) === '\u00ef\u00bb\u00bf') { line = line.substr(3); } // UTF-8 BOM read as Windows-1252
    var nonAscii = NONASCII.test(line);
    if (nonAscii) { line = U.fixUtf8(line); }
    if (line.length === 0) { return 0; }
    if (line.charCodeAt(0) === 35) { // '#'
      this.seenContent = true;
      var c = line.indexOf(':'), name = c > 0 ? line.substr(1, c - 1) : line.substr(1), val = c > 0 ? U.trim(line.substr(c + 1)) : '';
      switch (name) {
        case 'Software': this.software = U.own(val); break;
        case 'Version': this.version = U.own(val); break;
        case 'Date': this.dateDir = U.own(val); break;
        case 'Fields': this.bind(U.own(val).split(/\s+/), r, false); break;
        default: break; // Start-Date, End-Date, Remark: ignored
      }
      return 0;
    }
    if (!this.seenContent) {
      this.seenContent = true;
      // First non-empty line is data: not a W3C header; continue with assumed IIS default binding.
      this.notW3C = true;
      this.bind(P.DEFAULT_FIELDS, r, true);
    }
    r.raw = line; r.rawOrig = line !== orig ? orig : null; r.lineNo = this.lineNo; r.fileId = this.fileId; r.blockId = this.blocks.length - 1;
    r.nonAscii = nonAscii;
    if (!this.keys) { r.reason2 = 'unbound row (data before #Fields)'; return 2; }
    var tok = line.split(' ');
    if (tok.length !== this.nf) {
      r.reason2 = (tok.length < this.nf ? 'short row: ' : 'long row: ') + tok.length + ' fields, expected ' + this.nf;
      return 2;
    }
    var keys = this.keys, i, k, v;
    for (i = 0; i < this.nf; i++) {
      k = keys[i]; v = tok[i];
      if (P.NUMERIC[k] === 1) { r[k] = v === '-' ? -1 : +v; if (r[k] !== r[k]) { r[k] = -1; } } else if (k.charCodeAt(1) === 58) { r.extra[k.substr(2)] = v; } else { r[k] = v; }
    }
    if (this.splitUri) {
      var q = r.uri.indexOf('?');
      if (q >= 0) { r.stem = r.uri.substr(0, q); r.query = r.uri.substr(q + 1) || '-'; } else { r.stem = r.uri; r.query = '-'; }
    }
    var ts = this.hasDate ? dayMs(tok[this.dIdx]) + (this.tIdx >= 0 ? timeMs(tok[this.tIdx]) : 0) : P.parseW3cDate(this.dateDir) + (this.tIdx >= 0 ? timeMs(tok[this.tIdx]) % 86400000 : 0);
    if (ts !== ts) { r.reason2 = 'invalid date/time'; return 2; }
    r.ts = ts;
    // effective client IP from proxy headers if logged
    if (r.xff !== '-') {
      var hops = U.pctDecode(r.xff, true).t.split(/[,\s]+/), h, eip = '-';
      for (h = 0; h < hops.length; h++) { if (hops[h] && U.classifyIp(hops[h]) === 'public') { eip = hops[h]; break; } }
      r.eip = eip === '-' ? r.cip : eip;
    } else if (r.xrealip !== '-') { r.eip = r.xrealip; } else { r.eip = r.cip; }
    this.rowsSinceBind++;
    return 1;
  };

  /* ---------- list matchers ---------- */
  /* Entries: "re:<regex>" regex; contains '*' or '?' -> glob (anchored, whole value); else substring. */
  P.buildMatcher = function (entries) {
    var parts = [], i, e;
    for (i = 0; i < (entries || []).length; i++) {
      e = entries[i];
      if (!e) { continue; }
      if (e.substr(0, 3) === 're:') { parts.push('(?:' + e.substr(3) + ')'); } else if (/[*?]/.test(e)) { parts.push('(?:' + U.globToRegexSrc(e.toLowerCase()) + ')'); } else { parts.push(U.reEscape(e.toLowerCase())); }
    }
    if (!parts.length) { return { test: function () { return false; }, empty: true }; }
    var re = new RegExp(parts.join('|'), 'i');
    return { test: function (s) { return re.test(s); }, re: re, empty: false };
  };
  P.extSet = function (entries) {
    var m = {}, i, e;
    for (i = 0; i < (entries || []).length; i++) { e = entries[i].toLowerCase(); if (e.charAt(0) !== '.') { e = '.' + e; } m[e] = 1; }
    return m;
  };
  function endsWithAny(s, list) { var i; for (i = 0; i < list.length; i++) { if (U.endsWith(s, list[i])) { return true; } } return false; }

  /* ---------- derived attributes ---------- */
  var RE = {
    trav: /\.\.[\/\\]|[\/\\]\.\.(?:$|[\/\\;])|%2e%2e|%252e|%c0%ae|%c0%af|%c1%9c|%c1%1c|%e0%80%af|\.\.;\/|%5c\.\.|\.\.%5c|\.\.%2f|%2f\.\./i,
    exp001: /(?:%ad|\u00ad|-)d[\s+]?(?:allow_url_include|auto_prepend_file|cgi\.force_redirect|disable_functions|safe_mode|open_basedir)|php:\/\/input|php%3a%2f%2finput/i,
    sqliHigh: /union[\s+\/*()]+(?:all[\s+\/*()]+)?select|waitfor[\s+]+delay|xp_cmdshell|sp_oacreate|benchmark\s*\(|sleep\s*\(\s*\d|@@version|information_schema|pg_sleep|dbms_pipe|extractvalue\s*\(|updatexml\s*\(|load_file\s*\(|into[\s+]+(?:out|dump)file|;\s*(?:drop|insert|update|delete|exec|declare)[\s+]/i,
    sqliMed: /'\s*or\s*'|\bor\s+\d+\s*=\s*\d+|'\s*--|;\s*--|\/\*[\s\S]*\*\/|\bcast\s*\(|\bchar\s*\(\s*\d|\bconvert\s*\(|\bselect\b[\s\S]+\bfrom\b|'\s*and\s*'|\band\s+\d+\s*=\s*\d+|0x[0-9a-f]{8,}/ig,
    cmdi: /cmd(?:\.exe)?[\s+]+\/c|powershell|pwsh|\/bin\/(?:ba)?sh|\bwget[\s+]+https?:|\bcurl[\s+]+(?:-\S+[\s+]+)*https?:|certutil|bitsadmin|base64[\s+]+-d|\beval\s*\(|\bsystem\s*\(|\bexec\s*\(|passthru\s*\(|shell_exec|proc_open|popen\s*\(|\$\{jndi:|\$\{(?:env|sys|lower|upper|::-)|<script|javascript:|`[^`]{1,80}`|\|\|\s*\w|;\s*(?:id|whoami|uname|cat|ls|wget|curl|nc|ncat|bash|sh|ping|nslookup|echo)\b|\$\(\s*\w|\/etc\/passwd|c:\\windows\\win\.ini|win\.ini|boot\.ini/i,
    phpinfo: /(?:^|&)(?:phpinfo(?:=|&|$)|xdebuginfo|xdebug_session_start|q=info$|info=1$|phpinfo\(\))/i,
    versionOnly: /^(?:v|ver|version|_|t|ts|rev|cb|cachebuster|cache|hash|d)=[\w.\-]*$/i,
    hasD: /(?:^|&)d=/i,
    wsdl: /^(?:wsdl|disco|singlewsdl|xsd=|wsdl=)/i,
    axd: /\/(?:webresource|scriptresource)\.axd$/i,
    svc: /\.(?:asmx|svc)$/i,
    shellUa: /antsword|godzilla|behinder|weevely|china ?chopper|altman|cknife|b374k|^java\/[\d.]+$/i,
    php: /\.(?:php\d?|phtml|cgi|pl)$/i,
    dotnet: /\.(?:aspx|ashx|asmx|axd|svc|asp|cshtml|rem|soap)$/i
  };
  P.RE = RE;
  P.UA_FAMILIES_SRC = null; // filled below for the out-of-process engine

  var UA_FAMILIES = [
    ['bot', /googlebot|bingbot|baiduspider|yandex(?:bot)?|duckduckbot|slurp|applebot|ahrefsbot|semrushbot|mj12bot|petalbot|bytespider|gptbot|claudebot|ccbot|facebookexternalhit|dotbot|seznambot|sogou|exabot|ia_archiver/i],
    ['library', /python-requests|python-urllib|python\/|aiohttp|httpx|go-http-client|^curl\/|wget|^java\/|okhttp|apache-httpclient|libwww-perl|^ruby|^php\/|node-fetch|axios|undici|powershell|winhttp|microsoft-cryptoapi|^dalvik|cfnetwork|^mozilla\/5\.0$|^-$/i],
    ['edge', /edg(?:e|a|ios)?\//i], ['opera', /opr\/|opera/i], ['chrome', /chrome\/|crios\//i], ['firefox', /firefox\/|fxios\//i],
    ['safari', /safari\//i], ['ie', /msie |trident\//i], ['mobile-app', /mobile|android|iphone|ipad/i]
  ];

  /* Deriver caches per-distinct-value attributes so per-row cost stays low. */
  P.Deriver = function (lists, opts) {
    lists = lists || {};
    this.opts = opts || {};
    this.execExt = P.extSet(lists['executable-extensions'] || ['.aspx', '.ashx', '.asmx', '.asp', '.axd', '.svc', '.cshtml', '.vbhtml', '.soap', '.rem', '.php', '.jsp', '.jspx', '.cfm', '.cgi', '.pl', '.py']);
    this.staticExt = P.extSet(lists['static-extensions'] || ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.map', '.htm', '.html', '.txt', '.xml', '.json', '.bmp', '.webp']);
    this.ws005Ext = P.extSet(lists['static-abuse-extensions'] || ['.jpg', '.jpeg', '.gif', '.png', '.txt', '.css', '.ico', '.svg', '.xml', '.config', '.log']);
    this.probeExt = lists['probe-extensions'] || ['.bak', '.old', '.orig', '.swp', '.save', '.tmp', '.sql', '.zip', '.tar.gz', '.tgz', '.7z', '.rar', '~', '.backup', '.copy'];
    this.sens = P.buildMatcher(lists['sensitive-paths']);
    this.scanUa = P.buildMatcher(lists['scanner-user-agents']);
    this.loginEp = P.buildMatcher(lists['login-endpoints']);
    this.exPath = P.buildMatcher(lists['known-exploit-paths']);
    this.upDirs = P.buildMatcher(lists['upload-directories']);
    this.dlEp = P.buildMatcher(lists['download-endpoints']);
    this.pubDl = P.buildMatcher(lists['public-download-directories']);
    this.exfExt = P.extSet(lists['exfil-extensions']);
    this.exfHigh = P.extSet(lists['exfil-high-extensions']);
    this.shellName = P.buildMatcher(lists['webshell-names']);
    this.shellParam = P.buildMatcher(lists['webshell-parameters']);
    this.dotnetProbe = P.buildMatcher(lists['dotnet-probe-paths']);
    this.heartbeat = null;
    this.reset();
  };
  P.Deriver.prototype.reset = function () {
    this.sc = U.newMap(); this.scN = 0;
    this.qc = U.newMap(); this.qcN = 0;
    this.uc = U.newMap(); this.ucN = 0;
    this.ic = U.newMap(); this.icN = 0;
  };
  P.Deriver.prototype.stem = function (raw) {
    var v = this.sc[raw];
    if (v) { return v; }
    if (this.scN++ > 150000) { this.sc = U.newMap(); this.scN = 0; }
    var key = U.own(raw.toLowerCase()), d = U.pctDecode(raw, false), dec = U.own(d.t.toLowerCase()), ext = U.extOf(dec), dir = U.dirOf(dec);
    var base = dec.substr(dec.lastIndexOf('/') + 1);
    v = {
      key: key, dec: dec, ext: ext, dir: dir, base: base, decErr: d.e,
      exec: this.execExt[ext] === 1, stat: this.staticExt[ext] === 1, ws005: this.ws005Ext[ext] === 1,
      sens: this.sens.test(dec), probe: endsWithAny(dec, this.probeExt),
      exPath: this.exPath.test(dec), trav: RE.trav.test(key) || RE.trav.test(dec), cmdi: RE.cmdi.test(dec), exp001: RE.exp001.test(key),
      shellName: this.shellName.test(base), upDir: this.upDirs.test(dir), dlEp: this.dlEp.test(dec), loginEp: this.loginEp.test(dec),
      pubDl: this.pubDl.test(dir), exf: this.exfExt[ext] === 1, exfHigh: this.exfHigh[ext] === 1, long: raw.length >= 1024,
      dotnetProbe: this.dotnetProbe.test(dec), axd: RE.axd.test(dec), svc: RE.svc.test(dec), php: RE.php.test(dec), dotnet: RE.dotnet.test(dec)
    };
    this.sc[raw] = v;
    return v;
  };
  P.Deriver.prototype.query = function (raw) {
    var v = this.qc[raw];
    if (v) { return v; }
    if (this.qcN++ > 150000) { this.qc = U.newMap(); this.qcN = 0; }
    if (raw === '-' || raw === '') {
      v = { empty: true, dec: '', lower: '', len: 0, decErr: false, exp001: false, trav: false, sqli: 0, cmdi: false, phpinfo: false, shellParam: false, highEnt: false, long: false, versionOnly: false, hasD: false, wsdl: false };
    } else {
      var d = U.pctDecode(raw, true), lower = U.own(d.t.toLowerCase()), rl = raw.toLowerCase(), sq = 0;
      if (RE.sqliHigh.test(lower)) { sq = 2; } else {
        var mm = lower.match(RE.sqliMed);
        if (mm && mm.length >= 2) { sq = 1; }
      }
      v = {
        empty: false, dec: U.own(d.t), lower: lower, len: raw.length, decErr: d.e,
        exp001: RE.exp001.test(rl) || RE.exp001.test(lower), trav: RE.trav.test(rl) || RE.trav.test(lower), sqli: sq,
        cmdi: RE.cmdi.test(lower), phpinfo: RE.phpinfo.test(lower), shellParam: this.shellParam.test(lower),
        highEnt: raw.length >= 200 && U.entropy(raw) >= 5.5, long: raw.length >= 2048, versionOnly: RE.versionOnly.test(lower),
        hasD: RE.hasD.test(lower), wsdl: RE.wsdl.test(lower)
      };
    }
    this.qc[raw] = v;
    return v;
  };
  P.Deriver.prototype.ua = function (raw) {
    var v = this.uc[raw];
    if (v) { return v; }
    if (this.ucN++ > 100000) { this.uc = U.newMap(); this.ucN = 0; }
    var dec = raw === '-' ? '' : U.own(raw.replace(/\+/g, ' ')), fam = 'other', i, scanner = this.scanUa.test(dec), shell = RE.shellUa.test(dec);
    if (!dec) { fam = 'empty'; } else if (shell) { fam = 'webshell-client'; } else if (scanner) { fam = 'scanner'; } else {
      for (i = 0; i < UA_FAMILIES.length; i++) { if (UA_FAMILIES[i][1].test(dec)) { fam = UA_FAMILIES[i][0]; break; } }
    }
    v = { dec: dec, fam: fam, scanner: scanner, shellUa: shell, empty: !dec };
    this.uc[raw] = v;
    return v;
  };
  P.Deriver.prototype.ipClass = function (ip) {
    var v = this.ic[ip];
    if (v) { return v; }
    if (this.icN++ > 200000) { this.ic = U.newMap(); this.icN = 0; }
    v = U.classifyIp(ip);
    this.ic[ip] = v;
    return v;
  };
  P.UA_FAMILIES = UA_FAMILIES;
  P.UA_FAMILY_NAMES = ['edge', 'chrome', 'firefox', 'safari', 'ie', 'opera', 'mobile-app', 'bot', 'library', 'scanner', 'webshell-client', 'empty', 'other'];
}(IISLA));
