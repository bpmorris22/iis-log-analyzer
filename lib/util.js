/* IIS Log Analyzer - util.js
 * Shared helpers. ES5 only (IE11 document mode inside mshta.exe).
 * Never use let/const/arrow functions/template literals in this project.
 */
var IISLA = IISLA || {};
(function (NS) {
  'use strict';
  var U = NS.util = {};

  NS.VERSION = '1.1.1';
  NS.bootWarnings = NS.bootWarnings || [];
  /* Debug trace to %TEMP%\iisla-trace.log (enabled with /trace on the command line or always during autotest). */
  NS.traceOn = false;
  NS.trace = function (msg) {
    if (!NS.traceOn) { return; }
    try {
      var sh = new ActiveXObject("WScript.Shell"), p = sh.ExpandEnvironmentStrings("%TEMP%") + String.fromCharCode(92) + "iisla-trace.log";
      var ts = new ActiveXObject("Scripting.FileSystemObject").OpenTextFile(p, 8, true, 0);
      ts.WriteLine(new Date().toISOString() + " " + String(msg).replace(/[^ -~]/g, "?")); ts.Close();
    } catch (e) { }
  };

  /* ---------- COM helpers ---------- */
  var _fso = null, _sh = null;
  U.fso = function () { if (!_fso) { _fso = new ActiveXObject('Scripting.FileSystemObject'); } return _fso; };
  U.shell = function () { if (!_sh) { _sh = new ActiveXObject('WScript.Shell'); } return _sh; };
  U.expandEnv = function (s) {
    if (!s) { return s; }
    try { return U.shell().ExpandEnvironmentStrings(s); } catch (e) { return s; }
  };
  U.env = function (name) {
    try { var v = U.shell().ExpandEnvironmentStrings('%' + name + '%'); return v === '%' + name + '%' ? '' : v; } catch (e) { return ''; }
  };

  /* ---------- string ownership ----------
   * Substrings of the multi-megabyte read buffer can keep the whole buffer alive in the
   * script engine. Any string that outlives the current chunk (index values, kept examples,
   * loaded rows, cache entries) must be copied with U.own().
   */
  U.own = function (s) { return (s === null || s === undefined || s.length === 0) ? s : JSON.parse(JSON.stringify(s)); };

  /* ---------- maps ---------- */
  // Plain-object hash maps with a key prefix so that keys such as
  // "__proto__" or "constructor" from attacker-controlled logs are safe.
  U.newMap = function () { return Object.create(null); };

  /* ---------- formatting ---------- */
  function p2(n) { return n < 10 ? '0' + n : '' + n; }
  function p3(n) { return n < 10 ? '00' + n : (n < 100 ? '0' + n : '' + n); }
  U.p2 = p2; U.p3 = p3;

  /* Offset in minutes at a UTC instant for tz = fixed minutes (number) or a zone object from tz.js. */
  U.tzOff = function (tz, ms) { return typeof tz === 'number' ? tz : (tz && tz.off ? tz.off(ms) : 0); };
  U.fmtTs = function (ms, offsetMin, withMs) {
    if (ms === null || ms === undefined || isNaN(ms) || ms < 0) { return ''; }
    var d = new Date(ms + U.tzOff(offsetMin, ms) * 60000);
    var s = d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' + p2(d.getUTCDate()) + ' ' +
      p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds());
    if (withMs) { s += '.' + p3(d.getUTCMilliseconds()); }
    return s;
  };
  U.fmtIso = function (ms) {
    if (ms === null || ms === undefined || isNaN(ms)) { return ''; }
    return U.fmtTs(ms, 0).replace(' ', 'T') + 'Z';
  };
  U.dayKey = function (ms) {
    var d = new Date(ms);
    return d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' + p2(d.getUTCDate());
  };
  U.hourKey = function (ms) {
    var d = new Date(ms);
    return d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' + p2(d.getUTCDate()) + 'T' + p2(d.getUTCHours());
  };
  U.dayKeyToMs = function (k) {
    return Date.UTC(+k.substr(0, 4), +k.substr(5, 2) - 1, +k.substr(8, 2));
  };
  U.hourKeyToMs = function (k) {
    return Date.UTC(+k.substr(0, 4), +k.substr(5, 2) - 1, +k.substr(8, 2), +k.substr(11, 2));
  };
  U.nowIso = function () { return U.fmtIso(Date.now()); };
  U.stampForFile = function () {
    var d = new Date();
    return d.getUTCFullYear() + p2(d.getUTCMonth() + 1) + p2(d.getUTCDate()) + '-' +
      p2(d.getUTCHours()) + p2(d.getUTCMinutes()) + p2(d.getUTCSeconds()) + 'Z';
  };
  U.fmtOffset = function (min) {
    var sign = min < 0 ? '-' : '+'; var a = Math.abs(min);
    return 'UTC' + sign + p2(Math.floor(a / 60)) + ':' + p2(a % 60);
  };
  /* Parses "YYYY-MM-DD", "YYYY-MM-DD HH:MM", "YYYY-MM-DD HH:MM:SS", optional T and Z.
   * Interprets the value in offsetMin unless it ends with Z. Returns ms or NaN. */
  U.parseDateInput = function (s, offsetMin) {
    if (!s) { return NaN; }
    s = ('' + s).trim();
    var m = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2})(?::(\d{2}))?(?::(\d{2}))?)?\s*(Z|UTC)?$/i.exec(s);
    if (!m) { return NaN; }
    var ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    if (!m[7]) { ms = (offsetMin && typeof offsetMin === 'object' && offsetMin.localToUtc) ? offsetMin.localToUtc(ms) : ms - (offsetMin || 0) * 60000; }
    return ms;
  };
  U.fmtNum = function (n) {
    if (n === null || n === undefined || isNaN(n)) { return ''; }
    var s = '' + Math.round(n), neg = false;
    if (s.charAt(0) === '-') { neg = true; s = s.substr(1); }
    var out = '';
    while (s.length > 3) { out = ',' + s.substr(s.length - 3) + out; s = s.substr(0, s.length - 3); }
    return (neg ? '-' : '') + s + out;
  };
  U.fmtBytes = function (n) {
    if (n === null || n === undefined || isNaN(n) || n < 0) { return ''; }
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
  };
  U.fmtDuration = function (ms) {
    if (ms === null || ms === undefined || isNaN(ms)) { return ''; }
    if (ms < 1000) { return Math.round(ms) + ' ms'; }
    var s = ms / 1000;
    if (s < 60) { return s.toFixed(1) + ' s'; }
    var m = Math.floor(s / 60); s = Math.round(s % 60);
    if (m < 60) { return m + 'm ' + s + 's'; }
    var h = Math.floor(m / 60); m = m % 60;
    if (h < 48) { return h + 'h ' + m + 'm'; }
    return Math.floor(h / 24) + 'd ' + (h % 24) + 'h';
  };
  U.pct = function (a, b) { return b ? (100 * a / b).toFixed(1) + '%' : ''; };

  /* ---------- escaping ---------- */
  U.stripCtl = function (s) {
    if (s === null || s === undefined) { return ''; }
    return ('' + s).replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '\ufffd');
  };
  U.escHtml = function (s) {
    if (s === null || s === undefined) { return ''; }
    return U.stripCtl(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  };
  U.csvCell = function (s) {
    if (s === null || s === undefined) { return ''; }
    s = ('' + s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
    // Neutralize spreadsheet formula injection from attacker-controlled values.
    if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) { s = "'" + s; }
    if (/[",\r\n]/.test(s)) { s = '"' + s.replace(/"/g, '""') + '"'; }
    return s;
  };
  /* JSON with all non-ASCII escaped, so it can be appended with ANSI FSO streams. */
  U.asciiJson = function (o, indent) {
    return JSON.stringify(o, null, indent).replace(/[\u007F-\uffff]/g, function (c) {
      return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4);
    });
  };

  /* ---------- percent decoding (UTF-8) ---------- */
  function hexv(c) {
    if (c >= 48 && c <= 57) { return c - 48; }
    if (c >= 65 && c <= 70) { return c - 55; }
    if (c >= 97 && c <= 102) { return c - 87; }
    return -1;
  }
  /* Returns {t: decodedText, e: decodeErrorFlag}. '+' becomes space when plus is true. */
  U.pctDecode = function (s, plus) {
    if (s === null || s === undefined || s === '-') { return { t: '', e: false }; }
    if (s.indexOf('%') < 0) { return { t: plus ? s.replace(/\+/g, ' ') : s, e: false }; }
    var bytes = [], out = '', err = false, i, n = s.length, c, h1, h2;
    function flush() {
      if (!bytes.length) { return; }
      var r = utf8(bytes); if (r === null) { err = true; r = latin(bytes); }
      out += r; bytes = [];
    }
    for (i = 0; i < n; i++) {
      c = s.charCodeAt(i);
      if (c === 37 && i + 2 < n) {
        h1 = hexv(s.charCodeAt(i + 1)); h2 = hexv(s.charCodeAt(i + 2));
        if (h1 >= 0 && h2 >= 0) { bytes.push(h1 * 16 + h2); i += 2; continue; }
        if (s.charAt(i + 1) === 'u' || s.charAt(i + 1) === 'U') { err = true; }
      } else if (c === 37) { err = true; }
      flush();
      out += (plus && c === 43) ? ' ' : s.charAt(i);
    }
    flush();
    return { t: out, e: err };
  };
  /* Strict UTF-8 decoder over a byte array; returns null when the bytes are not valid UTF-8. */
  U.utf8Decode = function (b) { return utf8(b); };
  /* Log lines are read as Windows-1252 (a lossless byte-to-character mapping). A line whose bytes form valid
   * UTF-8 (IIS writes UTF-8 by default) is re-decoded as UTF-8; anything else keeps its Windows-1252 reading. */
  var CP1252_HIGH = [0x20AC, 0x81, 0x201A, 0x192, 0x201E, 0x2026, 0x2020, 0x2021, 0x2C6, 0x2030, 0x160, 0x2039, 0x152, 0x8D, 0x17D, 0x8F,
    0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x2DC, 0x2122, 0x161, 0x203A, 0x153, 0x9D, 0x17E, 0x178], CP1252_REV = {};
  (function () { var i; for (i = 0; i < 32; i++) { CP1252_REV[CP1252_HIGH[i]] = 0x80 + i; } }());
  U.CP1252_HIGH = CP1252_HIGH;
  U.fixUtf8 = function (line) {
    var bytes = new Array(line.length), i, c, b;
    for (i = 0; i < line.length; i++) {
      c = line.charCodeAt(i);
      if (c < 0x80 || (c >= 0xA0 && c <= 0xFF)) { b = c; } else { b = CP1252_REV[c]; if (b === undefined) { return line; } }
      bytes[i] = b;
    }
    var s = utf8(bytes);
    return s === null ? line : s;
  };
  function latin(b) { var s = '', i; for (i = 0; i < b.length; i++) { s += String.fromCharCode(b[i]); } return s; }
  function utf8(b) {
    var s = '', i = 0, c, c2, c3, c4, cp;
    while (i < b.length) {
      c = b[i];
      if (c < 0x80) { s += String.fromCharCode(c); i++; continue; }
      if (c >= 0xC2 && c < 0xE0) {
        c2 = b[i + 1]; if (c2 === undefined || (c2 & 0xC0) !== 0x80) { return null; }
        s += String.fromCharCode(((c & 0x1F) << 6) | (c2 & 0x3F)); i += 2; continue;
      }
      if (c >= 0xE0 && c < 0xF0) {
        c2 = b[i + 1]; c3 = b[i + 2];
        if (c2 === undefined || c3 === undefined || (c2 & 0xC0) !== 0x80 || (c3 & 0xC0) !== 0x80) { return null; }
        cp = ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
        if (cp < 0x800) { return null; }
        s += String.fromCharCode(cp); i += 3; continue;
      }
      if (c >= 0xF0 && c < 0xF5) {
        c2 = b[i + 1]; c3 = b[i + 2]; c4 = b[i + 3];
        if (c4 === undefined || (c2 & 0xC0) !== 0x80 || (c3 & 0xC0) !== 0x80 || (c4 & 0xC0) !== 0x80) { return null; }
        cp = ((c & 0x07) << 18) | ((c2 & 0x3F) << 12) | ((c3 & 0x3F) << 6) | (c4 & 0x3F);
        if (cp < 0x10000 || cp > 0x10FFFF) { return null; }
        cp -= 0x10000;
        s += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF)); i += 4; continue;
      }
      return null; // overlong (C0/C1), stray continuation, or invalid lead byte
    }
    return s;
  }

  U.entropy = function (s) {
    if (!s) { return 0; }
    var f = {}, i, n = s.length, h = 0, k, p;
    for (i = 0; i < n; i++) { k = s.charAt(i); f[k] = (f[k] || 0) + 1; }
    for (k in f) { if (f.hasOwnProperty(k)) { p = f[k] / n; h -= p * Math.log(p) / Math.LN2; } }
    return h;
  };

  /* ---------- glob / lists ---------- */
  U.reEscape = function (s) { return ('' + s).replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&'); };
  U.globToRegexSrc = function (g) {
    var out = '', i, c;
    for (i = 0; i < g.length; i++) {
      c = g.charAt(i);
      if (c === '*') { out += '.*'; } else if (c === '?') { out += '.'; } else { out += U.reEscape(c); }
    }
    return '^' + out + '$';
  };
  U.globToRegex = function (g) { return new RegExp(U.globToRegexSrc(g), 'i'); };
  /* Parses list text: one entry per line, # comments, blank lines ignored. */
  U.parseList = function (text) {
    var out = [], lines = (text || '').split(/\r?\n/), i, l;
    for (i = 0; i < lines.length; i++) {
      l = lines[i].replace(/^\s+|\s+$/g, '');
      if (!l || l.charAt(0) === '#') { continue; }
      out.push(l);
    }
    return out;
  };

  /* ---------- IP helpers ---------- */
  U.parseIPv4 = function (s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) { return -1; }
    var a = +m[1], b = +m[2], c = +m[3], d = +m[4];
    if (a > 255 || b > 255 || c > 255 || d > 255) { return -1; }
    return ((a * 256 + b) * 256 + c) * 256 + d;
  };
  /* Expands an IPv6 address to 32 lowercase hex chars, or null. */
  U.expandIPv6 = function (s) {
    s = ('' + s).toLowerCase();
    var pct = s.indexOf('%'); if (pct >= 0) { s = s.substr(0, pct); }
    if (s.charAt(0) === '[') { s = s.replace(/^\[|\]$/g, ''); }
    if (!/^[0-9a-f:.]+$/.test(s) || s.indexOf(':') < 0) { return null; }
    var v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s), tail = [];
    if (v4) {
      var n = U.parseIPv4(v4[1]); if (n < 0) { return null; }
      s = s.substr(0, s.length - v4[1].length) + ('0000' + Math.floor(n / 65536).toString(16)).slice(-4) + ':' + ('0000' + (n % 65536).toString(16)).slice(-4);
    }
    var parts = s.split('::');
    if (parts.length > 2) { return null; }
    var head = parts[0] ? parts[0].split(':') : [];
    tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
    var fill = 8 - head.length - tail.length;
    if (parts.length === 1 && fill !== 0) { return null; }
    if (fill < 0) { return null; }
    var all = head.slice(0), i;
    for (i = 0; i < fill; i++) { all.push('0'); }
    all = all.concat(tail);
    var out = '';
    for (i = 0; i < 8; i++) {
      if (!/^[0-9a-f]{1,4}$/.test(all[i])) { return null; }
      out += ('0000' + all[i]).slice(-4);
    }
    return out;
  };
  U.isValidIp = function (s) { return U.parseIPv4(s) >= 0 || U.expandIPv6(s) !== null; };

  /* CIDR object: {v:4, base, mask} or {v:6, hex, bits} */
  U.parseCidr = function (s) {
    s = ('' + s).trim();
    var slash = s.indexOf('/'), ip = slash >= 0 ? s.substr(0, slash) : s, bits = slash >= 0 ? +s.substr(slash + 1) : -1;
    var n4 = U.parseIPv4(ip);
    if (n4 >= 0) {
      if (bits < 0) { bits = 32; }
      if (!(bits >= 0 && bits <= 32)) { return null; }
      var size = Math.pow(2, 32 - bits);
      return { v: 4, base: Math.floor(n4 / size) * size, size: size, text: s };
    }
    var h = U.expandIPv6(ip);
    if (h) {
      if (bits < 0) { bits = 128; }
      if (!(bits >= 0 && bits <= 128)) { return null; }
      return { v: 6, hex: h, bits: bits, text: s };
    }
    return null;
  };
  function hexPrefixMatch(a, b, bits) {
    var full = Math.floor(bits / 4), rem = bits % 4;
    if (a.substr(0, full) !== b.substr(0, full)) { return false; }
    if (!rem) { return true; }
    var m = (0xF << (4 - rem)) & 0xF;
    return (parseInt(a.charAt(full), 16) & m) === (parseInt(b.charAt(full), 16) & m);
  }
  U.cidrMatch = function (cidr, ip) {
    if (!cidr) { return false; }
    if (cidr.v === 4) {
      var n = U.parseIPv4(ip);
      if (n < 0) {
        var h = U.expandIPv6(ip);
        if (h && h.substr(0, 24) === '00000000000000000000ffff') { n = parseInt(h.substr(24), 16); } else { return false; }
      }
      return n >= cidr.base && n < cidr.base + cidr.size;
    }
    var hx = U.expandIPv6(ip);
    return !!hx && hexPrefixMatch(hx, cidr.hex, cidr.bits);
  };

  var EXTRA_INTERNAL = [], ALLOW = {}, ALLOW_N = 0;
  /* Allow-listed client IPs (e.g. Hawk allowed IPs) get class 'allowlisted', which suppresses public/internal rules but keeps rows visible. */
  U.getAllowlist = function () { var o = [], k; for (k in ALLOW) { if (Object.prototype.hasOwnProperty.call(ALLOW, k)) { o.push(k); } } return o; };
  U.setAllowlist = function (list) {
    ALLOW = {}; ALLOW_N = 0;
    var i, v;
    for (i = 0; i < (list || []).length; i++) { v = U.trim(list[i]).toLowerCase(); if (v && U.isValidIp(v)) { ALLOW[v] = 1; ALLOW_N++; } }
    return ALLOW_N;
  };
  U.setInternalCidrs = function (list) {
    EXTRA_INTERNAL = [];
    var i, c;
    for (i = 0; i < (list || []).length; i++) { c = U.parseCidr(list[i]); if (c) { EXTRA_INTERNAL.push(c); } }
  };
  /* Classes: loopback, rfc1918, internal (user CIDR), linklocal, cgnat, bogon, public, invalid, none */
  U.classifyIp = function (s) {
    if (!s || s === '-') { return 'none'; }
    if (ALLOW_N && ALLOW[s.toLowerCase()] === 1) { return 'allowlisted'; }
    var n = U.parseIPv4(s), i;
    if (n < 0) {
      var h = U.expandIPv6(s);
      if (!h) { return 'invalid'; }
      if (h.substr(0, 24) === '00000000000000000000ffff') {
        var v = parseInt(h.substr(24), 16);
        return U.classifyIp(Math.floor(v / 16777216) + '.' + (Math.floor(v / 65536) % 256) + '.' + (Math.floor(v / 256) % 256) + '.' + (v % 256));
      }
      if (h === '00000000000000000000000000000001') { return 'loopback'; }
      for (i = 0; i < EXTRA_INTERNAL.length; i++) { if (U.cidrMatch(EXTRA_INTERNAL[i], s)) { return 'internal'; } }
      if (/^fe[89ab]/.test(h)) { return 'linklocal'; }
      if (/^f[cd]/.test(h)) { return 'rfc1918'; }
      if (h === '00000000000000000000000000000000' || /^ff/.test(h) || (!TESTNETS_PUBLIC && /^20010db8/.test(h))) { return 'bogon'; }
      return 'public';
    }
    var a = Math.floor(n / 16777216), b = Math.floor(n / 65536) % 256;
    if (a === 127) { return 'loopback'; }
    for (i = 0; i < EXTRA_INTERNAL.length; i++) { if (U.cidrMatch(EXTRA_INTERNAL[i], s)) { return 'internal'; } }
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) { return 'rfc1918'; }
    if (a === 169 && b === 254) { return 'linklocal'; }
    if (a === 100 && b >= 64 && b <= 127) { return 'cgnat'; }
    var c3 = Math.floor(n / 256) % 256;
    var testNet = (a === 192 && b === 0 && c3 === 2) || (a === 198 && b === 51 && c3 === 100) || (a === 203 && b === 0 && c3 === 113);
    if (a === 0 || a >= 224 || (testNet && !TESTNETS_PUBLIC) || (a === 198 && (b === 18 || b === 19))) { return 'bogon'; }
    return 'public';
  };
  /* Training and demo data only: classify the documentation ranges (RFC 5737 TEST-NET-1/2/3 and 2001:db8::/32)
   * as public so internet-facing rules can be demonstrated without using real addresses. Off by default. */
  var TESTNETS_PUBLIC = false;
  U.setTestNetsPublic = function (on) { TESTNETS_PUBLIC = !!on; };
  U.testNetsPublic = function () { return TESTNETS_PUBLIC; };
  U.IP_CLASSES = ['public', 'allowlisted', 'rfc1918', 'internal', 'loopback', 'linklocal', 'cgnat', 'bogon', 'invalid', 'none'];
  U.isInternalClass = function (c) { return c === 'rfc1918' || c === 'internal' || c === 'loopback' || c === 'linklocal'; };

  /* ---------- path helpers ---------- */
  U.extOf = function (stemLower) {
    var slash = stemLower.lastIndexOf('/'), base = stemLower.substr(slash + 1), dot = base.lastIndexOf('.');
    return dot > 0 || (dot === 0 && base.length > 1) ? base.substr(dot) : '';
  };
  U.dirOf = function (stemLower) {
    var slash = stemLower.lastIndexOf('/');
    return slash > 0 ? stemLower.substr(0, slash + 1) : '/';
  };
  U.baseOf = function (p) {
    var i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
    return i >= 0 ? p.substr(i + 1) : p;
  };
  U.parentOf = function (p) {
    var i = p.lastIndexOf('\\');
    return i > 0 ? p.substr(0, i) : p;
  };
  U.joinPath = function (a, b) {
    if (!a) { return b; }
    return a.charAt(a.length - 1) === '\\' ? a + b : a + '\\' + b;
  };
  U.safeName = function (s) { return ('' + s).replace(/[^A-Za-z0-9._\-]+/g, '_').substr(0, 80); };
  /* True when child is the same as or inside parent (case-insensitive). */
  U.isInside = function (child, parent) {
    if (!child || !parent) { return false; }
    var c = child.toLowerCase().replace(/[\\\/]+$/, '') + '\\', p = parent.toLowerCase().replace(/[\\\/]+$/, '') + '\\';
    return c.indexOf(p) === 0;
  };

  /* ---------- file I/O (UTF-8 via ADODB.Stream) ---------- */
  U.fileExists = function (p) { try { return U.fso().FileExists(p); } catch (e) { return false; } };
  U.folderExists = function (p) { try { return U.fso().FolderExists(p); } catch (e) { return false; } };
  U.ensureFolder = function (p) {
    var f = U.fso();
    if (!p || f.FolderExists(p)) { return; }
    var parent = f.GetParentFolderName(p);
    if (parent && parent !== p) { U.ensureFolder(parent); }
    f.CreateFolder(p);
  };
  /* ADODB.Stream.ReadText is pathologically slow for large counts in mshta; 64 KB chunks are fast. */
  U.readTextUtf8 = function (path) {
    var st = new ActiveXObject('ADODB.Stream'), parts = [];
    st.Type = 2; st.Charset = 'utf-8'; st.Open();
    try { st.LoadFromFile(path); while (!st.EOS) { parts.push(st.ReadText(65536)); } return parts.join(''); } finally { st.Close(); }
  };
  /* Writes text as UTF-8; bom=false strips the BOM ADODB always emits. */
  U.writeTextUtf8 = function (path, text, bom) {
    var w = U.utf8Writer(path, bom);
    w.write(text); w.close();
  };
  /* Streaming UTF-8 writer for large exports. */
  U.utf8Writer = function (path, bom) {
    var st = new ActiveXObject('ADODB.Stream');
    st.Type = 2; st.Charset = 'utf-8'; st.Open();
    return {
      write: function (t) { if (t) { st.WriteText(t); } },
      close: function () {
        try {
          if (bom) { st.SaveToFile(path, 2); return; }
          st.Position = 0; st.Type = 1; st.Position = 3;
          var bin = new ActiveXObject('ADODB.Stream'); bin.Type = 1; bin.Open();
          st.CopyTo(bin); bin.SaveToFile(path, 2); bin.Close();
        } finally { st.Close(); }
      }
    };
  };
  /* Fast paths for large files. ADODB.Stream.ReadText is extremely slow on large streams (~1 MB/s in mshta),
   * so big JSON (the scan index) is written as pure ASCII (non-ASCII escaped as \uXXXX) and read with FSO. */
  U.readTextAnsi = function (path) {
    var f = U.fso(), ts;
    if (f.GetFile(path).Size === 0) { return ''; }
    ts = f.OpenTextFile(path, 1, false, 0);
    try { return ts.ReadAll(); } finally { ts.Close(); }
  };
  U.writeJsonAscii = function (path, obj) {
    var text = U.asciiJson(obj), ts = U.fso().CreateTextFile(path, true, false);
    try { ts.Write(text); } finally { ts.Close(); }
    return text.length;
  };
  U.readJsonAscii = function (path) {
    if (!U.fileExists(path)) { return null; }
    var t = U.readTextAnsi(path);
    if (t.substr(0, 3) === '\u00ef\u00bb\u00bf') { t = t.substr(3); }
    return JSON.parse(t);
  };
  U.appendAscii = function (path, line) {
    var ts = U.fso().OpenTextFile(path, 8, true, 0);
    try { ts.WriteLine(line); } finally { ts.Close(); }
  };
  U.readJson = function (path) {
    if (!U.fileExists(path)) { return null; }
    var t = U.readTextUtf8(path);
    if (t.charCodeAt(0) === 0xFEFF) { t = t.substr(1); }
    return JSON.parse(t);
  };
  U.writeJson = function (path, obj, indent) { U.writeTextUtf8(path, JSON.stringify(obj, null, indent), false); };

  /* ---------- misc ---------- */
  U.sortedKeys = function (obj, valFn, n) {
    var ks = [], k;
    for (k in obj) { ks.push(k); }
    ks.sort(function (a, b) { return valFn(obj[b]) - valFn(obj[a]) || (a < b ? -1 : a > b ? 1 : 0); });
    return n ? ks.slice(0, n) : ks;
  };
  U.countKeys = function (obj) { var n = 0, k; for (k in obj) { n++; } return n; };
  U.clone = function (o) { return JSON.parse(JSON.stringify(o)); };
  U.extend = function (dst) {
    var i, k, s;
    for (i = 1; i < arguments.length; i++) { s = arguments[i]; if (s) { for (k in s) { if (Object.prototype.hasOwnProperty.call(s, k)) { dst[k] = s[k]; } } } }
    return dst;
  };
  U.startsWith = function (s, p) { return s.substr(0, p.length) === p; };
  U.endsWith = function (s, p) { return p.length <= s.length && s.substr(s.length - p.length) === p; };
  U.trim = function (s) { return ('' + s).replace(/^\s+|\s+$/g, ''); };
  U.median = function (arr) {
    if (!arr.length) { return 0; }
    var a = arr.slice(0).sort(function (x, y) { return x - y; }), m = Math.floor(a.length / 2);
    return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
  };
  U.percentile = function (sorted, p) {
    if (!sorted.length) { return 0; }
    return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
  };

  /* Business-hours test in the display time zone. */
  U.isBusinessTime = function (ms, bh, offsetMin) {
    var local = ms + U.tzOff(offsetMin, ms) * 60000, dayMs = 86400000;
    var dow = (Math.floor(local / dayMs) + 4) % 7; if (dow < 0) { dow += 7; }
    if (bh.days.indexOf(dow) < 0) { return false; }
    var mins = Math.floor((local % dayMs) / 60000); if (mins < 0) { mins += 1440; }
    var s = bh.start.split(':'), e = bh.end.split(':');
    return mins >= (+s[0] * 60 + +s[1]) && mins < (+e[0] * 60 + +e[1]);
  };

  /* Windows error code lookups surfaced in the UI. */
  U.WIN32 = {
    0: 'Success', 2: 'File not found', 3: 'Path not found', 5: 'Access denied', 13: 'Invalid data',
    50: 'Request not supported', 64: 'Network name no longer available (client disconnected)',
    121: 'Semaphore timeout', 1: 'Incorrect function', 87: 'Invalid parameter', 995: 'I/O operation aborted',
    1229: 'Connection no longer exists', 1236: 'Connection aborted by local system', 1726: 'RPC call failed',
    2147942402: 'File not found (HRESULT)', 2147943395: 'Connection aborted (HRESULT)'
  };
  U.SUBSTATUS = {
    '401.1': 'Logon failed', '401.2': 'Logon failed due to server configuration', '401.3': 'Unauthorized due to ACL',
    '401.4': 'Authorization failed by filter', '401.5': 'Authorization failed by ISAPI/CGI',
    '403.1': 'Execute access forbidden', '403.2': 'Read access forbidden', '403.4': 'SSL required',
    '403.6': 'IP address rejected', '403.14': 'Directory listing denied', '403.18': 'Cannot execute in this application pool',
    '403.19': 'Cannot execute CGI in this application pool', '403.502': 'Too many requests (dynamic IP restriction)',
    '403.503': 'Rejected due to IP restriction', '404.0': 'Not found', '404.2': 'ISAPI/CGI restriction',
    '404.3': 'MIME map policy prevents this request', '404.4': 'No handler configured', '404.5': 'URL sequence denied',
    '404.6': 'Verb denied', '404.7': 'File extension denied', '404.8': 'Hidden namespace (e.g. bin, App_Data)',
    '404.9': 'Hidden file attribute', '404.10': 'Request header too long', '404.11': 'Double escape sequence',
    '404.12': 'High-bit characters', '404.13': 'Content length too large', '404.14': 'URL too long',
    '404.15': 'Query string too long', '404.17': 'Dynamic content mapped to static handler',
    '404.18': 'Query string sequence denied', '404.19': 'Denied by filtering rule', '404.20': 'Too many URL segments',
    '500.0': 'Module or ISAPI error', '500.19': 'Configuration data invalid', '500.21': 'Module not recognized',
    '500.50': 'Rewrite error', '503.0': 'Application pool unavailable', '503.2': 'Concurrent request limit exceeded'
  };
  U.METHODS_VALID = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT', 'PROPFIND',
    'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'SEARCH', 'DEBUG', 'RPC_IN_DATA', 'RPC_OUT_DATA',
    'BITS_POST', 'REPORT', 'MERGE', 'CHECKOUT', 'UNCHECKOUT', 'MKACTIVITY', 'VERSION-CONTROL'];
}(IISLA));
