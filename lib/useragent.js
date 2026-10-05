/* IIS Log Analyzer - useragent.js
 * User-agent analysis: browser and version, operating system, how old the browser version was when the request was
 * made, end of support, combinations that cannot exist (spoofed strings), malformed strings, injection payloads and
 * automation tools. Release dates come from lists\browser-releases.txt. Everything is derived from the user-agent
 * string and the request time, so both scan engines share it: the index keeps per-user-agent counts and this module
 * classifies each distinct string when a view, a filter or an aggregate rule asks for it.
 */
(function (NS) {
  'use strict';
  var U = NS.util, P = NS.parser, UA = NS.useragent = {};
  var DAY = 86400000;

  UA.FLAGS = ['stale', 'eol', 'eol-os', 'impossible', 'malformed', 'inject', 'headless', 'rare'];
  UA.FLAG_HELP = {
    stale: 'browser version older than the stale threshold when the request was made',
    eol: 'browser past its end of support when the request was made (Internet Explorer, EdgeHTML Edge, Presto Opera)',
    'eol-os': 'operating system past its end of support when the request was made (Windows XP, Vista, 7, 8, 8.1 ...)',
    impossible: 'a combination that never existed: browser version not released yet, or not available for that Windows version, or a Windows version that does not exist',
    malformed: 'unbalanced brackets, control characters, a misspelt or odd Mozilla token, a Chrome version not in four-part form, or an unusually long string',
    inject: 'exploit payload in the user agent (Log4Shell, Shellshock, OGNL, script, SQL or shell injection)',
    headless: 'headless browser or browser automation (HeadlessChrome, PhantomJS, Selenium, Puppeteer, Playwright ...)',
    rare: 'seen from no more than the configured number of clients, at least one of them public'
  };
  UA.cfg = { staleDays: 365, rareIps: 1, futureDays: 120 };
  UA.gen = 1; // bumped when thresholds or tables change, invalidating the results cached by UA.atDay
  UA.configure = function (settings) {
    if (!settings) { return; }
    if (settings.uaStaleDays > 0) { UA.cfg.staleDays = +settings.uaStaleDays; }
    if (settings.uaRareIps > 0) { UA.cfg.rareIps = +settings.uaRareIps; }
    UA.gen++;
  };

  /* ---------- release table ---------- */
  var REL = U.newMap(), CAD = U.newMap(), EOL = U.newMap(), cache = U.newMap(), cacheN = 0;
  UA.loaded = false;
  function dateMs(s) { var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || ''); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3]) : NaN; }
  /* lines: the parsed lines of lists\browser-releases.txt */
  UA.init = function (lines) {
    REL = U.newMap(); CAD = U.newMap(); EOL = U.newMap(); cache = U.newMap(); cacheN = 0;
    var i, p, ms, e;
    for (i = 0; i < (lines || []).length; i++) {
      p = U.trim(lines[i]).split(/\s+/);
      if (p[0] === 'cadence' && p.length >= 3 && +p[2] > 0) { CAD[p[1].toLowerCase()] = +p[2] * DAY; continue; }
      if (p[0] === 'eol' && p.length >= 3) { ms = dateMs(p[2]); if (!isNaN(ms)) { e = p[1].toLowerCase(); (EOL[e] || (EOL[e] = [])).push([p.length > 3 ? +p[3] : Infinity, ms]); } continue; }
      if (p.length >= 3 && /^\d+$/.test(p[1])) { ms = dateMs(p[2]); if (!isNaN(ms)) { e = p[0].toLowerCase(); (REL[e] || (REL[e] = [])).push([+p[1], ms]); } }
    }
    for (e in REL) { REL[e].sort(function (a, b) { return a[0] - b[0]; }); }
    for (e in EOL) { EOL[e].sort(function (a, b) { return a[0] - b[0]; }); }
    UA.loaded = true; UA.gen++;
  };
  /* Release date of a major version: { ms, est } with est 0 listed, 1 interpolated (or older than the first listed
   * version: its date is then a lower bound on the age), 2 extrapolated with the cadence. Null without a table. */
  UA.release = function (engine, major) {
    var t = REL[engine], i, a, b, cad;
    if (!t || !t.length || !(major >= 0)) { return null; }
    if (major <= t[0][0]) { return { ms: t[0][1], est: major === t[0][0] ? 0 : 1 }; }
    for (i = 1; i < t.length; i++) {
      if (major <= t[i][0]) {
        a = t[i - 1]; b = t[i];
        if (major === b[0]) { return { ms: b[1], est: 0 }; }
        return { ms: Math.round(a[1] + (b[1] - a[1]) * (major - a[0]) / (b[0] - a[0])), est: 1 };
      }
    }
    a = t[t.length - 1];
    cad = CAD[engine] || (t.length > 1 ? (a[1] - t[t.length - 2][1]) / (a[0] - t[t.length - 2][0]) : 365 * DAY);
    return { ms: Math.round(a[1] + (major - a[0]) * cad), est: 2 };
  };
  function eolOf(engine, major) {
    var t = EOL[engine], i;
    if (!t) { return 0; }
    for (i = 0; i < t.length; i++) { if (!(major >= 0) || major <= t[i][0]) { return t[i][1]; } }
    return 0;
  }

  /* ---------- parsing ---------- */
  // Windows NT versions (client editions; end of support dates of the client release)
  var NT = {
    '4.0': ['Windows NT 4.0', '2004-06-30'], '5.0': ['Windows 2000', '2010-07-13'], '5.01': ['Windows 2000', '2010-07-13'],
    '5.1': ['Windows XP', '2014-04-08'], '5.2': ['Windows XP x64 / Server 2003', '2015-07-14'], '6.0': ['Windows Vista', '2017-04-11'],
    '6.1': ['Windows 7', '2020-01-14'], '6.2': ['Windows 8', '2016-01-12'], '6.3': ['Windows 8.1', '2023-01-10'],
    '6.4': ['Windows 10 preview', ''], '10.0': ['Windows 10 / 11', '']
  };
  var NAMES = { chrome: 'Chrome', edge: 'Edge', opera: 'Opera', samsung: 'Samsung Internet', yandex: 'Yandex Browser', 'headless-chrome': 'Headless Chrome',
    firefox: 'Firefox', safari: 'Safari', ie: 'Internet Explorer', 'edge-legacy': 'Edge (EdgeHTML)', 'opera-presto': 'Opera (Presto)', office: 'Microsoft Office',
    'android-browser': 'Android browser' };
  UA.NAMES = NAMES;
  var RX = {
    office: /\bms-office\b|\bmsoffice\b|microsoft (?:office|outlook)|\boutlook-/i,
    trident: /\bTrident\/(\d+)/, msie: /\bMSIE (\d+)/,
    edgeHtml: /\bEdge\/(\d+)/,
    chromium: /\b(HeadlessChrome|Chrome|CriOS|Chromium)\/(\d+)(\S*)/,
    edg: /\bEdg(?:A|iOS)?\/\d/, opr: /\bOPR\/\d/, samsung: /\bSamsungBrowser\/\d/, yandex: /\bYaBrowser\/\d/,
    firefox: /\b(Firefox|FxiOS)\/(\d+)/,
    safari: /\bVersion\/(\d+)[\d.]*(?: Mobile\/\S+)? Safari\//,
    presto: /\bPresto\/|^Opera\/\d/,
    nt: /\bWindows NT (\d+\.\d+)/, winPhone: /\bWindows Phone(?: OS)? \d/, win9x: /\bWindows (?:95|98|ME)\b|\bWin(?:95|98)\b|\bWin 9x\b/,
    ios: /\b(?:iPhone|CPU) OS (\d+)_/, android: /\bAndroid (\d+)(?:\.(\d+))?/, cros: /\bCrOS\b/, mac: /\bMac OS X (\d+)(?:[_.](\d+))?/, linux: /\bLinux\b/,
    headless: /headlesschrome|phantomjs|slimerjs|selenium|webdriver|puppeteer|playwright|htmlunit|\bsplash\/|cypress/i,
    mozilla: /^Mozilla\/(\S*)/, mozTypo: /^(?:mozila|mozzila|mozzilla|mozlla|mozilia|mozill\/)/i, mozParen: /^Mozilla\/[\d.]+\(/,
    ctrl: /[\u0000-\u001f\u007f]/
  };
  function parenOk(s) {
    var d = 0, i, c;
    for (i = 0; i < s.length; i++) { c = s.charAt(i); if (c === '(') { d++; } else if (c === ')') { if (--d < 0) { return false; } } }
    return d === 0;
  }
  function between(v, lo, hi) { return v >= lo && v <= hi; }

  /* Static facts about a decoded user agent (cached). Fields: browser, name, engine, major, ver, os, osEol (ms or 0),
   * rel ({ms, est} or null), bEol (ms or 0), stat ({flag: reason} for impossible, malformed, inject, headless). */
  UA.info = function (dec) {
    dec = dec || '';
    var v = cache[dec];
    if (v) { return v; }
    if (cacheN++ > 100000) { cache = U.newMap(); cacheN = 0; }
    v = parse(dec);
    cache[dec] = v;
    return v;
  };
  function parse(dec) {
    var o = { browser: '', name: '', engine: '', major: -1, ver: '', os: '', osEol: 0, rel: null, bEol: 0, stat: {} }, m, nt = -1, ntv = '', ieReal = -1, msieOnly = false;
    if (!dec) { return o; }
    // operating system
    if ((m = RX.nt.exec(dec))) {
      ntv = m[1]; nt = parseFloat(ntv);
      if (NT[ntv]) { o.os = NT[ntv][0]; o.osEol = NT[ntv][1] ? dateMs(NT[ntv][1]) : 0; } else { o.os = 'Windows NT ' + ntv; o.stat.impossible = 'Windows NT ' + ntv + ' does not exist'; }
    } else if (RX.winPhone.test(dec)) { o.os = 'Windows Phone'; o.osEol = dateMs('2019-12-10'); }
    else if (RX.win9x.test(dec)) { o.os = 'Windows 9x / ME'; o.osEol = dateMs('2006-07-11'); }
    else if ((m = RX.ios.exec(dec))) { o.os = 'iOS ' + m[1]; }
    else if ((m = RX.android.exec(dec))) { o.os = 'Android ' + m[1] + (m[2] !== undefined && m[2] !== '' ? '.' + m[2] : ''); }
    else if (RX.cros.test(dec)) { o.os = 'ChromeOS'; }
    else if ((m = RX.mac.exec(dec))) { o.os = 'macOS ' + m[1] + (m[2] !== undefined && m[2] !== '' ? '.' + m[2] : ''); }
    else if (RX.linux.test(dec)) { o.os = 'Linux'; }
    // browser and engine
    var tri = RX.trident.exec(dec), ie = RX.msie.exec(dec), eh, ch, ff, sa;
    if (RX.office.test(dec)) { o.browser = 'office'; }
    else if ((eh = RX.edgeHtml.exec(dec))) { o.browser = 'edge-legacy'; o.engine = 'edgehtml'; o.major = +eh[1]; } // also sends a Chrome/ token
    else if (tri || ie) {
      ieReal = tri ? +tri[1] + 4 : +ie[1]; msieOnly = !tri;
      o.browser = 'ie'; o.engine = 'ie'; o.major = ieReal;
    }
    else if ((ch = RX.chromium.exec(dec))) {
      o.engine = 'chrome'; o.major = +ch[2]; o.ver = ch[2] + ch[3];
      o.browser = RX.edg.test(dec) ? 'edge' : RX.opr.test(dec) ? 'opera' : RX.samsung.test(dec) ? 'samsung' : RX.yandex.test(dec) ? 'yandex' : ch[1] === 'HeadlessChrome' ? 'headless-chrome' : 'chrome';
      if (ch[1] !== 'Chromium' && !/^\.\d+\.\d+\.\d+$/.test(ch[3])) { o.stat.malformed = ch[1] + '/' + ch[2] + ch[3] + ' is not the four-part version browsers send'; }
    }
    else if ((ff = RX.firefox.exec(dec))) {
      o.browser = 'firefox'; o.major = +ff[2];
      if (ff[1] === 'Firefox' || o.major >= 100) { o.engine = 'firefox'; } // Firefox for iOS used its own numbering before 100
    }
    else if (RX.presto.test(dec)) { o.browser = 'opera-presto'; o.engine = 'presto'; }
    else if ((sa = RX.safari.exec(dec))) {
      if (RX.android.test(dec)) { o.browser = 'android-browser'; } else { o.browser = 'safari'; o.engine = 'safari'; o.major = +sa[1]; }
    }
    if (o.browser) { o.name = NAMES[o.browser] + (o.major >= 0 ? ' ' + o.major : ''); }
    if (o.engine && o.major >= 0) { o.rel = UA.release(o.engine, o.major); }
    if (o.engine) { o.bEol = eolOf(o.engine, o.major); }
    // combinations that never existed
    if (nt >= 0 && !o.stat.impossible) {
      var who = o.name;
      if (o.engine === 'chrome') {
        if (nt < 5.1) { o.stat.impossible = who + ' on ' + o.os + ': Chromium browsers never ran on Windows 2000 or older'; }
        else if (between(nt, 5.1, 6.0) && o.major > 49) { o.stat.impossible = who + ' on ' + o.os + ': version 49 was the last for Windows XP and Vista'; }
        else if (between(nt, 6.1, 6.3) && o.major > 109) { o.stat.impossible = who + ' on ' + o.os + ': version 109 was the last for Windows 7, 8 and 8.1'; }
      } else if (o.engine === 'firefox') {
        if (nt < 5.1 && o.major > 12) { o.stat.impossible = who + ' on ' + o.os + ': Firefox 12 was the last for Windows 2000'; }
        else if (between(nt, 5.1, 6.0) && o.major > 52) { o.stat.impossible = who + ' on ' + o.os + ': Firefox 52 ESR was the last for Windows XP and Vista'; }
        else if (between(nt, 6.1, 6.3) && o.major > 115) { o.stat.impossible = who + ' on ' + o.os + ': Firefox 115 ESR was the last for Windows 7, 8 and 8.1'; }
      } else if (o.engine === 'ie') {
        var maxIe = nt < 5.1 ? 6 : nt < 6 ? 8 : nt < 6.1 ? 9 : 11, minIe = nt >= 6.3 ? 11 : nt >= 6.2 ? 10 : nt >= 6.1 ? 8 : nt >= 6.0 ? 7 : 0;
        if (msieOnly && nt >= 6.1) { o.stat.impossible = 'MSIE ' + ieReal + ' on ' + o.os + ' without a Trident token: Internet Explorer on Windows 7 and later always sends one'; }
        else if (ieReal > maxIe) { o.stat.impossible = who + ' on ' + o.os + ': Internet Explorer ' + maxIe + ' was the last for that Windows version'; }
        else if (ieReal < minIe) { o.stat.impossible = who + ' on ' + o.os + ': that Windows version shipped with Internet Explorer ' + minIe; }
      } else if (o.engine === 'edgehtml' && ntv !== '10.0') { o.stat.impossible = who + ' on ' + o.os + ': EdgeHTML Edge ran only on Windows 10'; }
      else if (o.engine === 'safari' && o.major > 5) { o.stat.impossible = who + ' on ' + o.os + ': Safari for Windows ended with 5.1'; }
    }
    // malformed strings
    var mz = RX.mozilla.exec(dec), bad = [];
    if (RX.ctrl.test(dec)) { bad.push('control characters'); }
    if (!parenOk(dec)) { bad.push('unbalanced brackets'); }
    if (RX.mozTypo.test(dec)) { bad.push('misspelt Mozilla token'); }
    else if (mz && mz[1] !== '4.0' && mz[1] !== '5.0') { bad.push('Mozilla/' + mz[1] + ' token (browsers send 4.0 or 5.0)'); }
    if (RX.mozParen.test(dec)) { bad.push('no space after the Mozilla token'); }
    if (dec.length > 768) { bad.push('unusually long (' + dec.length + ' characters)'); }
    if (o.stat.malformed) { bad.push(o.stat.malformed); }
    if (bad.length) { o.stat.malformed = bad.join('; '); } else { delete o.stat.malformed; }
    if (P.RE.uaInject.test(dec)) { o.stat.inject = 'exploit payload in the user agent'; }
    if (RX.headless.test(dec)) { o.stat.headless = 'headless browser or automation tool'; }
    return o;
  }

  /* ---------- evaluation at a point in time ---------- */
  UA.fmtDate = function (ms) { return U.dayKey(ms); };
  /* Age of the browser version in days at time ts (null when unknown); negative ages (pre-release builds) are reported as 0. */
  UA.ageAt = function (info, ts) {
    if (!info.rel || !ts) { return null; }
    return Math.max(0, Math.floor((ts - info.rel.ms) / DAY));
  };
  /* Flags of a user agent for a request at ts: { age, flags: [names], why: {flag: reason} }. rare is not included
   * (it depends on the corpus): see UA.isRare. */
  UA.at = function (info, ts) {
    var out = { age: null, flags: [], why: {} }, k;
    function add(f, why) { if (!out.why[f]) { out.flags.push(f); out.why[f] = why; } }
    if (info.rel && ts) {
      var raw = Math.floor((ts - info.rel.ms) / DAY), rd = (info.rel.est === 2 ? '~' : '') + UA.fmtDate(info.rel.ms);
      out.age = Math.max(0, raw);
      if (raw < -UA.cfg.futureDays) { add('impossible', info.name + ' was not released until ' + rd + ', ' + U.fmtNum(-raw) + ' days after ' + UA.fmtDate(ts)); }
      else if (raw > UA.cfg.staleDays) { add('stale', info.name + ' was released ' + rd + ', ' + U.fmtNum(raw) + ' days before ' + UA.fmtDate(ts)); }
    }
    if (info.bEol && ts >= info.bEol) { add('eol', info.name + ': support ended ' + UA.fmtDate(info.bEol)); }
    if (info.osEol && ts >= info.osEol) { add('eol-os', info.os + ': support ended ' + UA.fmtDate(info.osEol)); }
    for (k in info.stat) { if (Object.prototype.hasOwnProperty.call(info.stat, k)) { add(k, info.stat[k]); } }
    out.flags.sort(function (a, b) { return UA.FLAGS.indexOf(a) - UA.FLAGS.indexOf(b); });
    return out;
  };
  /* UA.at for a row filter: every date in the tables is a UTC midnight and ages are whole days, so the result is the same
   * for every request of a UTC day; it is kept on the deriver's per-string object for the last day asked. */
  UA.atDay = function (ui, ts) {
    var d = Math.floor(ts / DAY);
    if (ui && ui.atD === d && ui.atG === UA.gen) { return ui.atR; }
    var r = UA.at(UA.of(ui), d * DAY);
    if (ui) { ui.atD = d; ui.atG = UA.gen; ui.atR = r; }
    return r;
  };
  /* rec: an index user-agent record ({ipN, ipOv, pubN}) or a loaded-rows group. Rare: no more than cfg.rareIps clients, at
   * least one of them public (internal-only clients such as health checks are not interesting). A user agent missing from
   * the index was evicted because it was rarely seen, so it counts as rare. */
  UA.isRare = function (rec) { return !rec || (!rec.ipOv && rec.ipN <= UA.cfg.rareIps && rec.pubN > 0); };
  /* The deriver's per-string object (store.uaInfo, ev.ctx.ui) gets its analysis attached once. */
  UA.of = function (ui) { return ui ? (ui.px || (ui.px = UA.info(ui.dec))) : UA.info(''); };
  /* Index keys are the raw logged strings (spaces logged as '+'). */
  UA.decodeKey = function (k) { return k === '-' ? '' : k.replace(/\+/g, ' '); };
}(IISLA));
