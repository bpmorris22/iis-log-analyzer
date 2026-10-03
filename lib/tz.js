/* IIS Log Analyzer - tz.js
 * DST-aware display time zones built from the Windows time zone database
 * (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones, including the per-year
 * "Dynamic DST" rules), read through WMI StdRegProv. Each zone is compiled into a table of
 * UTC transition instants and offsets (1970-2100), so lookups are a binary search and the
 * same table can be handed to the out-of-process scan engine.
 *
 * Zone object: { id, label, kind: 'windows'|'fixed', off(utcMs) -> minutes, localToUtc(localMs),
 *                table: { t: [utcMs...], o: [offsetMinutes...] } }
 * Local time = UTC + off(utc) minutes.
 */
(function (NS) {
  'use strict';
  var U = NS.util, TZ = NS.tz = {};
  var HKLM = 0x80000002, BASE = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones';
  var FROM_YEAR = 1970, TO_YEAR = 2100;
  var reg = null, zoneCache = {}, listCache = null;

  /* ---------- zone objects ---------- */
  function makeZone(id, label, kind, table) {
    var z = { id: id, label: label, kind: kind, table: table }, cs = -Infinity, ce = -Infinity, co = table.o[0];
    var t = table.t, o = table.o, n = t.length;
    z.off = function (ms) {
      if (ms >= cs && ms < ce) { return co; }
      // binary search: last index with t[i] <= ms
      var lo = 0, hi = n - 1, mid;
      if (ms < t[0]) { cs = -Infinity; ce = t[0]; co = o[0]; return co; }
      while (lo < hi) { mid = (lo + hi + 1) >> 1; if (t[mid] <= ms) { lo = mid; } else { hi = mid - 1; } }
      cs = t[lo]; ce = lo + 1 < n ? t[lo + 1] : Infinity; co = o[lo];
      return co;
    };
    /* Local wall-clock ms -> UTC ms. In a DST gap the result is shifted forward; in an overlap the first (DST) instant wins. */
    z.localToUtc = function (local) {
      var u1 = local - z.off(local) * 60000;
      return local - z.off(u1) * 60000;
    };
    z.fixed = table.t.length === 1 ? table.o[0] : null;
    return z;
  }
  TZ.fixed = function (minutes, label) {
    minutes = +minutes || 0;
    return makeZone('fixed:' + minutes, label || U.fmtOffset(minutes), 'fixed', { t: [-8.64e15], o: [minutes] });
  };
  TZ.UTC = TZ.fixed(0, 'UTC');

  /* ---------- registry access (WMI StdRegProv) ---------- */
  function regProv() {
    if (!reg) { reg = new ActiveXObject('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\default').Get('StdRegProv'); }
    return reg;
  }
  function call(method, sub, value) {
    var r = regProv(), inp = r.Methods_.Item(method).InParameters.SpawnInstance_();
    inp.hDefKey = HKLM; inp.sSubKeyName = sub;
    if (value !== undefined) { inp.sValueName = value; }
    return r.ExecMethod_(method, inp);
  }
  function vbArray(v) { return v === null || v === undefined ? [] : new VBArray(v).toArray(); }
  function regString(sub, name) { var o = call('GetStringValue', sub, name); return o.ReturnValue === 0 ? o.sValue : ''; }
  function regBinary(sub, name) { var o = call('GetBinaryValue', sub, name); return o.ReturnValue === 0 ? vbArray(o.uValue) : null; }
  function regDword(sub, name) { var o = call('GetDWORDValue', sub, name); return o.ReturnValue === 0 ? o.uValue : null; }

  /* Parses the 44-byte REG_TZI_FORMAT structure. */
  TZ.parseTzi = function (b) {
    function i32(o) { var v = b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24); return v; }
    function u16(o) { return b[o] | (b[o + 1] << 8); }
    function st(o) { return { year: u16(o), month: u16(o + 2), dow: u16(o + 4), day: u16(o + 6), hour: u16(o + 8), minute: u16(o + 10), second: u16(o + 12), ms: u16(o + 14) }; }
    if (!b || b.length < 44) { return null; }
    return { bias: i32(0), stdBias: i32(4), dltBias: i32(8), std: st(12), dlt: st(28) };
  };

  /* Lists Windows time zones: [{id, label, std, dlt}] sorted by base offset then label. */
  /* The zone list costs about three registry reads per zone (~420 synchronous WMI calls, noticeable when the Case view
   * opens), so it is cached on disk and reused while the set of zone keys is unchanged (one EnumKey call). */
  function listCachePath() { return U.joinPath(U.joinPath(U.env('LOCALAPPDATA') || U.env('TEMP'), 'IISLogAnalyzer'), 'tz-list.json'); }
  TZ.list = function () {
    if (listCache) { return listCache; }
    var out = [], names = vbArray(call('EnumKey', BASE).sNames), i, sub, tzi, key = names.slice(0).sort().join('|'), cached = null;
    try { cached = U.fileExists(listCachePath()) ? U.readJsonAscii(listCachePath()) : null; } catch (eC) { cached = null; }
    if (cached && cached.v === 1 && cached.key === key && cached.zones && cached.zones.length === names.length) { listCache = cached.zones; return listCache; }
    for (i = 0; i < names.length; i++) {
      sub = BASE + '\\' + names[i];
      tzi = TZ.parseTzi(regBinary(sub, 'TZI'));
      out.push({ id: names[i], label: regString(sub, 'Display') || names[i], std: regString(sub, 'Std'), dlt: regString(sub, 'Dlt'), bias: tzi ? tzi.bias : 0, hasDst: !!(tzi && tzi.std.month) });
    }
    out.sort(function (a, b) { return b.bias - a.bias || (a.label < b.label ? -1 : 1); });
    listCache = out;
    try { U.ensureFolder(U.parentOf(listCachePath())); U.writeJsonAscii(listCachePath(), { v: 1, key: key, created: U.nowIso(), zones: out }); } catch (eW) { }
    return out;
  };

  /* Reads one zone's rules: { def: tzi, years: {y: tzi}, first, last } */
  TZ.readRules = function (id) {
    var sub = BASE + '\\' + id, def = TZ.parseTzi(regBinary(sub, 'TZI'));
    if (!def) { throw new Error('Time zone not found in registry: ' + id); }
    var rules = { def: def, years: {}, first: null, last: null }, dyn = sub + '\\Dynamic DST';
    var first = regDword(dyn, 'FirstEntry'), last = regDword(dyn, 'LastEntry'), y, t;
    if (first !== null && last !== null) {
      for (y = first; y <= last; y++) { t = TZ.parseTzi(regBinary(dyn, '' + y)); if (t) { rules.years[y] = t; } }
      rules.first = first; rules.last = last;
    }
    return rules;
  };

  /* ---------- rule compilation ---------- */
  function ruleFor(rules, year) {
    if (rules.first === null) { return rules.def; }
    if (year <= rules.first) { return rules.years[rules.first] || rules.def; }
    if (year >= rules.last) { return rules.years[rules.last] || rules.def; }
    var y = year;
    while (y >= rules.first) { if (rules.years[y]) { return rules.years[y]; } y--; }
    return rules.def;
  }
  /* Local wall-clock instant (as UTC-based ms) of a SYSTEMTIME transition rule in a given year. */
  TZ.transitionLocal = function (st, year) {
    if (!st.month) { return null; }
    var day;
    if (st.year) { day = st.day; } else {
      var firstDow = new Date(Date.UTC(year, st.month - 1, 1)).getUTCDay(), dim = new Date(Date.UTC(year, st.month, 0)).getUTCDate();
      day = 1 + ((st.dow - firstDow + 7) % 7) + (st.day - 1) * 7;
      while (day > dim) { day -= 7; }
    }
    return Date.UTC(year, st.month - 1, day, st.hour, st.minute, st.second, st.ms);
  };
  /* Microsoft encodes "at the start of the year" as the first <weekday of Jan 1> of January at 00:00:00;
   * Win32 (SystemTimeToTzSpecificLocalTimeEx) treats such a transition as exactly Jan 1 00:00 in every year. */
  function isYearStartMarker(st) { return !st.year && st.month === 1 && st.day === 1 && !st.hour && !st.minute && !st.second && !st.ms; }
  /* Compiles rules into a transition table between FROM_YEAR and TO_YEAR, following Win32 semantics:
   * each year's rule takes over at Jan 1 00:00 local time measured with the offset in force just before it. */
  TZ.compile = function (rules) {
    var ev = [], seq = 0, y, r, std, dst, sU, eU, hasDst, b, cur = null;
    function push(t, o) { ev.push([t, o, seq++]); cur = o; }
    for (y = FROM_YEAR; y <= TO_YEAR; y++) {
      r = ruleFor(rules, y);
      std = -(r.bias + r.stdBias); dst = -(r.bias + r.dltBias);
      hasDst = !!(r.std.month && r.dlt.month) && std !== dst;
      if (cur === null) { cur = hasDst && TZ.transitionLocal(r.dlt, y) > TZ.transitionLocal(r.std, y) ? dst : std; }
      b = Date.UTC(y, 0, 1) - cur * 60000;               // year boundary in UTC, using the outgoing offset
      if (!hasDst) { push(b, std); continue; }
      sU = isYearStartMarker(r.dlt) ? b : TZ.transitionLocal(r.dlt, y) - std * 60000;   // DST start: local standard time
      eU = isYearStartMarker(r.std) ? b : TZ.transitionLocal(r.std, y) - dst * 60000;   // DST end: local daylight time
      if (sU < eU) { push(b, std); push(sU, dst); push(eU, std); } else { push(b, dst); push(eU, std); push(sU, dst); }
    }
    ev.sort(function (a, b2) { return a[0] - b2[0] || a[2] - b2[2]; });
    var t = [], o = [], i;
    for (i = 0; i < ev.length; i++) {
      if (o.length && o[o.length - 1] === ev[i][1]) { continue; }
      if (t.length && t[t.length - 1] === ev[i][0]) { o[o.length - 1] = ev[i][1]; continue; }
      t.push(ev[i][0]); o.push(ev[i][1]);
    }
    t[0] = -8.64e15; // first rule extends to the beginning of time
    return { t: t, o: o };
  };
  TZ.windows = function (id) {
    if (zoneCache[id]) { return zoneCache[id]; }
    var rules = TZ.readRules(id), label = regString(BASE + '\\' + id, 'Display') || id;
    var z = makeZone(id, label, 'windows', TZ.compile(rules));
    zoneCache[id] = z;
    return z;
  };
  /* Resolves 'fixed:<minutes>' or a Windows zone id. Falls back to a fixed offset if the registry is unavailable. */
  TZ.byId = function (id, fallbackMinutes, fallbackLabel) {
    if (!id || /^fixed:/i.test(id)) { return TZ.fixed(id ? +id.substr(6) : (fallbackMinutes || 0), fallbackLabel); }
    if (id === 'UTC') { return TZ.UTC; }
    try { return TZ.windows(id); } catch (e) {
      NS.bootWarnings.push('Time zone "' + id + '" unavailable (' + e.message + '); using fixed ' + U.fmtOffset(fallbackMinutes || 0) + '.');
      return TZ.fixed(fallbackMinutes || 0, fallbackLabel);
    }
  };
  /* Zone for a case (backward compatible with fixed-offset cases). */
  TZ.forCase = function (cd, settings) {
    if (cd && cd.displayTzId) { return TZ.byId(cd.displayTzId, cd.displayTzOffsetMinutes, cd.displayTzLabel); }
    if (cd && cd.displayTzOffsetMinutes !== undefined) { return TZ.fixed(cd.displayTzOffsetMinutes, cd.displayTzLabel); }
    return TZ.forSettings(settings);
  };
  TZ.forSettings = function (s) {
    s = s || {};
    return s.displayTzId ? TZ.byId(s.displayTzId, s.displayTzOffsetMinutes, s.displayTzLabel) : TZ.fixed(s.displayTzOffsetMinutes || 0, s.displayTzLabel);
  };
  /* Short label with the offset in effect at a given instant, e.g. "(UTC-08:00) Pacific Time [PDT now UTC-07:00]". */
  TZ.describe = function (z, ms) {
    if (!z) { return ''; }
    if (z.kind === 'fixed') { return z.label; }
    return z.label + ' (DST-aware; ' + U.fmtOffset(z.off(ms === undefined ? Date.now() : ms)) + ' now)';
  };

  /* ---------- self test against an oracle file ----------
   * in: { zones: { id: [[utcMs, offsetMinutes], ...] } } produced by test\tz-oracle.ps1 (.NET TimeZoneInfo).
   * out: { checked, mismatches: [...], zones } */
  TZ.selfTest = function (inPath, outPath) {
    var data = JSON.parse(U.readTextAnsi(inPath)), res = { checked: 0, zones: 0, mismatches: [], started: U.nowIso() }, id, z, arr, i, got;
    for (id in data.zones) {
      res.zones++;
      try { z = TZ.windows(id); } catch (e) { res.mismatches.push({ zone: id, error: e.message }); continue; }
      arr = data.zones[id];
      for (i = 0; i < arr.length; i++) {
        res.checked++;
        got = z.off(arr[i][0]);
        if (got !== arr[i][1] && res.mismatches.length < 500) { res.mismatches.push({ zone: id, utc: U.fmtIso(arr[i][0]), expected: arr[i][1], got: got }); }
      }
    }
    res.finished = U.nowIso();
    U.writeTextUtf8(outPath, JSON.stringify(res, null, 1), false);
    return res;
  };
}(IISLA));
