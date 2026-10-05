/* IIS Log Analyzer - scan.js
 * Scan pass: streams every file once, builds the Index (aggregates, first-seen
 * tables, integrity facts, rule hits) without materializing rows.
 */
(function (NS) {
  'use strict';
  var U = NS.util, IO = NS.io, P = NS.parser, R = NS.rules, S = NS.scan = {};

  S.SCHEMA = 8; // 8: per-user-agent status mix, executable successes, rule-hit rows, public clients and first occurrence; 7: outcome-graded severities, response mix per rule; 4: ASCII-only JSON; 5: windows-1252 + UTF-8 recovery, DST zones; 6: strict dates, resume state, rule-set fingerprint incl. enabled rules
  S.IP_STEM_CAP = 32;   // distinct paths tracked per client (count continues as overflow)
  S.IP_UA_CAP = 8;      // distinct user agents tracked per client
  S.WIN_PURGE_ROWS = 400000; // purge idle per-client windows this often
  S.KEEP_RAW = 200;          // rule-hit pointers that also keep the raw line (the rest keep pointers only)
  S.GROUP_AT = 25;           // per rule, entities beyond this many are folded into one summary finding
  var HOUR = 3600000, DAY = 86400000;

  S.fingerprint = function (files) {
    var parts = [], i;
    for (i = 0; i < files.length; i++) { parts.push(files[i].name.toLowerCase() + '|' + files[i].size + '|' + files[i].mtime); }
    return R.fnv(parts.join('\n')) + '-' + files.length;
  };

  S.newIndex = function (site, files, settings, ruleset) {
    var fl = [], i, f;
    for (i = 0; i < files.length; i++) {
      f = files[i];
      fl.push({ fileId: i, name: f.name, path: f.path, displayPath: f.displayPath, size: f.size, mtime: f.mtime, ctime: f.ctime,
        nameKind: f.nameKind, nameDate: f.nameDate, scanned: false });
    }
    return {
      schemaVersion: S.SCHEMA, toolVersion: NS.VERSION, createdUtc: U.nowIso(), completedUtc: '', site: site.name, sitePath: site.path,
      siteDisplayPath: site.displayPath, siteKind: site.kind, corpusFingerprint: S.fingerprint(files), rulesetHash: ruleset.hash, rulesDisabled: (ruleset.disabledIds || []).slice(),
      rulesetVersion: ruleset.version, settingsUsed: { displayTz: settings.tzZone ? settings.tzZone.id : 'fixed:' + (settings.displayTzOffsetMinutes || 0), businessHours: settings.businessHours, gapHours: 4, testNetsPublic: U.testNetsPublic() },
      partial: true, filesDone: 0, scanMs: 0, partialFile: -1, partialLine: 0,
      files: fl, schemas: [], softwares: U.newMap(),
      totals: { rows: 0, lines: 0, malformed: 0, blocks: 0, nonAscii: 0, decodeErr: 0, firstTs: 0, lastTs: 0, bytes: 0 },
      perDay: U.newMap(), perHour: U.newMap(), ips: U.newMap(), stems: U.newMap(), uas: U.newMap(), users: U.newMap(), statuses: U.newMap(), methods: U.newMap(),
      sports: U.newMap(), exts: U.newMap(), uaFams: U.newMap(), restarts: [], gaps: [], missingFiles: [], lbKeys: U.newMap(), heartbeat: null, ruleHits: U.newMap(), findings: [],
      caps: { ipCap: settings.indexCaps.ips, stemCap: settings.indexCaps.stems, uaCap: settings.indexCaps.uas, ipEvicted: 0, stemEvicted: 0, uaEvicted: 0, lbOv: 0 },
      counts: { ips: 0, stems: 0, uas: 0 },
      hashes: { done: false, tool: '', when: '' }
    };
  };

  /* Rule thresholds used by the streaming pass (shared with the fast engine job). */
  S.scanParams = function (ruleset) {
    var rp = function (id, k, d) { var r = ruleset.byId[id]; return r && r.params && r.params[k] !== undefined ? r.params[k] : d; };
    return {
      s7win: rp('R-SCAN-007', 'windowMinutes', 5) * 60000, a1win: rp('R-AUTH-001', 'windowMinutes', 10) * 60000,
      a2win: rp('R-AUTH-002', 'windowMinutes', 10) * 60000, a2count: rp('R-AUTH-002', 'count', 10),
      a4rows: rp('R-AUTH-004', 'rowsPerDay', 50), s1dayMin: rp('R-SCAN-001', 'dayMin4xx', 100), s1ratio: rp('R-SCAN-001', 'ratio', 0.8),
      gapMs: ((ruleset.byId['R-INF-001'] || {}).params || {}).gapHours * HOUR || 4 * HOUR
    };
  };

  /* ---------- Scanner ---------- */
  S.Scanner = function (opts) {
    this.site = opts.site;
    this.files = opts.site.files;
    this.settings = opts.settings;
    this.ruleset = opts.ruleset;
    this.lists = opts.lists;
    this.manifest = opts.manifest || null;
    this.idx = opts.resumeIndex ? S.nullProto(opts.resumeIndex) : S.newIndex(opts.site, this.files, opts.settings, opts.ruleset);
    this.D = new P.Deriver(opts.lists);
    this.ev = new R.Evaluator(opts.ruleset, this.D);
    this.win = U.newMap();
    this.retention = opts.settings.ruleHitRetention || 50000;
    this.p = S.scanParams(opts.ruleset);
    this.gapMs = this.p.gapMs;
    this.onProgress = opts.onProgress || function () { };
    this.bh = opts.settings.businessHours;
    this.tz = opts.tz || opts.settings.tzZone || opts.settings.displayTzOffsetMinutes || 0;
    // restore user first-seen knowledge when resuming
    for (var u in this.idx.users) { this.ev.users[u] = 1; }
    this.prevTs = 0;
    this.sincePurge = 0;
    this.counts = this.idx.counts;
    // eviction backoff: after a sweep that cannot get below 90% of a cap (protected or frequent entries), the next
    // sweep waits until the table has grown by another 10% of the cap (amortised cost, no sweep per new key)
    this.evictAt = { ips: 0, stems: 0, uas: 0 };
    this.cancelAfterRows = opts.cancelAfterRows || 0; // test hook: cancel at the first chunk boundary after N rows
    // Resuming a cancelled scan: restore the detection state saved at the cancel point (windows, exploit windows,
    // continuity counters) so the result is identical to an uninterrupted scan.
    this.resumeState = opts.resumeIndex && this.idx.resumeState ? this.idx.resumeState : null;
    this.idx.engine = opts.resumeIndex ? (this.idx.engine || 'built-in (JavaScript)') + ' + built-in resume' : 'built-in (JavaScript)';
    this.idx.resumeState = null;
    if (this.resumeState) { this.loadState(this.resumeState); }
  };

  /* Detection state at a cancel point. Format shared with the fast engine (IISScanEngine.cs ResumeStateJson):
   * win rows = [ip, b5, s5[], n5, b10, login, e401, last401, b10b, dDay, dUas[], dUaN, d4, dn, dOff, h, dl, en[[stem, n, q[]]],
   *             rec.off[dDay] before the partial close (null = absent), rec.md4, rec.md4d]. */
  S.Scanner.prototype.saveState = function () {
    var out = { v: 1, prevTs: this.prevTs, lastBlock: this.lastBlock, blockPrevTs: this.blockPrevTs, sincePurge: this.sincePurge,
      evictAt: [this.evictAt.ips, this.evictAt.stems, this.evictAt.uas], win: [], expWin: [] }, k, w, rec, e, s, en;
    function keys(m) { if (!m) { return null; } var a = [], x; for (x in m) { a.push(x); } return a; }
    for (k in this.win) {
      w = this.win[k]; rec = this.idx.ips[k]; en = null;
      if (w.en) { en = []; for (s in w.en) { en.push([s, w.en[s].n, keys(w.en[s].q)]); } }
      out.win.push([k, w.b5, keys(w.s5), w.n5, w.b10, w.login, w.e401, w.last401, w.b10b, w.dDay, keys(w.dUas), w.dUaN, w.d4, w.dn, w.dOff, w.h, w.dl, en,
        rec && w.dDay && rec.off[w.dDay] !== undefined ? rec.off[w.dDay] : null, rec ? rec.md4 : 0, rec ? rec.md4d : '']);
    }
    for (k in this.ev.expWin) { e = this.ev.expWin[k]; out.expWin.push([k, e.ts, keys(e.stems)]); }
    return out;
  };
  S.Scanner.prototype.loadState = function (rs) {
    var i, e, w, rec, k, m, idx = this.idx;
    function setOf(a) { if (!a) { return null; } var o = U.newMap(), j; for (j = 0; j < a.length; j++) { o[a[j]] = 1; } return o; }
    this.win = U.newMap();
    for (i = 0; i < rs.win.length; i++) {
      e = rs.win[i];
      w = { b5: e[1], s5: setOf(e[2]), n5: e[3], b10: e[4], login: e[5], e401: e[6], last401: e[7], b10b: e[8], dDay: e[9], dUas: setOf(e[10]), dUaN: e[11],
        d4: e[12], dn: e[13], dOff: e[14], h: e[15], dl: e[16], en: null };
      if (e[17]) { w.en = U.newMap(); for (k = 0; k < e[17].length; k++) { m = e[17][k]; w.en[m[0]] = { n: m[1], q: setOf(m[2]) }; } }
      this.win[e[0]] = w;
      rec = idx.ips[e[0]];
      if (rec && w.dDay) { // undo the day close applied when the partial index was finished; the day continues now
        if (e[18] === null) { delete rec.off[w.dDay]; } else { rec.off[w.dDay] = e[18]; }
        rec.md4 = e[19]; rec.md4d = e[20];
      }
    }
    this.ev.expWin = U.newMap();
    for (i = 0; i < rs.expWin.length; i++) { e = rs.expWin[i]; this.ev.expWin[e[0]] = { ts: e[1], stems: setOf(e[2]) }; }
    this.prevTs = rs.prevTs; this.sincePurge = rs.sincePurge;
    this.evictAt = { ips: rs.evictAt[0], stems: rs.evictAt[1], uas: rs.evictAt[2] };
  };

  S.Scanner.prototype.run = function (done, token) {
    var self = this, idx = this.idx, files = this.files, fi = idx.filesDone, rd = null, fp = null, frec = null,
      row = P.newRow(), t0 = Date.now(), bytesTotal = 0, bytesDone = 0, rowsAtStart = idx.totals.rows, lastProg = 0, i,
      lastFlush = Date.now();
    for (i = 0; i < files.length; i++) { bytesTotal += files[i].size; if (i < fi) { bytesDone += files[i].size; } }
    var bytesBase = bytesDone;
    if (!this.resumeState && fi > 0 && idx.files[fi - 1] && idx.files[fi - 1].maxTs) { this.prevTs = idx.files[fi - 1].maxTs; }

    function openNext() {
      if (fi >= files.length) { return false; }
      frec = idx.files[fi];
      var resume = idx.partialFile === fi && idx.partialLine > 0;
      self.skip = resume ? idx.partialLine : 0;
      idx.partialFile = -1; idx.partialLine = 0;
      if (!resume) U.extend(frec, { scanned: false, lines: 0, rows: 0, malformed: 0, malformedSamples: [], blocks: [], notW3C: false, tailNoEol: false,
        crlf: 0, lfOnly: 0, nonAscii: 0, decodeErr: 0, backSteps: 0, backSamples: [], firstTs: 0, lastTs: 0, minTs: 0, maxTs: 0,
        s500: [], openError: '' });
      try { rd = new IO.LineReader(files[fi].path, self.settings.chunkChars, files[fi].size, self.settings); } catch (e) {
        frec.openError = e.message; frec.scanned = true; fi++; idx.filesDone = fi; rd = null; return true;
      }
      fp = new P.FileParser(fi);
      if (resume && self.resumeState) { self.lastBlock = self.resumeState.lastBlock; self.blockPrevTs = self.resumeState.blockPrevTs; } else { self.lastBlock = -1; self.blockPrevTs = 0; }
      return true;
    }
    function closeFile() {
      frec.lines = fp.lineNo; frec.blocks = fp.blocks; frec.notW3C = fp.notW3C; frec.tailNoEol = rd.tailNoEol;
      frec.crlf = rd.crlf; frec.lfOnly = rd.lfOnly; frec.scanned = true;
      idx.totals.lines += fp.lineNo; idx.totals.blocks += fp.blocks.length; idx.totals.bytes += files[fi].size;
      self.fileBlocks(fi, fp.blocks);
      bytesDone += files[fi].size;
      fi++; idx.filesDone = fi; rd = null; fp = null;
    }

    function step() {
      if (!rd) {
        if (!openNext()) { return true; }
        if (!rd) { return false; }
      }
      var lines = rd.next(), k, code;
      if (lines === null) { closeFile(); return false; }
      for (k = 0; k < lines.length; k++) {
        code = fp.line(lines[k], row);
        if (self.skip && fp.lineNo <= self.skip) { continue; }
        if (code === 1) { self.row(row, frec); } else if (code === 2) {
          frec.malformed++; idx.totals.malformed++;
          if (frec.malformedSamples.length < 20) { frec.malformedSamples.push({ line: row.lineNo, reason: row.reason2, raw: U.own(row.raw.substr(0, 2000)) }); }
        }
      }
      if (rd.done) { closeFile(); }
      if (self.cancelAfterRows && token && idx.totals.rows >= self.cancelAfterRows) { self.cancelAfterRows = 0; token.cancelled = true; }
      var now = Date.now();
      if (now - lastProg > 250) {
        lastProg = now;
        var el = (now - t0) / 1000, rows = idx.totals.rows - rowsAtStart, bd = bytesDone - bytesBase + (rd ? rd.charsRead : 0);
        self.onProgress({ file: fi, files: files.length, current: files[Math.min(fi, files.length - 1)].name, rows: idx.totals.rows,
          rate: el > 0 ? rows / el : 0, bytesDone: bytesBase + bd, bytesTotal: bytesTotal,
          eta: bd > 0 ? (bytesTotal - bytesBase - bd) * el / bd : 0 });
      }
      if (self.onCheckpoint && now - lastFlush > 300000) { lastFlush = now; self.onCheckpoint(idx); }
      return false;
    }
    IO.runSliced(step, function (err, cancelled) {
      if (rd && fp && cancelled) { idx.partialFile = fi; idx.partialLine = fp.lineNo; }
      if (rd) { rd.close(); }
      idx.scanMs += Date.now() - t0;
      if (err) { done(err, idx); return; }
      if (cancelled) {
        // roll back the partially read file so a resume re-reads it cleanly is not possible for aggregates;
        // we keep counts and mark the index partial at the last fully completed file.
        idx.partial = true; idx.cancelledAt = U.nowIso();
        self.finish(true);
        done(null, idx, true);
        return;
      }
      idx.partial = false; idx.completedUtc = U.nowIso();
      self.finish(false);
      done(null, idx, false);
    }, this.settings.sliceMs || 25, token);
  };

  function inc(map, k, n) { map[k] = (map[k] || 0) + (n || 1); }

  S.Scanner.prototype.fileBlocks = function (fileId, blocks) {
    var idx = this.idx, i, b, sig;
    for (i = 0; i < blocks.length; i++) {
      b = blocks[i];
      sig = b.fields;
      var found = null, j;
      for (j = 0; j < idx.schemas.length; j++) { if (idx.schemas[j].fields === sig) { found = idx.schemas[j]; break; } }
      if (!found) { found = { fields: sig, firstFile: fileId, firstLine: b.line, blocks: 1, assumed: b.assumed }; idx.schemas.push(found); j = idx.schemas.length - 1; } else { found.blocks++; }
      b.schema = j; delete b.fields; delete b.rowsBefore;
      if (b.software) { if (!idx.softwares[b.software]) { idx.softwares[b.software] = { firstFile: fileId, blocks: 0 }; } idx.softwares[b.software].blocks++; }
      if (i > 0) { idx.restarts.push({ fileId: fileId, line: b.line, date: b.date, ts: b.dateTs }); }
    }
  };

  /* Per-row aggregation. r is the reused row object. */
  S.Scanner.prototype.row = function (r, frec) {
    var idx = this.idx, D = this.D, t = r.ts, ev = this.ev;
    var nh = ev.evaluate(r), c = ev.ctx, si = c.si, qi = c.qi, ui = c.ui, cls = c.cls, pub = c.pub, ip = r.eip;
    var st = r.status, scl = st >= 0 ? Math.floor(st / 100) : 0, isPost = r.method === 'POST', lb = cls === 'loopback';
    var tot = idx.totals;
    tot.rows++;
    if (++this.sincePurge >= S.WIN_PURGE_ROWS) { this.sincePurge = 0; this.purgeWindows(t); }
    if (!tot.firstTs || t < tot.firstTs) { tot.firstTs = t; }
    if (t > tot.lastTs) { tot.lastTs = t; }
    if (r.nonAscii) { tot.nonAscii++; frec.nonAscii++; }
    if (qi.decErr || si.decErr) { tot.decodeErr++; frec.decodeErr++; }
    // file facts
    frec.rows++;
    if (!frec.firstTs) { frec.firstTs = t; frec.minTs = t; }
    frec.lastTs = t;
    if (t < frec.minTs) { frec.minTs = t; }
    if (t > frec.maxTs) { frec.maxTs = t; }
    if (r.blockId !== this.lastBlock) { this.lastBlock = r.blockId; this.blockPrevTs = 0; }
    if (this.blockPrevTs && t < this.blockPrevTs) {
      frec.backSteps++;
      if (frec.backSamples.length < 5) { frec.backSamples.push({ line: r.lineNo, ts: t, prev: this.blockPrevTs }); }
    }
    this.blockPrevTs = t;
    if (st === 500 && frec.s500.length < 500) { frec.s500.push(t); }
    // gaps (global, in file order)
    if (this.prevTs && t - this.prevTs >= this.gapMs) {
      idx.gaps.push({ from: this.prevTs, to: t, hours: (t - this.prevTs) / HOUR, fileId: r.fileId, line: r.lineNo });
    }
    if (t > this.prevTs) { this.prevTs = t; }

    // time series
    var dk = r.date.length === 10 ? r.date : U.dayKey(t), hk = dk + 'T' + (r.time.length >= 2 ? r.time.substr(0, 2) : U.p2(new Date(t).getUTCHours()));
    var pd = idx.perDay[dk];
    if (!pd) { pd = idx.perDay[dk] = [0, 0, 0, 0, 0, 0, 0, 0]; }
    pd[0]++; if (scl >= 2 && scl <= 5) { pd[scl - 1]++; } if (pub) { pd[5]++; } if (lb) { pd[6]++; } if (nh) { pd[7]++; }
    var ph = idx.perHour[hk];
    if (!ph) { ph = idx.perHour[hk] = [0, 0, 0, 0, 0]; }
    ph[0]++; if (scl === 5) { ph[1]++; } if (pub) { ph[2]++; } if (lb) { ph[3]++; } if (nh) { ph[4]++; }

    inc(idx.statuses, st + '.' + (r.sub < 0 ? 0 : r.sub));
    inc(idx.methods, r.method);
    inc(idx.sports, r.sip + ':' + (r.port < 0 ? '-' : r.port));
    inc(idx.exts, si.ext || '(none)');
    inc(idx.uaFams, ui.fam);
    if (lb) {
      var lk = si.key + '?' + r.query;
      if (idx.lbKeys[lk] !== undefined || U.countKeys(idx.lbKeys) < 2000) { inc(idx.lbKeys, lk); } else { idx.caps.lbOv++; }
    }

    // ---- IP aggregate ----
    var rec = idx.ips[ip];
    if (!rec) {
      if (this.counts.ips >= idx.caps.ipCap && this.counts.ips >= this.evictAt.ips) { this.evictIps(); }
      rec = idx.ips[ip] = { n: 0, first: t, last: t, cls: cls, s2: 0, s3: 0, s4: 0, s5: 0, m: U.newMap(), st: U.newMap(), stN: 0, stOv: 0, ua: U.newMap(), uaN: 0, uaOv: 0,
        exec: 0, stat: 0, post: 0, d: U.newMap(), dN: 0, dOv: 0, hits: U.newMap(), php: 0, dn: 0, firstExp: 0, ms5: 0, ms5t: 0, mlogin: 0, mlogint: 0,
        m401: 0, m401t: 0, a401ok: 0, muaDay: 0, muaDayD: '', mdl: 0, mdlt: 0, menum: 0, menumS: '', md4: 0, md4d: '', off: U.newMap() };
      this.counts.ips++;
    }
    rec.n++; if (t < rec.first) { rec.first = t; } if (t > rec.last) { rec.last = t; }
    if (scl === 2) { rec.s2++; } else if (scl === 3) { rec.s3++; } else if (scl === 4) { rec.s4++; } else if (scl === 5) { rec.s5++; }
    inc(rec.m, r.method);
    if (rec.st[si.key] !== undefined) { rec.st[si.key]++; } else if (rec.stN < S.IP_STEM_CAP) { rec.st[si.key] = 1; rec.stN++; } else { rec.stOv++; }
    if (rec.ua[r.ua] !== undefined) { rec.ua[r.ua]++; } else if (rec.uaN < S.IP_UA_CAP) { rec.ua[r.ua] = 1; rec.uaN++; } else { rec.uaOv++; }
    if (si.exec) { rec.exec++; } if (si.stat) { rec.stat++; } if (isPost) { rec.post++; }
    if (si.php) { rec.php++; } if (si.dotnet) { rec.dn++; }
    if (rec.d[dk] !== undefined) { rec.d[dk]++; } else if (rec.dN < 400) { rec.d[dk] = 1; rec.dN++; } else { rec.dOv++; }

    // ---- stem aggregate ----
    var s = idx.stems[si.key];
    if (!s) {
      if (this.counts.stems >= idx.caps.stemCap && this.counts.stems >= this.evictAt.stems) { this.evictStems(); }
      s = idx.stems[si.key] = { n: 0, first: t, last: t, fFile: r.fileId, fLine: r.lineNo, fIp: U.own(ip), raw: U.own(r.stem), ips: U.newMap(), ipN: 0, ipOv: 0, pubN: 0,
        post: 0, ok: 0, okPub: 0, s4: 0, s5: 0, sts: U.newMap(), exec: si.exec, upDir: si.upDir };
      this.counts.stems++;
    }
    s.n++; if (t > s.last) { s.last = t; }
    if (t < s.first) { s.first = t; s.fFile = r.fileId; s.fLine = r.lineNo; s.fIp = U.own(ip); }
    if (isPost) { s.post++; }
    if (st === 200) { s.ok++; if (pub) { s.okPub++; } }
    if (scl === 4) { s.s4++; } else if (scl === 5) { s.s5++; }
    inc(s.sts, st);
    if (s.ips[ip] === undefined) {
      if (s.ipN < 20) { s.ips[ip] = 1; s.ipN++; if (pub) { s.pubN++; } } else { s.ipOv = 1; }
    }

    // ---- UA aggregate ----
    var u = idx.uas[r.ua];
    if (!u) {
      if (this.counts.uas >= idx.caps.uaCap && this.counts.uas >= this.evictAt.uas) { this.evictUas(); }
      u = idx.uas[r.ua] = { n: 0, first: t, last: t, fFile: r.fileId, fLine: r.lineNo, fIp: U.own(ip), ips: U.newMap(), ipN: 0, ipOv: 0, pubN: 0, fam: ui.fam,
        s2: 0, s3: 0, s4: 0, s5: 0, post: 0, exec: 0, xok: 0, hits: 0 };
      this.counts.uas++;
    }
    u.n++; if (t > u.last) { u.last = t; } if (t < u.first) { u.first = t; u.fFile = r.fileId; u.fLine = r.lineNo; u.fIp = U.own(ip); }
    if (u.ips[ip] === undefined) { if (u.ipN < 20) { u.ips[ip] = 1; u.ipN++; if (pub) { u.pubN++; } } else { u.ipOv = 1; } }
    if (scl === 2) { u.s2++; } else if (scl === 3) { u.s3++; } else if (scl === 4) { u.s4++; } else if (scl === 5) { u.s5++; }
    if (isPost) { u.post++; }
    if (si.exec) { u.exec++; if (scl === 2 && pub) { u.xok++; } } // xok: public 2xx responses from executable handlers
    if (nh) { u.hits++; }

    // ---- users ----
    if (r.user !== '-' && r.user !== '') {
      var us = idx.users[r.user];
      if (!us) { us = idx.users[r.user] = { n: 0, first: t, last: t, fFile: r.fileId, fLine: r.lineNo, ips: U.newMap(), ipN: 0, pub: 0 }; }
      us.n++; if (t > us.last) { us.last = t; }
      if (us.ips[ip] === undefined && us.ipN < 50) { us.ips[ip] = 1; us.ipN++; }
      if (pub) { us.pub++; }
    }

    // ---- rule hits ----
    if (nh) {
      var j, id, h;
      for (j = 0; j < nh; j++) {
        id = ev.hits[j];
        h = idx.ruleHits[id];
        if (!h) { h = idx.ruleHits[id] = { n: 0, sev: ev.hitSev[j], first: t, last: t, kept: [], ips: U.newMap(), ipN: 0, stems: U.newMap(), stN: 0, sx: [0, 0, 0, 0, 0] }; }
        h.n++; if (t > h.last) { h.last = t; } if (t < h.first) { h.first = t; }
        h.sev = R.maxSev(h.sev, ev.hitSev[j]);
        h.sx[scl >= 2 && scl <= 5 ? scl - 2 : 4]++; // response mix: 2xx, 3xx, 4xx, 5xx, other
        if (h.kept.length < this.retention) { h.kept.push([r.fileId, r.lineNo, t, U.own(ip), h.kept.length < S.KEEP_RAW ? U.own(r.raw.length > 1500 ? r.raw.substr(0, 1500) : r.raw) : '']); }
        if (h.ips[ip] !== undefined) { h.ips[ip]++; } else if (h.ipN < 1000) { h.ips[ip] = 1; h.ipN++; }
        if (h.stems[si.key] !== undefined) { h.stems[si.key]++; } else if (h.stN < 1000) { h.stems[si.key] = 1; h.stN++; }
        inc(rec.hits, id);
        if (R.EXPLOIT_RULES[id] === 1 && !rec.firstExp) { rec.firstExp = t; }
      }
    }

    // ---- per-client windows ----
    var w = this.win[ip];
    if (!w) { w = this.win[ip] = { b5: -1, s5: null, n5: 0, b10: -1, login: 0, e401: 0, last401: 0, b10b: -1, dDay: '', dUas: null, dUaN: 0, d4: 0, dn: 0, dOff: 0, h: -1, dl: 0, en: null }; }
    var p = this.p, b;
    b = Math.floor(t / p.s7win);
    if (b !== w.b5) { w.b5 = b; w.s5 = U.newMap(); w.n5 = 0; }
    if (w.s5[si.key] === undefined) { w.s5[si.key] = 1; w.n5++; if (w.n5 > rec.ms5) { rec.ms5 = w.n5; rec.ms5t = t; } }
    b = Math.floor(t / p.a1win);
    if (b !== w.b10) { w.b10 = b; w.login = 0; }
    if (isPost && si.loginEp) { w.login++; if (w.login > rec.mlogin) { rec.mlogin = w.login; rec.mlogint = t; } }
    b = Math.floor(t / p.a2win);
    if (b !== w.b10b) { w.b10b = b; w.e401 = 0; }
    if (st === 401) { w.e401++; w.last401 = t; if (w.e401 > rec.m401) { rec.m401 = w.e401; rec.m401t = t; } } else if ((st === 200 || st === 302) && w.last401 && t - w.last401 <= 300000 && rec.m401 >= p.a2count) { rec.a401ok = 1; }
    if (dk !== w.dDay) { this.closeDay(rec, w); w.dDay = U.own(dk); w.dUas = U.newMap(); w.dUaN = 0; w.d4 = 0; w.dn = 0; w.dOff = 0; }
    w.dn++; if (scl === 4) { w.d4++; }
    if (pub && w.dUas[r.ua] === undefined) { w.dUas[r.ua] = 1; w.dUaN++; if (w.dUaN > rec.muaDay) { rec.muaDay = w.dUaN; rec.muaDayD = U.own(dk); } }
    if ((cls === 'rfc1918' || cls === 'internal') && si.exec && !U.isBusinessTime(t, this.bh, this.tz)) { w.dOff++; }
    if (pub && si.dlEp) {
      b = Math.floor(t / HOUR);
      if (b !== w.h) { w.h = b; w.dl = 0; w.en = U.newMap(); }
      w.dl++; if (w.dl > rec.mdl) { rec.mdl = w.dl; rec.mdlt = t; }
      var e = w.en[si.key];
      if (!e) { e = w.en[si.key] = { n: 0, q: U.newMap() }; }
      if (e.n < 1000 && e.q[r.query] === undefined) { e.q[r.query] = 1; e.n++; if (e.n > rec.menum) { rec.menum = e.n; rec.menumS = U.own(si.key); } }
    }
  };
  S.Scanner.prototype.closeDay = function (rec, w) {
    if (!w.dDay) { return; }
    if (w.dOff >= this.p.a4rows) { rec.off[w.dDay] = w.dOff; }
    if (w.d4 >= this.p.s1dayMin && w.d4 / w.dn >= this.p.s1ratio && w.d4 > rec.md4) { rec.md4 = w.d4; rec.md4d = w.dDay; }
  };

  /* Closes and drops per-client window state for clients idle for more than a day (bounded memory). */
  S.Scanner.prototype.purgeWindows = function (now) {
    var k, w, rec, cut = now - DAY;
    for (k in this.win) {
      w = this.win[k]; rec = this.idx.ips[k];
      if (!rec) { delete this.win[k]; continue; }
      if (rec.last < cut) { this.closeDay(rec, w); delete this.win[k]; }
    }
  };

  /* ---------- cardinality control ---------- */
  S.Scanner.prototype.evictIps = function () {
    var ips = this.idx.ips, k, removed = 0, thr = 1;
    while (this.counts.ips >= this.idx.caps.ipCap * 0.9 && thr < 1000) {
      for (k in ips) {
        var r = ips[k];
        if (r.n <= thr && !U.countKeys(r.hits)) { delete ips[k]; delete this.win[k]; this.counts.ips--; removed++; }
      }
      thr *= 2;
    }
    this.idx.caps.ipEvicted += removed;
    if (this.counts.ips >= this.idx.caps.ipCap * 0.9) { this.evictAt.ips = this.counts.ips + Math.ceil(this.idx.caps.ipCap * 0.1); }
  };
  S.Scanner.prototype.evictStems = function () {
    var st = this.idx.stems, k, removed = 0, thr = 1;
    while (this.counts.stems >= this.idx.caps.stemCap * 0.9 && thr < 1000) {
      for (k in st) { if (st[k].n <= thr && (!st[k].exec || st[k].ok === 0)) { delete st[k]; this.counts.stems--; removed++; } }
      thr *= 2;
    }
    this.idx.caps.stemEvicted += removed;
    if (this.counts.stems >= this.idx.caps.stemCap * 0.9) { this.evictAt.stems = this.counts.stems + Math.ceil(this.idx.caps.stemCap * 0.1); }
  };
  S.Scanner.prototype.evictUas = function () {
    var ua = this.idx.uas, k, removed = 0, thr = 1;
    while (this.counts.uas >= this.idx.caps.uaCap * 0.9 && thr < 1000) {
      for (k in ua) { if (ua[k].n <= thr && !ua[k].hits) { delete ua[k]; this.counts.uas--; removed++; } } // user agents with rule hits are kept
      thr *= 2;
    }
    this.idx.caps.uaEvicted += removed;
    if (this.counts.uas >= this.idx.caps.uaCap * 0.9) { this.evictAt.uas = this.counts.uas + Math.ceil(this.idx.caps.uaCap * 0.1); }
  };

  /* ---------- post-scan ---------- */
  S.Scanner.prototype.finish = function (partial) {
    var idx = this.idx, k;
    idx.resumeState = partial ? this.saveState() : null; // captured before the windows are closed below
    for (k in this.win) { if (idx.ips[k]) { this.closeDay(idx.ips[k], this.win[k]); } }
    this.win = U.newMap();
    S.finishIndex(idx, this.ruleset, this.settings, partial);
  };
  /* Post-processing shared by the in-HTA scanner and the out-of-process engine. */
  S.finishIndex = function (idx, ruleset, settings, partial) {
    S.learnHeartbeat(idx);
    S.missingFiles(idx);
    idx.findings = S.buildFindings(idx, ruleset, settings);
    idx.partial = !!partial;
  };
  /* Converts a JSON-loaded index to null-prototype maps so attacker-controlled keys such as
   * "constructor" or "__proto__" behave like any other key when scanning resumes. */
  S.nullProto = function (idx) {
    function np(o) { var m = U.newMap(), k; for (k in o) { if (Object.prototype.hasOwnProperty.call(o, k)) { m[k] = o[k]; } } return m; }
    var tops = ['softwares', 'perDay', 'perHour', 'ips', 'stems', 'uas', 'users', 'statuses', 'methods', 'sports', 'exts', 'uaFams', 'lbKeys', 'ruleHits'], i, k, r;
    for (i = 0; i < tops.length; i++) { idx[tops[i]] = np(idx[tops[i]] || {}); }
    for (k in idx.ips) { r = idx.ips[k]; r.m = np(r.m); r.st = np(r.st); r.ua = np(r.ua); r.d = np(r.d); r.hits = np(r.hits); r.off = np(r.off); }
    for (k in idx.stems) { r = idx.stems[k]; r.ips = np(r.ips); r.sts = np(r.sts); }
    for (k in idx.uas) { idx.uas[k].ips = np(idx.uas[k].ips); }
    for (k in idx.users) { idx.users[k].ips = np(idx.users[k].ips); }
    for (k in idx.ruleHits) { r = idx.ruleHits[k]; r.ips = np(r.ips); r.stems = np(r.stems); }
    return idx;
  };

  S.learnHeartbeat = function (idx) {
    var best = '', bn = 0, k, days = 0;
    for (k in idx.lbKeys) { if (idx.lbKeys[k] > bn) { bn = idx.lbKeys[k]; best = k; } }
    for (k in idx.perDay) { if (idx.perDay[k][6] > 0) { days++; } }
    if (best && days && bn / days >= 100) {
      var q = best.indexOf('?');
      idx.heartbeat = { key: best, stem: best.substr(0, q), query: best.substr(q + 1), total: bn, perDay: Math.round(bn / days), days: days };
    } else { idx.heartbeat = null; }
  };

  S.missingFiles = function (idx) {
    var dates = {}, i, f, min = null, max = null;
    idx.missingFiles = [];
    for (i = 0; i < idx.files.length; i++) {
      f = idx.files[i];
      if (f.nameKind !== 'daily' || !f.nameDate) { continue; }
      dates[f.nameDate] = 1;
      if (!min || f.nameDate < min) { min = f.nameDate; }
      if (!max || f.nameDate > max) { max = f.nameDate; }
    }
    if (!min) { return; }
    var t = U.dayKeyToMs(min), end = U.dayKeyToMs(max), dk;
    while (t <= end) { dk = U.dayKey(t); if (!dates[dk]) { idx.missingFiles.push(dk); } t += DAY; }
  };

  function topKeys(map, n) { return U.sortedKeys(map, function (v) { return v; }, n); }

  /* Builds all findings from the index. Safe to call again after rule changes (aggregate rules only need the index). */
  S.buildFindings = function (idx, rs, settings) {
    var out = [], rule, f, k, i, rid;
    idx.findingsRulesetHash = rs.hash; // which rule set (text + enabled rules) these findings reflect
    function en(id) { var r = rs.byId[id]; return r && r.enabled ? r : null; }
    function pr(id, key, d) { var r = rs.byId[id]; return r && r.params && r.params[key] !== undefined ? r.params[key] : d; }
    function ipExamples(id, ip) {
      var h = idx.ruleHits[id], ex = [], j;
      if (!h) { return ex; }
      for (j = 0; j < h.kept.length && ex.length < 20; j++) { if (h.kept[j][3] === ip) { ex.push(h.kept[j]); } }
      return ex;
    }
    // --- row rule summaries ---
    for (rid in idx.ruleHits) {
      rule = rs.byId[rid];
      if (!rule || !rule.enabled) { continue; }
      var h = idx.ruleHits[rid];
      f = R.newFinding(rule, 'rows', rid, h.sev);
      f.count = h.n; f.first = h.first; f.last = h.last; f.ips = topKeys(h.ips, 25); f.stems = topKeys(h.stems, 25);
      f.examples = h.kept.slice(0, 20); f.kept = h.kept.length;
      f.detail = U.fmtNum(h.n) + ' matching rows from ' + (h.ipN >= 1000 ? '1000+' : h.ipN) + ' client(s); ' + (h.stN >= 1000 ? '1000+' : h.stN) + ' distinct path(s).';
      var sx = h.sx || [0, 0, 0, 0, 0], mix = [], SXL = ['2xx', '3xx', '4xx', '5xx', 'other'], q;
      f.statusMix = {}; for (q = 0; q < 5; q++) { f.statusMix[SXL[q]] = sx[q]; if (sx[q]) { mix.push(U.fmtNum(sx[q]) + ' ' + SXL[q]); } }
      if (mix.length) { f.detail += ' Responses: ' + mix.join(', ') + '.'; }
      if (rule.params && rule.params.gradeByStatus === true && h.n && !sx[0] && !sx[3]) { f.detail += ' No request succeeded or caused a server error (no 2xx or 5xx), so the severity is lowered.'; }
      out.push(f);
    }
    // --- per-IP escalations of row rules ---
    var esc = [['R-SCAN-002', 'perIpEscalate', 20, 'medium'], ['R-SCAN-005', 'perIpEscalate', 10, 'medium'], ['R-EXF-003', null, 0, 'medium']];
    for (k in idx.ips) {
      var ip = idx.ips[k], pub = ip.cls === 'public';
      for (i = 0; i < esc.length; i++) {
        rule = en(esc[i][0]);
        if (!rule) { continue; }
        if (esc[i][0] === 'R-EXF-003') {
          var thr3 = pr('R-EXF-003', 'perHourEscalate', 50);
          if (ip.mdl >= thr3) { f = R.newFinding(rule, 'ip', k, 'medium'); f.count = ip.mdl; f.first = ip.mdlt; f.last = ip.mdlt; f.ips = [k]; f.examples = ipExamples(rule.id, k); f.detail = 'Peak ' + ip.mdl + ' download/attachment requests in one hour.'; out.push(f); }
          continue;
        }
        var thr = pr(esc[i][0], esc[i][1], esc[i][2]);
        if ((ip.hits[esc[i][0]] || 0) >= thr) {
          f = R.newFinding(rule, 'ip', k, esc[i][3]); f.count = ip.hits[esc[i][0]]; f.first = ip.first; f.last = ip.last; f.ips = [k];
          f.examples = ipExamples(rule.id, k); f.detail = U.fmtNum(ip.hits[esc[i][0]]) + ' hits from this client (threshold ' + thr + ').'; out.push(f);
        }
      }
      // R-SCAN-001
      if ((rule = en('R-SCAN-001')) && pub) {
        var min4 = pr('R-SCAN-001', 'min4xx', 100), ratio = pr('R-SCAN-001', 'ratio', 0.8);
        if ((ip.s4 >= min4 && ip.s4 / ip.n >= ratio) || ip.md4 > 0) {
          f = R.newFinding(rule, 'ip', k); f.count = ip.s4; f.first = ip.first; f.last = ip.last; f.ips = [k]; f.stems = topKeys(ip.st, 15);
          f.detail = U.fmtNum(ip.s4) + ' of ' + U.fmtNum(ip.n) + ' responses were 4xx (' + U.pct(ip.s4, ip.n) + ')' + (ip.md4 ? '; peak day ' + ip.md4d + ' with ' + U.fmtNum(ip.md4) + ' 4xx' : '') + '.';
          out.push(f);
        }
      }
      if ((rule = en('R-SCAN-007')) && !U.isInternalClass(ip.cls) && ip.ms5 >= pr('R-SCAN-007', 'distinctStems', 50)) {
        f = R.newFinding(rule, 'ip', k); f.count = ip.ms5; f.first = ip.ms5t; f.last = ip.ms5t; f.ips = [k]; f.stems = topKeys(ip.st, 15);
        f.detail = ip.ms5 + ' distinct paths within one ' + pr('R-SCAN-007', 'windowMinutes', 5) + '-minute window.'; out.push(f);
      }
      if ((rule = en('R-SCAN-009')) && pub && ip.n >= pr('R-SCAN-009', 'minRows', 20) && ip.php > 0 && ip.dn === 0) {
        f = R.newFinding(rule, 'ip', k); f.count = ip.n; f.first = ip.first; f.last = ip.last; f.ips = [k]; f.stems = topKeys(ip.st, 10);
        f.detail = ip.php + ' PHP/CGI requests, no .NET handler requests.'; out.push(f);
      }
      if ((rule = en('R-WS-006')) && pub && ip.n >= pr('R-WS-006', 'minRows', 20) && ip.stat === 0 && ip.exec / ip.n >= pr('R-WS-006', 'execRatio', 0.9) &&
          ip.s2 >= pr('R-WS-006', 'min2xx', 5) && ip.s4 / ip.n <= pr('R-WS-006', 'max4xxRatio', 0.5)) {
        f = R.newFinding(rule, 'ip', k); f.count = ip.n; f.first = ip.first; f.last = ip.last; f.ips = [k]; f.stems = topKeys(ip.st, 15);
        f.detail = U.pct(ip.exec, ip.n) + ' executable handlers, 0 static assets, ' + U.fmtNum(ip.post) + ' POST, ' + U.fmtNum(ip.s2) + ' 2xx, ' + U.pct(ip.s4, ip.n) + ' 4xx.'; out.push(f);
      }
      if ((rule = en('R-AUTH-001')) && ip.mlogin >= pr('R-AUTH-001', 'posts', 20)) {
        f = R.newFinding(rule, 'ip', k); f.count = ip.mlogin; f.first = ip.mlogint; f.last = ip.mlogint; f.ips = [k];
        f.detail = 'Peak ' + ip.mlogin + ' login POSTs in one window.'; out.push(f);
      }
      if ((rule = en('R-AUTH-002')) && ip.m401 >= pr('R-AUTH-002', 'count', 10)) {
        f = R.newFinding(rule, 'ip', k, ip.a401ok ? 'high' : null); f.count = ip.m401; f.first = ip.m401t; f.last = ip.m401t; f.ips = [k];
        f.detail = 'Peak ' + ip.m401 + ' 401 responses in one window' + (ip.a401ok ? '; a 200/302 followed within 5 minutes (possible success).' : '.'); out.push(f);
      }
      if ((rule = en('R-AUTH-004'))) {
        var dcount = 0, dsum = 0, firstD = '', lastD = '';
        for (var dd in ip.off) { dcount++; dsum += ip.off[dd]; if (!firstD || dd < firstD) { firstD = dd; } if (!lastD || dd > lastD) { lastD = dd; } }
        if (dcount) {
          f = R.newFinding(rule, 'ip', k); f.count = dsum; f.first = U.dayKeyToMs(firstD); f.last = U.dayKeyToMs(lastD); f.ips = [k];
          f.detail = dcount + ' day(s) with \u2265' + pr('R-AUTH-004', 'rowsPerDay', 50) + ' off-hours executable requests; ' + U.fmtNum(dsum) + ' rows in total.'; f.days = ip.off; out.push(f);
        }
      }
      if ((rule = en('R-AUTH-005')) && pub && ip.muaDay >= pr('R-AUTH-005', 'uasPerDay', 5)) {
        f = R.newFinding(rule, 'ip', k); f.count = ip.muaDay; f.first = U.dayKeyToMs(ip.muaDayD); f.last = f.first; f.ips = [k];
        f.detail = ip.muaDay + ' distinct user agents on ' + ip.muaDayD + '.'; out.push(f);
      }
      if ((rule = en('R-EXF-004')) && ip.menum >= pr('R-EXF-004', 'distinctQueries', 200)) {
        f = R.newFinding(rule, 'ip', k); f.count = ip.menum; f.first = ip.first; f.last = ip.last; f.ips = [k]; f.stems = [ip.menumS];
        f.detail = ip.menum + ' distinct query strings against ' + ip.menumS + ' within one hour.'; out.push(f);
      }
    }
    // --- stem rules ---
    var corpusStart = idx.totals.firstTs, base = pr('R-WS-001', 'baselineDays', 30) * DAY, maxIps1 = pr('R-WS-001', 'maxDistinctIps', 10);
    for (k in idx.stems) {
      var s = idx.stems[k];
      if (!s.exec) { continue; }
      var ipArr = [];
      for (var ii in s.ips) { ipArr.push(ii); }
      if ((rule = en('R-WS-001')) && s.okPub > 0 && s.first - corpusStart >= base && !s.ipOv && s.ipN <= maxIps1) {
        f = R.newFinding(rule, 'stem', k); f.count = s.n; f.first = s.first; f.last = s.last; f.ips = ipArr; f.stems = [s.raw];
        f.detail = 'First seen ' + U.fmtTs(s.first) + ' UTC (' + Math.round((s.first - corpusStart) / DAY) + ' days after corpus start) from ' + s.fIp + '; ' + s.okPub + ' public 200 responses, ' + s.ipN + ' distinct client(s).';
        f.firstRef = [s.fFile, s.fLine]; out.push(f);
      }
      if ((rule = en('R-WS-002')) && s.upDir && s.okPub > 0) {
        f = R.newFinding(rule, 'stem', k); f.count = s.n; f.first = s.first; f.last = s.last; f.ips = ipArr; f.stems = [s.raw];
        f.detail = s.okPub + ' public 200 responses; ' + s.ipN + (s.ipOv ? '+' : '') + ' client(s).'; f.firstRef = [s.fFile, s.fLine]; out.push(f);
      }
      if ((rule = en('R-WS-003')) && !s.ipOv && s.ipN > 0 && s.ipN <= pr('R-WS-003', 'maxIps', 2) && s.pubN === s.ipN && s.n >= pr('R-WS-003', 'minRows', 5) &&
          s.post / s.n >= pr('R-WS-003', 'postRatio', 0.5) && s.ok / s.n >= pr('R-WS-003', 'okRatio', 0.8)) {
        f = R.newFinding(rule, 'stem', k); f.count = s.n; f.first = s.first; f.last = s.last; f.ips = ipArr; f.stems = [s.raw];
        f.detail = s.n + ' requests, ' + U.pct(s.post, s.n) + ' POST, ' + U.pct(s.ok, s.n) + ' status 200, from ' + ipArr.join(', ') + '.'; f.firstRef = [s.fFile, s.fLine]; out.push(f);
      }
      if ((rule = en('R-WS-007')) && s.okPub > 0 && idx.ips[s.fIp] && idx.ips[s.fIp].firstExp && idx.ips[s.fIp].firstExp < s.first && idx.ips[s.fIp].cls === 'public') {
        f = R.newFinding(rule, 'stem', k); f.count = s.n; f.first = s.first; f.last = s.last; f.ips = [s.fIp]; f.stems = [s.raw];
        f.detail = s.fIp + ' triggered an exploitation rule at ' + U.fmtTs(idx.ips[s.fIp].firstExp) + ' UTC, then first requested this path at ' + U.fmtTs(s.first) + ' UTC.';
        f.firstRef = [s.fFile, s.fLine]; out.push(f);
      }
    }
    // --- user-agent rules (classified by lib/useragent.js from the string and the time it was first seen) ---
    S.uaFindings(idx, out, en, pr);
    // --- integrity ---
    S.integrityFindings(idx, rs, out, en, pr);
    return R.sortFindings(S.groupFindings(out, rs));
  };

  /* R-UA-001 (outdated browser reaching executable handlers) and R-UA-002 (spoofed, malformed or automation user agent). */
  S.uaFindings = function (idx, out, en, pr) {
    var UAx = NS.useragent, r1 = en('R-UA-001'), r2 = en('R-UA-002'), k, f;
    if (!UAx || (!r1 && !r2)) { return; }
    var minAge = pr('R-UA-001', 'minAgeDays', 730), inclEol = pr('R-UA-001', 'includeEol', true) !== false, minOk = pr('R-UA-001', 'minExecOk', 1), maxIps = pr('R-UA-001', 'maxIps', 20);
    var want = {}, esc2 = pr('R-UA-002', 'escalateOnExecOk', true) !== false;
    pr('R-UA-002', 'flags', ['impossible', 'malformed', 'headless']).forEach(function (x) { want[x] = 1; });
    for (k in idx.uas) {
      var u = idx.uas[k], dec = UAx.decodeKey(k), inf = UAx.info(dec);
      if (!dec) { continue; }
      var at = UAx.at(inf, u.first), ips = [], x, clients = u.ipN + (u.ipOv ? '+' : '') + ' client(s)';
      for (x in u.ips) { ips.push(x); }
      if (r1 && inf.engine && (u.xok || 0) >= minOk && !u.ipOv && u.ipN <= maxIps && ((at.age !== null && at.age >= minAge) || (inclEol && at.why.eol))) {
        f = R.newFinding(r1, 'ua', dec); f.count = u.n; f.first = u.first; f.last = u.last; f.ips = ips; f.firstRef = [u.fFile, u.fLine];
        f.detail = (at.age !== null ? inf.name + ' was released ' + (inf.rel.est === 2 ? '~' : '') + UAx.fmtDate(inf.rel.ms) + ', ' + U.fmtNum(at.age) + ' days before it was first seen' : inf.name) +
          (at.why.eol ? '; ' + at.why.eol : '') + (at.why['eol-os'] ? '; ' + at.why['eol-os'] : '') + '. ' + U.fmtNum(u.xok) + ' public 2xx responses from executable handlers; ' + clients + ', ' + U.fmtNum(u.n) + ' requests.';
        out.push(f);
      }
      if (r2 && u.pubN > 0) {
        var hit = at.flags.filter(function (fl) { return want[fl] === 1; });
        if (hit.length) {
          f = R.newFinding(r2, 'ua', dec, esc2 && u.xok > 0 ? 'medium' : null); f.count = u.n; f.first = u.first; f.last = u.last; f.ips = ips; f.firstRef = [u.fFile, u.fLine];
          f.detail = hit.map(function (fl) { return fl + ': ' + at.why[fl]; }).join('; ') + '. ' + clients + ' (' + u.pubN + ' public), ' + U.fmtNum(u.n) + ' requests, ' +
            U.fmtNum(u.xok) + ' public 2xx responses from executable handlers.';
          out.push(f);
        }
      }
    }
  };

  /* Keeps the S.GROUP_AT strongest findings per rule (by severity, then count) and folds the rest into one summary finding. */
  S.groupFindings = function (list, rs) {
    var by = {}, order = [], out = [], i, f, k;
    for (i = 0; i < list.length; i++) { f = list[i]; if (f.entity === 'rows' || f.entity === 'corpus') { out.push(f); continue; } if (!by[f.ruleId]) { by[f.ruleId] = []; order.push(f.ruleId); } by[f.ruleId].push(f); }
    for (k = 0; k < order.length; k++) {
      var arr = by[order[k]];
      if (arr.length <= S.GROUP_AT) { out = out.concat(arr); continue; }
      arr.sort(function (a, b) { return (R.SEV[b.severity] || 0) - (R.SEV[a.severity] || 0) || b.count - a.count; });
      out = out.concat(arr.slice(0, S.GROUP_AT));
      var rest = arr.slice(S.GROUP_AT), rule = rs.byId[order[k]], sm = R.newFinding(rule, 'summary', rest.length + ' more ' + rest[0].entity + (rest.length > 1 ? 's' : ''), rule.severity), ips = {}, stems = {}, keys = [], j, n = 0;
      sm.first = rest[0].first; sm.last = rest[0].last;
      for (j = 0; j < rest.length; j++) {
        var r = rest[j]; n += r.count || 0;
        if (r.first && (!sm.first || r.first < sm.first)) { sm.first = r.first; } if (r.last > sm.last) { sm.last = r.last; }
        (r.ips || []).forEach(function (x) { ips[x] = (ips[x] || 0) + 1; }); (r.stems || []).forEach(function (x) { stems[x] = (stems[x] || 0) + 1; });
        if (keys.length < 2000) { keys.push(r.key); }
      }
      sm.count = n; sm.ips = Object.keys(ips).slice(0, 2000); sm.stems = Object.keys(stems).slice(0, 200); sm.members = keys; sm.grouped = rest.length;
      sm.detail = rest.length + ' further ' + rest[0].entity + ' entities matched this rule (the ' + S.GROUP_AT + ' strongest are listed as separate findings). First keys: ' + keys.slice(0, 15).join(', ') + (keys.length > 15 ? ' ...' : '');
      out.push(sm);
    }
    return out;
  };

  S.integrityFindings = function (idx, rs, out, en, pr) {
    var rule, f, i, j, fr;
    if ((rule = en('R-INF-001'))) {
      var gh = pr('R-INF-001', 'gapHours', 4);
      for (i = 0; i < idx.gaps.length; i++) {
        var g = idx.gaps[i];
        if (g.hours < gh) { continue; }
        f = R.newFinding(rule, 'gap', U.fmtIso(g.from)); f.count = 1; f.first = g.from; f.last = g.to;
        f.detail = 'No rows for ' + g.hours.toFixed(1) + ' h between ' + U.fmtTs(g.from) + ' and ' + U.fmtTs(g.to) + ' UTC (resumes in ' + (idx.files[g.fileId] || {}).name + ' line ' + g.line + ').';
        f.fileRefs = [[g.fileId, g.line]]; out.push(f);
      }
      if (idx.missingFiles.length) {
        f = R.newFinding(rule, 'corpus', 'missing-files'); f.count = idx.missingFiles.length;
        f.first = U.dayKeyToMs(idx.missingFiles[0]); f.last = U.dayKeyToMs(idx.missingFiles[idx.missingFiles.length - 1]);
        f.detail = idx.missingFiles.length + ' daily file(s) missing inside the corpus span: ' + idx.missingFiles.slice(0, 30).join(', ') + (idx.missingFiles.length > 30 ? ' ...' : '');
        out.push(f);
      }
    }
    var tol = pr('R-INF-003', 'toleranceHours', 26) * HOUR, blocksThr = pr('R-INF-002', 'blocksPerFile', 3), ewin = pr('R-INF-002', 'errorWindowMinutes', 5) * 60000;
    // Restarts are routine on some servers: only flag files well above this corpus's own median.
    var bcounts = []; for (i = 0; i < idx.files.length; i++) { if (idx.files[i].blocks && idx.files[i].blocks.length) { bcounts.push(idx.files[i].blocks.length); } }
    var medBlocks = U.median(bcounts); blocksThr = Math.max(blocksThr, Math.ceil(medBlocks * pr('R-INF-002', 'medianFactor', 3)));
    var sizesByDate = {};
    for (i = 0; i < idx.files.length; i++) { if (idx.files[i].nameDate && idx.files[i].nameKind === 'daily') { sizesByDate[idx.files[i].nameDate] = idx.files[i].size; } }
    var lastScanned = -1;
    for (i = 0; i < idx.files.length; i++) { if (idx.files[i].scanned) { lastScanned = i; } }
    for (i = 0; i < idx.files.length; i++) {
      fr = idx.files[i];
      if (!fr.scanned) { continue; }
      var near = 0;
      if (fr.blocks && fr.s500 && fr.s500.length) {
        for (j = 1; j < fr.blocks.length; j++) {
          var bt = fr.blocks[j].dateTs;
          if (bt === null || bt !== bt) { continue; }
          for (var q = 0; q < fr.s500.length; q++) { if (Math.abs(fr.s500[q] - bt) <= ewin) { near++; } }
        }
      }
      if ((rule = en('R-INF-002')) && fr.blocks && (fr.blocks.length >= blocksThr || (near && fr.blocks.length > 1))) {
        f = R.newFinding(rule, 'file', fr.name, near ? 'medium' : null); f.count = fr.blocks.length; f.first = fr.firstTs; f.last = fr.lastTs;
        f.detail = fr.blocks.length + ' header blocks (' + (fr.blocks.length - 1) + ' restarts; corpus median ' + medBlocks + ' blocks per file)' + (near ? '; ' + near + ' HTTP 500 response(s) within \u00b1' + (ewin / 60000) + ' min of a restart.' : '.');
        f.fileRefs = []; for (j = 1; j < fr.blocks.length && j < 50; j++) { f.fileRefs.push([i, fr.blocks[j].line]); }
        out.push(f);
      }
      if ((rule = en('R-INF-003'))) {
        var reasons = [];
        if (fr.backSteps) { reasons.push(fr.backSteps + ' backwards timestamp step(s)'); }
        if (fr.nameDate && fr.nameKind === 'daily' && fr.rows) {
          var nm = U.dayKeyToMs(fr.nameDate);
          if (fr.minTs < nm - (tol - DAY) || fr.maxTs > nm + tol) { reasons.push('content ' + U.fmtTs(fr.minTs) + ' .. ' + U.fmtTs(fr.maxTs) + ' UTC disagrees with filename date ' + fr.nameDate); }
        }
        if (reasons.length) {
          f = R.newFinding(rule, 'file', fr.name); f.count = fr.backSteps || 1; f.first = fr.minTs; f.last = fr.maxTs; f.detail = reasons.join('; ') + '.';
          f.fileRefs = []; for (j = 0; j < fr.backSamples.length; j++) { f.fileRefs.push([i, fr.backSamples[j].line]); }
          out.push(f);
        }
      }
      if ((rule = en('R-INF-004'))) {
        var why = [];
        if (fr.tailNoEol && i !== lastScanned) { why.push('file ends without a newline (truncated tail)'); }
        if (fr.nameDate && fr.nameKind === 'daily') {
          var nm2 = U.dayKeyToMs(fr.nameDate), nb = [], w;
          for (w = 1; w <= pr('R-INF-004', 'weeks', 4); w++) {
            var a = sizesByDate[U.dayKey(nm2 - w * 7 * DAY)], b2 = sizesByDate[U.dayKey(nm2 + w * 7 * DAY)];
            if (a !== undefined) { nb.push(a); } if (b2 !== undefined) { nb.push(b2); }
          }
          if (nb.length >= pr('R-INF-004', 'minNeighbours', 4)) {
            var med = U.median(nb);
            if (med > 0 && fr.size < med * pr('R-INF-004', 'ratio', 0.2) && i !== lastScanned) { why.push('size ' + U.fmtBytes(fr.size) + ' vs same-weekday median ' + U.fmtBytes(med)); }
          }
        }
        if (why.length) { f = R.newFinding(rule, 'file', fr.name); f.count = 1; f.first = fr.minTs; f.last = fr.maxTs; f.detail = why.join('; ') + '.'; f.fileRefs = [[i, 1]]; out.push(f); }
      }
      if ((rule = en('R-INF-007')) && fr.lines) {
        var bad = fr.malformed + fr.nonAscii + fr.decodeErr;
        if (bad / Math.max(1, fr.lines) >= pr('R-INF-007', 'ratio', 0.01) && bad >= 5) {
          f = R.newFinding(rule, 'file', fr.name); f.count = bad; f.first = fr.minTs; f.last = fr.maxTs;
          f.detail = fr.malformed + ' malformed, ' + fr.nonAscii + ' non-ASCII, ' + fr.decodeErr + ' URL-decode errors in ' + U.fmtNum(fr.lines) + ' lines.';
          f.fileRefs = []; for (j = 0; j < fr.malformedSamples.length; j++) { f.fileRefs.push([i, fr.malformedSamples[j].line]); }
          out.push(f);
        }
      }
    }
    if ((rule = en('R-INF-005'))) {
      if (idx.schemas.length > 1) {
        f = R.newFinding(rule, 'corpus', 'schema'); f.count = idx.schemas.length;
        f.detail = idx.schemas.length + ' distinct #Fields layouts: ' + idx.schemas.map(function (s) { return '[' + (idx.files[s.firstFile] || {}).name + ' line ' + s.firstLine + '] ' + s.fields; }).join(' | ');
        f.fileRefs = idx.schemas.map(function (s) { return [s.firstFile, s.firstLine]; }); out.push(f);
      }
      if (U.countKeys(idx.softwares) > 1) {
        f = R.newFinding(rule, 'corpus', 'software'); f.count = U.countKeys(idx.softwares);
        var sl = []; for (var sw in idx.softwares) { sl.push(sw + ' (from ' + (idx.files[idx.softwares[sw].firstFile] || {}).name + ')'); }
        f.detail = 'Multiple #Software values: ' + sl.join('; '); out.push(f);
      }
    }
    if ((rule = en('R-INF-006')) && idx.heartbeat) {
      var minH = pr('R-INF-006', 'minHours', 2), share = pr('R-INF-006', 'minDailyShare', 0.5), lbDays = [], dk;
      for (dk in idx.perDay) { if (idx.perDay[dk][6] > 0) { lbDays.push(idx.perDay[dk][6]); } }
      var medLb = U.median(lbDays), events = [];
      for (dk in idx.perDay) {
        if (idx.perDay[dk][6] < medLb * share) { continue; }
        var run = 0, runStart = -1, h;
        for (h = 0; h <= 24; h++) {
          var ph = h < 24 ? idx.perHour[dk + 'T' + U.p2(h)] : null, lbn = ph ? ph[3] : 0;
          if (h < 24 && lbn === 0) { if (run === 0) { runStart = h; } run++; } else {
            if (run >= minH) { events.push({ day: dk, from: runStart, hours: run }); }
            run = 0;
          }
        }
      }
      events.sort(function (a, b) { return a.day < b.day ? -1 : 1; });
      for (i = 0; i < events.length && i < 500; i++) {
        var ev = events[i], ft = U.dayKeyToMs(ev.day) + ev.from * HOUR;
        f = R.newFinding(rule, 'hour', ev.day + 'T' + U.p2(ev.from)); f.count = ev.hours; f.first = ft; f.last = ft + ev.hours * HOUR;
        f.detail = 'Heartbeat ' + idx.heartbeat.stem + '?' + idx.heartbeat.query + ' (normally ~' + idx.heartbeat.perDay + '/day from loopback) absent for ' + ev.hours + ' h from ' + U.fmtTs(ft) + ' UTC.';
        out.push(f);
      }
    }
  };
}(IISLA));
