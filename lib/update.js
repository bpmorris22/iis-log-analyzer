/* IIS Log Analyzer - update.js
 * Version check against the GitHub releases of this project, and in-place replacement of the single-file HTA.
 * Network use is explicit: a manual check asks first; the start-up check runs only when enabled in Settings.
 * A downloaded HTA replaces the running file only after its size and SHA-256 match the release asset and it
 * reports the expected version; the previous file is kept next to it as a backup.
 */
(function (NS) {
  'use strict';
  var U = NS.util, UP = NS.update = {};

  UP.REPO = 'bpmorris22/iis-log-analyzer';
  UP.API = 'https://api.github.com/repos/' + UP.REPO + '/releases/latest';
  UP.RELEASES = 'https://github.com/' + UP.REPO + '/releases';
  UP.ASSET = 'IISLogAnalyzer.hta';

  /* "v1.2.0" / "1.2.0" -> [1, 2, 0] */
  UP.parseVersion = function (s) { var m = /(\d+)\.(\d+)\.(\d+)/.exec(s || ''); return m ? [+m[1], +m[2], +m[3]] : null; };
  /* > 0 when a is newer than b */
  UP.compare = function (a, b) {
    var x = UP.parseVersion(a), y = UP.parseVersion(b), i;
    if (!x || !y) { return 0; }
    for (i = 0; i < 3; i++) { if (x[i] !== y[i]) { return x[i] > y[i] ? 1 : -1; } }
    return 0;
  };
  UP.current = function () { return UP.versionOverride || NS.VERSION; };
  /* The single-file build embeds its resources; the folder form loads lib\*.js and cannot be replaced by one file. */
  UP.isSingleFile = function () { return !!document.querySelector('script[data-res]'); };
  UP.selfPath = function () {
    var a = NS.app && NS.app.state && NS.app.state.htaPath;
    return a || decodeURIComponent(('' + document.location.pathname).replace(/^\/+/, '')).replace(/\//g, '\\');
  };

  /* Asynchronous GET (MSXML2.ServerXMLHTTP, polled so the window stays responsive). cb(err, textOrBytes) */
  UP.get = function (url, binary, cb, timeoutMs) {
    var x, t0 = Date.now();
    try {
      x = new ActiveXObject('MSXML2.ServerXMLHTTP.6.0');
      x.open('GET', url, true);
      x.setRequestHeader('User-Agent', 'IISLogAnalyzer/' + NS.VERSION);
      if (!binary) { x.setRequestHeader('Accept', 'application/vnd.github+json'); }
      x.send();
    } catch (e) { cb(new Error('Request failed: ' + e.message)); return; }
    (function poll() {
      var rs, st;
      try { rs = x.readyState; } catch (e1) { cb(e1); return; }
      if (rs === 4) {
        try { st = x.status; } catch (e2) { cb(new Error('No response: ' + e2.message)); return; }
        if (st !== 200) { cb(new Error('HTTP ' + st + ' from ' + url)); return; }
        try { cb(null, binary ? x.responseBody : x.responseText); } catch (e3) { cb(e3); }
        return;
      }
      if (Date.now() - t0 > (timeoutMs || 20000)) { try { x.abort(); } catch (e4) { } cb(new Error('Timed out contacting ' + url.replace(/^https:\/\/([^\/]+).*$/, '$1'))); return; }
      setTimeout(poll, 150);
    }());
  };

  /* Latest published release. cb(err, { version, tag, name, url, published, notes, asset: { url, size, sha256 }, shaUrl }) */
  UP.latest = function (cb) {
    UP.get(UP.API, false, function (err, text) {
      if (err) { cb(err); return; }
      var r, i, a, info;
      try { r = JSON.parse(text); } catch (e) { cb(new Error('Unexpected answer from GitHub')); return; }
      info = { version: (r.tag_name || '').replace(/^v/i, ''), tag: r.tag_name || '', name: r.name || r.tag_name || '', url: r.html_url || UP.RELEASES,
        published: r.published_at || '', notes: r.body || '', asset: null, shaUrl: '' };
      for (i = 0; i < (r.assets || []).length; i++) {
        a = r.assets[i];
        if (a.name === UP.ASSET) { info.asset = { url: a.browser_download_url, size: a.size, sha256: /^sha256:[0-9a-f]{64}$/i.test(a.digest || '') ? a.digest.substr(7).toLowerCase() : '' }; }
        if (a.name === UP.ASSET + '.sha256') { info.shaUrl = a.browser_download_url; }
      }
      if (!UP.parseVersion(info.version)) { cb(new Error('The latest release has no version number')); return; }
      cb(null, info);
    });
  };

  function saveBytes(bytes, path) {
    var s = new ActiveXObject('ADODB.Stream');
    s.Type = 1; s.Open();
    try { s.Write(bytes); s.SaveToFile(path, 2); } finally { s.Close(); }
  }
  function expectedHash(info, cb) {
    if (info.asset.sha256) { cb(null, info.asset.sha256); return; }
    if (!info.shaUrl) { cb(new Error('The release publishes no SHA-256 for ' + UP.ASSET)); return; }
    UP.get(info.shaUrl, false, function (err, t) {
      var m = !err && /^\s*([0-9a-f]{64})\b/i.exec(t || '');
      if (!m) { cb(err || new Error('Unreadable SHA-256 file in the release')); return; }
      cb(null, m[1].toLowerCase());
    });
  }

  /* Downloads the release HTA to dest and verifies size, SHA-256 and embedded version.
   * cb(err, { path, sha256, bytes }) ; workDir: folder for certutil output. */
  UP.download = function (info, dest, workDir, cb) {
    if (!info.asset) { cb(new Error('The release has no ' + UP.ASSET + ' asset')); return; }
    expectedHash(info, function (errH, want) {
      if (errH) { cb(errH); return; }
      UP.get(info.asset.url, true, function (err, bytes) {
        if (err) { cb(err); return; }
        var fso = U.fso(), size, got, text;
        try { saveBytes(bytes, dest); } catch (e1) { cb(new Error('Cannot write ' + dest + ': ' + e1.message)); return; }
        function fail(msg) { try { fso.DeleteFile(dest, true); } catch (e) { } cb(new Error(msg)); }
        try { size = fso.GetFile(dest).Size; } catch (e2) { fail('Download vanished: ' + e2.message); return; }
        if (info.asset.size && size !== info.asset.size) { fail('Size mismatch: ' + size + ' bytes, release says ' + info.asset.size); return; }
        got = NS.io.hashFileSync(dest, workDir);
        if (got !== want) { fail('SHA-256 mismatch: downloaded ' + (got || '(none)') + ', release says ' + want); return; }
        try { text = U.readTextUtf8(dest); } catch (e3) { fail('Downloaded file unreadable: ' + e3.message); return; }
        if (text.indexOf("NS.VERSION = '" + info.version + "'") < 0) { fail('The downloaded HTA does not report version ' + info.version); return; }
        cb(null, { path: dest, sha256: got, bytes: size });
      }, 180000);
    });
  };

  /* Replaces target with the verified download; the old file is kept as <name>-<oldversion>.bak.hta.
   * Returns { target, backup }. */
  UP.replace = function (downloaded, target, oldVersion) {
    var fso = U.fso(), dir = U.parentOf(target), base = U.baseOf(target).replace(/\.hta$/i, '');
    var backup = U.joinPath(dir, base + '-' + oldVersion + '.bak.hta'), n = 1;
    while (fso.FileExists(backup)) { backup = U.joinPath(dir, base + '-' + oldVersion + '.bak' + (++n) + '.hta'); }
    fso.CopyFile(target, backup, false);
    fso.CopyFile(downloaded, target, true);
    try { fso.DeleteFile(downloaded, true); } catch (e) { }
    return { target: target, backup: backup };
  };
}(IISLA));
