/* Node.js harness that emulates the small COM surface used by the engine
 * (Scripting.FileSystemObject, Enumerator, WScript.Shell) so the parser,
 * rules and scan engine can be regression-tested outside mshta.
 * Usage: node test/run-scan.js <siteFolder> [fileGlob]
 */
'use strict';
var fs = require('fs'), path = require('path'), vm = require('vm');

function wrapFile(p) {
  var st = fs.statSync(p);
  return { Name: path.basename(p), Path: p, Size: st.size, DateLastModified: st.mtime, DateCreated: st.birthtime };
}
function wrapFolder(p) {
  return {
    Name: path.basename(p), Path: p,
    get Files() { return fs.readdirSync(p).map(function (n) { return path.join(p, n); }).filter(function (q) { return fs.statSync(q).isFile(); }).map(wrapFile); },
    get SubFolders() { return fs.readdirSync(p).map(function (n) { return path.join(p, n); }).filter(function (q) { return fs.statSync(q).isDirectory(); }).map(wrapFolder); }
  };
}
/* FSO text stream in ASCII mode on a cp1252 system: incremental Windows-1252 decoding, like the real component. */
function TextStream(p, mode) {
  this.p = p; this.mode = mode;
  if (mode === 1) { this.fd = fs.openSync(p, 'r'); this.size = fs.fstatSync(this.fd).size; this.off = 0; }
}
Object.defineProperty(TextStream.prototype, 'AtEndOfStream', { get: function () { return this.off >= this.size; } });
TextStream.prototype.Read = function (n) {
  var len = Math.max(0, Math.min(n, this.size - this.off)), b = Buffer.alloc(len);
  if (len) { fs.readSync(this.fd, b, 0, len, this.off); }
  this.off += len; return CP1252.decode(b);
};
TextStream.prototype.ReadAll = function () { return this.Read(this.size - this.off); };
TextStream.prototype.WriteLine = function (s) { fs.appendFileSync(this.p, s + '\r\n', 'latin1'); };
TextStream.prototype.Close = function () { if (this.fd !== undefined) { fs.closeSync(this.fd); this.fd = undefined; } };

var FSO = {
  FileExists: function (p) { try { return fs.statSync(p).isFile(); } catch (e) { return false; } },
  FolderExists: function (p) { try { return fs.statSync(p).isDirectory(); } catch (e) { return false; } },
  GetFolder: function (p) { return wrapFolder(p); },
  GetFile: function (p) { return wrapFile(p); },
  GetParentFolderName: function (p) { var d = path.dirname(p); return d === p ? '' : d; },
  OpenTextFile: function (p, mode) { return new TextStream(p, mode); },
  CreateFolder: function (p) { fs.mkdirSync(p, { recursive: true }); },
  DeleteFile: function (p) { fs.unlinkSync(p); }
};
var CP1252 = new TextDecoder('windows-1252');
function AdoStream() { this.text = ''; this.pos = 0; }
Object.defineProperty(AdoStream.prototype, 'EOS', { get: function () { return this.pos >= this.text.length; } });
AdoStream.prototype.Open = function () { };
AdoStream.prototype.Close = function () { };
AdoStream.prototype.LoadFromFile = function (p) { if (this.Charset !== 'windows-1252') { throw new Error('harness: only windows-1252 emulated'); } this.text = CP1252.decode(fs.readFileSync(p)); this.pos = 0; };
AdoStream.prototype.ReadText = function (n) { var s = this.text.substr(this.pos, n < 0 ? undefined : n); this.pos += s.length; return s; };
global.ActiveXObject = function (progId) {
  if (progId === 'Scripting.FileSystemObject') { return FSO; }
  if (progId === 'ADODB.Stream') { return new AdoStream(); }
  if (progId === 'WScript.Shell') { return { ExpandEnvironmentStrings: function (s) { return s.replace(/%([^%]+)%/g, function (m, n) { return process.env[n] || m; }); } }; }
  throw new Error('ActiveXObject not emulated: ' + progId);
};
global.Enumerator = function (arr) { this.a = arr; this.i = 0; };
global.Enumerator.prototype.atEnd = function () { return this.i >= this.a.length; };
global.Enumerator.prototype.moveNext = function () { this.i++; };
global.Enumerator.prototype.item = function () { return this.a[this.i]; };

var root = path.join(__dirname, '..');
function load(f) { vm.runInThisContext(fs.readFileSync(path.join(root, f), 'utf8'), { filename: f }); }
['lib/util.js', 'lib/tz.js', 'lib/io.js', 'lib/parser.js', 'lib/useragent.js', 'lib/rules.js', 'lib/scan.js', 'lib/engine.js', 'lib/store.js', 'lib/filter.js'].forEach(function (f) {
  if (fs.existsSync(path.join(root, f))) { load(f); }
});
var NS = global.IISLA;
NS.io.fsoStreamOk = function () { return true; }; // proven on the workstation by the HTA self-test; emulated above
NS.util.readTextUtf8 = function (p) { return fs.readFileSync(p, 'utf8'); };
NS.util.writeTextUtf8 = function (p, t) { fs.writeFileSync(p, t, 'utf8'); };
NS.util.isBusinessTime = NS.util.isBusinessTime;

NS.loadLists = function () {
  var dir = path.join(root, 'lists'), out = {};
  fs.readdirSync(dir).forEach(function (n) { if (/\.txt$/.test(n)) { out[n.replace(/\.txt$/, '')] = NS.util.parseList(fs.readFileSync(path.join(dir, n), 'utf8')); } });
  NS.useragent.init(out['browser-releases']); // as the HTA does at start-up
  return out;
};
NS.defaultSettings = function () {
  return JSON.parse(fs.readFileSync(path.join(root, 'config', 'settings.json'), 'utf8'));
};
module.exports = NS;
