// IIS Log Analyzer - fast scan engine (C# 5, compiled at run time by Windows PowerShell 5.1 Add-Type).
//
// Out-of-process equivalent of lib/scan.js S.Scanner: streams every file once and writes the index
// aggregates as ASCII-only JSON. The HTA supplies everything that is data (rules, lists, regex sources,
// field map, constants, time-zone transition table) in a job file, and runs the shared JavaScript
// post-processing (heartbeat, missing files, findings) on the result, so both engines produce the same
// index. Semantics follow JavaScript exactly where it matters: number parsing/printing, Date.UTC,
// string splitting, regex translation (JS -> .NET), null-prototype map behaviour and insertion order.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;
using System.Threading;

namespace IISLA
{
    // ---------------------------------------------------------------- JSON
    public static class Json
    {
        public static object Parse(string s) { int i = 0; return Val(s, ref i); }
        static void Ws(string s, ref int i) { while (i < s.Length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++; }
        static object Val(string s, ref int i)
        {
            Ws(s, ref i);
            char c = s[i];
            if (c == '{')
            {
                i++; var d = new Dictionary<string, object>(); Ws(s, ref i);
                if (s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws(s, ref i); string k = Str(s, ref i); Ws(s, ref i); i++; // ':'
                    d[k] = Val(s, ref i); Ws(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    i++; return d;
                }
            }
            if (c == '[')
            {
                i++; var l = new List<object>(); Ws(s, ref i);
                if (s[i] == ']') { i++; return l; }
                while (true)
                {
                    l.Add(Val(s, ref i)); Ws(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    i++; return l;
                }
            }
            if (c == '"') return Str(s, ref i);
            if (c == 't') { i += 4; return true; }
            if (c == 'f') { i += 5; return false; }
            if (c == 'n') { i += 4; return null; }
            int st = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            return double.Parse(s.Substring(st, i - st), NumberStyles.Float, CultureInfo.InvariantCulture);
        }
        static string Str(string s, ref int i)
        {
            i++; var sb = new StringBuilder();
            while (true)
            {
                char c = s[i++];
                if (c == '"') break;
                if (c == '\\')
                {
                    char e = s[i++];
                    switch (e)
                    {
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'u': sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16)); i += 4; break;
                        default: sb.Append(e); break;
                    }
                }
                else sb.Append(c);
            }
            return sb.ToString();
        }
    }

    // Streaming ASCII-only JSON writer (non-ASCII escaped as \uXXXX, like U.asciiJson).
    public sealed class JW
    {
        readonly TextWriter w;
        readonly List<bool> first = new List<bool>();
        public JW(TextWriter w) { this.w = w; }
        void Sep() { if (first.Count > 0) { if (!first[first.Count - 1]) w.Write(','); first[first.Count - 1] = false; } }
        public JW BeginObj() { Sep(); w.Write('{'); first.Add(true); return this; }
        public JW EndObj() { w.Write('}'); first.RemoveAt(first.Count - 1); return this; }
        public JW BeginArr() { Sep(); w.Write('['); first.Add(true); return this; }
        public JW EndArr() { w.Write(']'); first.RemoveAt(first.Count - 1); return this; }
        public JW Key(string k) { Sep(); WriteStr(k); w.Write(':'); first.Add(true); first.RemoveAt(first.Count - 1); suppress = true; return this; }
        bool suppress;
        void SepV() { if (suppress) { suppress = false; return; } Sep(); }
        public JW Str(string s) { SepV(); if (s == null) w.Write("null"); else WriteStr(s); return this; }
        public JW Num(double v) { SepV(); w.Write(Js.JsonNum(v)); return this; }
        public JW Bool(bool b) { SepV(); w.Write(b ? "true" : "false"); return this; }
        public JW Null() { SepV(); w.Write("null"); return this; }
        public JW ObjStart() { SepV(); w.Write('{'); first.Add(true); return this; }
        public JW ArrStart() { SepV(); w.Write('['); first.Add(true); return this; }
        public JW KNum(string k, double v) { return Key(k).Num(v); }
        public JW KStr(string k, string v) { return Key(k).Str(v); }
        public JW KBool(string k, bool v) { return Key(k).Bool(v); }
        public JW Raw(string json) { SepV(); w.Write(json); return this; }
        void WriteStr(string s)
        {
            w.Write('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                switch (c)
                {
                    case '"': w.Write("\\\""); break;
                    case '\\': w.Write("\\\\"); break;
                    case '\n': w.Write("\\n"); break;
                    case '\r': w.Write("\\r"); break;
                    case '\t': w.Write("\\t"); break;
                    case '\b': w.Write("\\b"); break;
                    case '\f': w.Write("\\f"); break;
                    default:
                        if (c < 0x20 || c >= 0x7f) { w.Write("\\u"); w.Write(((int)c).ToString("x4")); }
                        else w.Write(c);
                        break;
                }
            }
            w.Write('"');
        }
    }

    // ---------------------------------------------------------------- JavaScript semantics
    public static class Js
    {
        public static bool IsWs(char c)
        {
            return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == '\u00a0' || c == '\u1680' || c == '\u180e' ||
                (c >= '\u2000' && c <= '\u200a') || c == '\u2028' || c == '\u2029' || c == '\u202f' || c == '\u205f' || c == '\u3000' || c == '\ufeff';
        }
        public static string Trim(string s)
        {
            int a = 0, b = s.Length;
            while (a < b && IsWs(s[a])) a++;
            while (b > a && IsWs(s[b - 1])) b--;
            return (a == 0 && b == s.Length) ? s : s.Substring(a, b - a);
        }
        // Splits on runs of JS whitespace like s.split(/\s+/) (leading/trailing runs give empty first/last items).
        public static List<string> SplitWs(string s)
        {
            var o = new List<string>(); int i = 0, st = 0;
            while (i <= s.Length)
            {
                if (i == s.Length) { o.Add(s.Substring(st)); break; }
                if (IsWs(s[i])) { o.Add(s.Substring(st, i - st)); while (i < s.Length && IsWs(s[i])) i++; st = i; continue; }
                i++;
            }
            return o;
        }
        static readonly Regex DecLit = new Regex(@"^([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$", RegexOptions.CultureInvariant);
        // ToNumber(string) per ES5 9.3.1
        public static double ToNumber(string s)
        {
            s = Trim(s);
            if (s.Length == 0) return 0;
            if (s.Length > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            {
                double v = 0;
                for (int i = 2; i < s.Length; i++)
                {
                    int d = HexVal(s[i]); if (d < 0) return double.NaN;
                    v = v * 16 + d;
                }
                return v;
            }
            int p = 0; bool neg = false;
            if (s[0] == '+' || s[0] == '-') { neg = s[0] == '-'; p = 1; }
            string r = s.Substring(p);
            if (r == "Infinity") return neg ? double.NegativeInfinity : double.PositiveInfinity;
            if (!DecLit.IsMatch(r)) return double.NaN;
            double x = double.Parse(r, NumberStyles.AllowDecimalPoint | NumberStyles.AllowExponent, CultureInfo.InvariantCulture);
            return neg ? -x : x;
        }
        public static int HexVal(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        }
        // Number.prototype.toString() per ES5 9.8.1 (shortest round-trip digits from "R").
        public static string NumStr(double v)
        {
            if (double.IsNaN(v)) return "NaN";
            if (double.IsPositiveInfinity(v)) return "Infinity";
            if (double.IsNegativeInfinity(v)) return "-Infinity";
            if (v == 0) return "0";
            if (v < 0) return "-" + NumStr(-v);
            if (v == Math.Floor(v) && v < 1e21) return v.ToString("0", CultureInfo.InvariantCulture);
            string r = v.ToString("R", CultureInfo.InvariantCulture);
            // decompose into digits and exponent n (value = 0.digits * 10^n)
            string mant = r, exps = "0";
            int ei = r.IndexOfAny(new char[] { 'E', 'e' });
            if (ei >= 0) { mant = r.Substring(0, ei); exps = r.Substring(ei + 1); }
            int e10 = int.Parse(exps, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            int dot = mant.IndexOf('.');
            string intPart = dot >= 0 ? mant.Substring(0, dot) : mant, frac = dot >= 0 ? mant.Substring(dot + 1) : "";
            string digits = (intPart + frac).TrimStart('0');
            int lead = (intPart + frac).Length - digits.Length;
            int n = intPart.Length - lead + e10;
            digits = digits.TrimEnd('0'); if (digits.Length == 0) return "0";
            int k = digits.Length;
            if (k <= n && n <= 21) return digits + new string('0', n - k);
            if (0 < n && n <= 21) return digits.Substring(0, n) + "." + digits.Substring(n);
            if (-6 < n && n <= 0) return "0." + new string('0', -n) + digits;
            string es = (n - 1 >= 0 ? "+" : "-") + Math.Abs(n - 1).ToString(CultureInfo.InvariantCulture);
            return k == 1 ? digits + "e" + es : digits.Substring(0, 1) + "." + digits.Substring(1) + "e" + es;
        }
        public static string JsonNum(double v)
        {
            if (double.IsNaN(v) || double.IsInfinity(v)) return "null";
            if (v == Math.Floor(v) && Math.Abs(v) < 9007199254740992.0) return ((long)v).ToString(CultureInfo.InvariantCulture);
            return v.ToString("G17", CultureInfo.InvariantCulture);
        }
        static double ToInteger(double v) { if (double.IsNaN(v)) return 0; if (double.IsInfinity(v)) return v; return v < 0 ? -Math.Floor(-v) : Math.Floor(v); }
        static double DaysFromCivil(double y, double m, double d)
        {
            // proleptic Gregorian, m 1..12
            y -= m <= 2 ? 1 : 0;
            double era = Math.Floor(y / 400);
            double yoe = y - era * 400;
            double doy = Math.Floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
            double doe = yoe * 365 + Math.Floor(yoe / 4) - Math.Floor(yoe / 100) + doy;
            return era * 146097 + doe - 719468;
        }
        // Date.UTC(year, month, date, hours, minutes, seconds, ms) per ES5 15.9.4.3
        public static double DateUTC(double y, double mo, double d, double h, double mi, double s, double ms)
        {
            if (double.IsNaN(y) || double.IsNaN(mo) || double.IsNaN(d) || double.IsNaN(h) || double.IsNaN(mi) || double.IsNaN(s) || double.IsNaN(ms)) return double.NaN;
            if (double.IsInfinity(y) || double.IsInfinity(mo) || double.IsInfinity(d) || double.IsInfinity(h) || double.IsInfinity(mi) || double.IsInfinity(s) || double.IsInfinity(ms)) return double.NaN;
            double yi = ToInteger(y);
            if (yi >= 0 && yi <= 99) yi += 1900;
            double m = ToInteger(mo), ym = yi + Math.Floor(m / 12), mn = m - Math.Floor(m / 12) * 12;
            double day = DaysFromCivil(ym, mn + 1, 1) + ToInteger(d) - 1;
            double t = day * 86400000.0 + (ToInteger(h) * 3600000.0 + ToInteger(mi) * 60000.0 + ToInteger(s) * 1000.0 + ToInteger(ms));
            if (Math.Abs(t) > 8.64e15) return double.NaN;
            return ToInteger(t);
        }
        public static void CivilFromMs(double t, out long y, out int m, out int d, out int hh)
        {
            double days = Math.Floor(t / 86400000.0);
            double msInDay = t - days * 86400000.0;
            hh = (int)Math.Floor(msInDay / 3600000.0);
            double z = days + 719468, era = Math.Floor(z / 146097), doe = z - era * 146097;
            double yoe = Math.Floor((doe - Math.Floor(doe / 1460) + Math.Floor(doe / 36524) - Math.Floor(doe / 146096)) / 365);
            double yy = yoe + era * 400, doy = doe - (365 * yoe + Math.Floor(yoe / 4) - Math.Floor(yoe / 100));
            double mp = Math.Floor((5 * doy + 2) / 153);
            d = (int)(doy - Math.Floor((153 * mp + 2) / 5) + 1);
            m = (int)(mp < 10 ? mp + 3 : mp - 9);
            y = (long)(yy + (m <= 2 ? 1 : 0));
        }
        public static string P2(long n) { return n < 10 && n >= 0 ? "0" + n : n.ToString(CultureInfo.InvariantCulture); }
        public static string DayKey(double t) { long y; int m, d, h; CivilFromMs(t, out y, out m, out d, out h); return y.ToString(CultureInfo.InvariantCulture) + "-" + P2(m) + "-" + P2(d); }
        public static int UtcHours(double t) { long y; int m, d, h; CivilFromMs(t, out y, out m, out d, out h); return h; }
        // JavaScript String.prototype.toLowerCase / toUpperCase (invariant mapping is equivalent for the
        // characters reachable from cp1252 decoding and percent-decoding of ordinary text).
        public static string Lower(string s) { return s.ToLowerInvariant(); }
        public static string Upper(string s) { return s.ToUpperInvariant(); }
    }

    // Translates a JavaScript regular expression source into an equivalent .NET pattern.
    public static class JsRegex
    {
        const string W = "A-Za-z0-9_";
        const string WB = "(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))";
        const string NWB = "(?:(?<=[A-Za-z0-9_])(?=[A-Za-z0-9_])|(?<![A-Za-z0-9_])(?![A-Za-z0-9_]))";
        public static string Translate(string src)
        {
            var sb = new StringBuilder(); bool inClass = false;
            for (int i = 0; i < src.Length; i++)
            {
                char c = src[i];
                if (c == '\\' && i + 1 < src.Length)
                {
                    char n = src[++i];
                    if (inClass)
                    {
                        if (n == 'd') sb.Append("0-9");
                        else if (n == 'w') sb.Append(W);
                        else if (n == 'u' && i + 4 < src.Length) { sb.Append("\\u").Append(src.Substring(i + 1, 4)); i += 4; }
                        else sb.Append('\\').Append(n);
                        continue;
                    }
                    if (n == 'd') sb.Append("[0-9]");
                    else if (n == 'D') sb.Append("[^0-9]");
                    else if (n == 'w') sb.Append("[" + W + "]");
                    else if (n == 'W') sb.Append("[^" + W + "]");
                    else if (n == 'b') sb.Append(WB);
                    else if (n == 'B') sb.Append(NWB);
                    else if (n == 'u' && i + 4 < src.Length) { sb.Append("\\u").Append(src.Substring(i + 1, 4)); i += 4; }
                    else sb.Append('\\').Append(n);
                    continue;
                }
                if (inClass) { if (c == ']') inClass = false; sb.Append(c); continue; }
                if (c == '[')
                {
                    inClass = true; sb.Append(c);
                    if (i + 1 < src.Length && src[i + 1] == '^') { sb.Append('^'); i++; }
                    if (i + 1 < src.Length && src[i + 1] == ']') { sb.Append("\\]"); i++; } // JS [] / [^] edge: treat literally
                    continue;
                }
                if (c == '$') { sb.Append("\\z"); continue; }
                if (c == '.') { sb.Append("[^\\n\\r\\u2028\\u2029]"); continue; }
                sb.Append(c);
            }
            return sb.ToString();
        }
        public static bool HasUpperLiteral(string src)
        {
            for (int i = 0; i < src.Length; i++)
            {
                char c = src[i];
                if (c == '\\') { if (i + 1 < src.Length && src[i + 1] == 'u') i += 5; else i++; continue; }
                if (c >= 'A' && c <= 'Z') return true;
            }
            return false;
        }
        public static Regex Make(string src, bool ignoreCase)
        {
            var o = RegexOptions.CultureInvariant | RegexOptions.Compiled;
            if (ignoreCase) o |= RegexOptions.IgnoreCase;
            return new Regex(Translate(src), o);
        }
    }

    // Insertion-ordered string map with JS-like delete/re-add semantics (deleted keys re-added go last).
    public sealed class OMap<V>
    {
        readonly Dictionary<string, int> ix = new Dictionary<string, int>(StringComparer.Ordinal);
        readonly List<string> keys = new List<string>();
        readonly List<V> vals = new List<V>();
        readonly List<bool> alive = new List<bool>();
        int dead;
        public int Count { get { return ix.Count; } }
        public bool TryGet(string k, out V v) { int i; if (ix.TryGetValue(k, out i)) { v = vals[i]; return true; } v = default(V); return false; }
        public bool Has(string k) { return ix.ContainsKey(k); }
        public V this[string k]
        {
            get { return vals[ix[k]]; }
            set { int i; if (ix.TryGetValue(k, out i)) vals[i] = value; else { ix[k] = keys.Count; keys.Add(k); vals.Add(value); alive.Add(true); } }
        }
        public void Remove(string k)
        {
            int i; if (!ix.TryGetValue(k, out i)) return;
            ix.Remove(k); alive[i] = false; vals[i] = default(V); dead++;
            if (dead > 4096 && dead > keys.Count / 2) Compact();
        }
        void Compact()
        {
            var nk = new List<string>(); var nv = new List<V>(); var na = new List<bool>();
            for (int i = 0; i < keys.Count; i++) if (alive[i]) { ix[keys[i]] = nk.Count; nk.Add(keys[i]); nv.Add(vals[i]); na.Add(true); }
            keys.Clear(); keys.AddRange(nk); vals.Clear(); vals.AddRange(nv); alive.Clear(); alive.AddRange(na); dead = 0;
        }
        public List<string> Keys() { var o = new List<string>(ix.Count); for (int i = 0; i < keys.Count; i++) if (alive[i]) o.Add(keys[i]); return o; }
        public void Inc(string k) { int i; if (ix.TryGetValue(k, out i)) vals[i] = (V)(object)(Convert.ToDouble(vals[i]) + 1.0); else this[k] = (V)(object)1.0; }
    }

    // ---------------------------------------------------------------- utilities ported from util.js
    public sealed class Cidr { public int V; public double Base, Size; public string Hex; public double Bits; }
    public static class IpUtil
    {
        static readonly Regex V4 = new Regex(@"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", RegexOptions.CultureInvariant);
        static readonly Regex V6chars = new Regex("^[0-9a-f:.]+$", RegexOptions.CultureInvariant);
        static readonly Regex V4tail = new Regex(@"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", RegexOptions.CultureInvariant);
        static readonly Regex Hex4 = new Regex("^[0-9a-f]{1,4}$", RegexOptions.CultureInvariant);
        public static List<Cidr> ExtraInternal = new List<Cidr>();
        public static HashSet<string> Allow = new HashSet<string>(StringComparer.Ordinal);
        public static double ParseV4(string s)
        {
            var m = V4.Match(s); if (!m.Success) return -1;
            double a = Js.ToNumber(m.Groups[1].Value), b = Js.ToNumber(m.Groups[2].Value), c = Js.ToNumber(m.Groups[3].Value), d = Js.ToNumber(m.Groups[4].Value);
            if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
            return ((a * 256 + b) * 256 + c) * 256 + d;
        }
        public static string ExpandV6(string s)
        {
            s = Js.Lower(s);
            int pct = s.IndexOf('%'); if (pct >= 0) s = s.Substring(0, pct);
            if (s.Length > 0 && s[0] == '[') s = Regex.Replace(s, @"^\[|\]\z", "");
            if (!V6chars.IsMatch(s) || s.IndexOf(':') < 0) return null;
            var v4 = V4tail.Match(s);
            if (v4.Success)
            {
                double n = ParseV4(v4.Groups[1].Value); if (n < 0) return null;
                long hi = (long)Math.Floor(n / 65536), lo = (long)(n % 65536);
                s = s.Substring(0, s.Length - v4.Groups[1].Value.Length) + ("0000" + hi.ToString("x")).Substring(("0000" + hi.ToString("x")).Length - 4) + ":" + ("0000" + lo.ToString("x")).Substring(("0000" + lo.ToString("x")).Length - 4);
            }
            string[] parts = s.Split(new string[] { "::" }, StringSplitOptions.None);
            if (parts.Length > 2) return null;
            var head = parts[0].Length > 0 ? new List<string>(parts[0].Split(':')) : new List<string>();
            var tail = parts.Length == 2 && parts[1].Length > 0 ? new List<string>(parts[1].Split(':')) : new List<string>();
            int fill = 8 - head.Count - tail.Count;
            if (parts.Length == 1 && fill != 0) return null;
            if (fill < 0) return null;
            var all = new List<string>(head); for (int i = 0; i < fill; i++) all.Add("0"); all.AddRange(tail);
            var sb = new StringBuilder();
            for (int i = 0; i < 8; i++)
            {
                if (i >= all.Count || !Hex4.IsMatch(all[i])) return null;
                string p = "0000" + all[i]; sb.Append(p.Substring(p.Length - 4));
            }
            return sb.ToString();
        }
        public static bool IsValid(string s) { return ParseV4(s) >= 0 || ExpandV6(s) != null; }
        public static Cidr ParseCidr(string s)
        {
            s = Js.Trim(s);
            int slash = s.IndexOf('/');
            string ip = slash >= 0 ? s.Substring(0, slash) : s;
            double bits = slash >= 0 ? Js.ToNumber(s.Substring(slash + 1)) : -1;
            double n4 = ParseV4(ip);
            if (n4 >= 0)
            {
                if (bits < 0) bits = 32;
                if (!(bits >= 0 && bits <= 32)) return null;
                double size = Math.Pow(2, 32 - bits);
                return new Cidr { V = 4, Base = Math.Floor(n4 / size) * size, Size = size };
            }
            string h = ExpandV6(ip);
            if (h != null)
            {
                if (bits < 0) bits = 128;
                if (!(bits >= 0 && bits <= 128)) return null;
                return new Cidr { V = 6, Hex = h, Bits = bits };
            }
            return null;
        }
        static bool HexPrefix(string a, string b, double bitsD)
        {
            int bits = (int)bitsD, full = bits / 4, rem = bits % 4;
            if (string.CompareOrdinal(a, 0, b, 0, full) != 0) return false;
            if (rem == 0) return true;
            int m = (0xF << (4 - rem)) & 0xF;
            return (Js.HexVal(a[full]) & m) == (Js.HexVal(b[full]) & m);
        }
        public static bool CidrMatch(Cidr c, string ip)
        {
            if (c == null) return false;
            if (c.V == 4)
            {
                double n = ParseV4(ip);
                if (n < 0)
                {
                    string h = ExpandV6(ip);
                    if (h != null && h.Substring(0, 24) == "00000000000000000000ffff") n = Convert.ToInt64(h.Substring(24), 16); else return false;
                }
                return n >= c.Base && n < c.Base + c.Size;
            }
            string hx = ExpandV6(ip);
            return hx != null && HexPrefix(hx, c.Hex, c.Bits);
        }
        public static string Classify(string s)
        {
            if (string.IsNullOrEmpty(s) || s == "-") return "none";
            if (Allow.Count > 0 && Allow.Contains(Js.Lower(s))) return "allowlisted";
            double n = ParseV4(s);
            if (n < 0)
            {
                string h = ExpandV6(s);
                if (h == null) return "invalid";
                if (h.Substring(0, 24) == "00000000000000000000ffff")
                {
                    long v = Convert.ToInt64(h.Substring(24), 16);
                    return Classify((v / 16777216) + "." + ((v / 65536) % 256) + "." + ((v / 256) % 256) + "." + (v % 256));
                }
                if (h == "00000000000000000000000000000001") return "loopback";
                foreach (var c in ExtraInternal) if (CidrMatch(c, s)) return "internal";
                if (h.StartsWith("fe8", StringComparison.Ordinal) || h.StartsWith("fe9", StringComparison.Ordinal) || h.StartsWith("fea", StringComparison.Ordinal) || h.StartsWith("feb", StringComparison.Ordinal)) return "linklocal";
                if (h.StartsWith("fc", StringComparison.Ordinal) || h.StartsWith("fd", StringComparison.Ordinal)) return "rfc1918";
                if (h == "00000000000000000000000000000000" || h.StartsWith("ff", StringComparison.Ordinal) || (!TestNetsPublic && h.StartsWith("20010db8", StringComparison.Ordinal))) return "bogon";
                return "public";
            }
            double a = Math.Floor(n / 16777216), b = Math.Floor(n / 65536) % 256;
            if (a == 127) return "loopback";
            foreach (var c in ExtraInternal) if (CidrMatch(c, s)) return "internal";
            if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)) return "rfc1918";
            if (a == 169 && b == 254) return "linklocal";
            if (a == 100 && b >= 64 && b <= 127) return "cgnat";
            double c3 = Math.Floor(n / 256) % 256;
            bool testNet = (a == 192 && b == 0 && c3 == 2) || (a == 198 && b == 51 && c3 == 100) || (a == 203 && b == 0 && c3 == 113);
            if (a == 0 || a >= 224 || (testNet && !TestNetsPublic) || (a == 198 && (b == 18 || b == 19))) return "bogon";
            return "public";
        }
        public static bool IsInternalClass(string c) { return c == "rfc1918" || c == "internal" || c == "loopback" || c == "linklocal"; }
        // Training and demo data only (mirrors util.js setTestNetsPublic): documentation ranges classify as public.
        public static bool TestNetsPublic;
    }

    public static class TextUtil
    {
        public static string ReEscape(string s) { return Regex.Replace(s, @"[.*+?^${}()|[\]\\/]", "\\$0"); }
        public static string GlobToRegexSrc(string g)
        {
            var sb = new StringBuilder();
            foreach (char c in g) { if (c == '*') sb.Append(".*"); else if (c == '?') sb.Append('.'); else sb.Append(ReEscape(c.ToString())); }
            return "^" + sb + "$";
        }
        public static string ExtOf(string stemLower)
        {
            int slash = stemLower.LastIndexOf('/');
            string b = stemLower.Substring(slash + 1);
            int dot = b.LastIndexOf('.');
            return dot > 0 || (dot == 0 && b.Length > 1) ? b.Substring(dot) : "";
        }
        public static string DirOf(string stemLower) { int slash = stemLower.LastIndexOf('/'); return slash > 0 ? stemLower.Substring(0, slash + 1) : "/"; }
        // U.pctDecode
        public static string PctDecode(string s, bool plus, out bool err)
        {
            err = false;
            if (s == null || s == "-") return "";
            if (s.IndexOf('%') < 0) return plus ? s.Replace('+', ' ') : s;
            var bytes = new List<int>(); var outb = new StringBuilder(); int n = s.Length;
            bool e = false;
            Action flush = () =>
            {
                if (bytes.Count == 0) return;
                string r = Utf8(bytes); if (r == null) { e = true; r = Latin(bytes); }
                outb.Append(r); bytes.Clear();
            };
            for (int i = 0; i < n; i++)
            {
                int c = s[i];
                if (c == 37 && i + 2 < n)
                {
                    int h1 = Js.HexVal(s[i + 1]), h2 = Js.HexVal(s[i + 2]);
                    if (h1 >= 0 && h2 >= 0) { bytes.Add(h1 * 16 + h2); i += 2; continue; }
                    if (s[i + 1] == 'u' || s[i + 1] == 'U') e = true;
                }
                else if (c == 37) e = true;
                flush();
                outb.Append(plus && c == 43 ? ' ' : s[i]);
            }
            flush();
            err = e;
            return outb.ToString();
        }
        static string Latin(List<int> b) { var sb = new StringBuilder(); foreach (int x in b) sb.Append((char)x); return sb.ToString(); }
        public static string Utf8(List<int> b)
        {
            var s = new StringBuilder(); int i = 0;
            while (i < b.Count)
            {
                int c = b[i];
                if (c < 0x80) { s.Append((char)c); i++; continue; }
                if (c >= 0xC2 && c < 0xE0)
                {
                    if (i + 1 >= b.Count || (b[i + 1] & 0xC0) != 0x80) return null;
                    s.Append((char)(((c & 0x1F) << 6) | (b[i + 1] & 0x3F))); i += 2; continue;
                }
                if (c >= 0xE0 && c < 0xF0)
                {
                    if (i + 2 >= b.Count || (b[i + 1] & 0xC0) != 0x80 || (b[i + 2] & 0xC0) != 0x80) return null;
                    int cp = ((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F);
                    if (cp < 0x800) return null;
                    s.Append((char)cp); i += 3; continue;
                }
                if (c >= 0xF0 && c < 0xF5)
                {
                    if (i + 3 >= b.Count || (b[i + 1] & 0xC0) != 0x80 || (b[i + 2] & 0xC0) != 0x80 || (b[i + 3] & 0xC0) != 0x80) return null;
                    int cp = ((c & 0x07) << 18) | ((b[i + 1] & 0x3F) << 12) | ((b[i + 2] & 0x3F) << 6) | (b[i + 3] & 0x3F);
                    if (cp < 0x10000 || cp > 0x10FFFF) return null;
                    cp -= 0x10000;
                    s.Append((char)(0xD800 + (cp >> 10))).Append((char)(0xDC00 + (cp & 0x3FF))); i += 4; continue;
                }
                return null;
            }
            return s.ToString();
        }
        // U.entropy: integer-like keys ('0'..'9') are summed first in ascending order, then other characters
        // in first-seen order, matching JavaScript object key enumeration.
        public static double Entropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var counts = new Dictionary<char, int>(); var order = new List<char>();
            foreach (char c in s) { int v; if (counts.TryGetValue(c, out v)) counts[c] = v + 1; else { counts[c] = 1; order.Add(c); } }
            double h = 0, n = s.Length;
            for (char d = '0'; d <= '9'; d++) { int v; if (counts.TryGetValue(d, out v)) { double p = v / n; h -= p * Math.Log(p) / Math.Log(2); } }
            foreach (char c in order) { if (c >= '0' && c <= '9') continue; double p = counts[c] / n; h -= p * Math.Log(p) / Math.Log(2); }
            return h;
        }
    }

    // Windows-1252 <-> bytes and UTF-8 re-decoding of a line (U.fixUtf8).
    public static class Cp1252
    {
        static readonly int[] High = { 0x20AC, 0x81, 0x201A, 0x192, 0x201E, 0x2026, 0x2020, 0x2021, 0x2C6, 0x2030, 0x160, 0x2039, 0x152, 0x8D, 0x17D, 0x8F,
            0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x2DC, 0x2122, 0x161, 0x203A, 0x153, 0x9D, 0x17E, 0x178 };
        static readonly Dictionary<int, int> Rev = new Dictionary<int, int>();
        static Cp1252() { for (int i = 0; i < 32; i++) Rev[High[i]] = 0x80 + i; }
        public static string FixUtf8(string line)
        {
            var bytes = new List<int>(line.Length);
            foreach (char ch in line)
            {
                int c = ch, b;
                if (c < 0x80 || (c >= 0xA0 && c <= 0xFF)) b = c; else if (!Rev.TryGetValue(c, out b)) return line;
                bytes.Add(b);
            }
            string s = TextUtil.Utf8(bytes);
            return s ?? line;
        }
    }

    // ---------------------------------------------------------------- derived attributes (P.Deriver)
    public sealed class Matcher
    {
        readonly List<string> subs = new List<string>(); readonly List<Regex> globs = new List<Regex>(), res = new List<Regex>(); readonly List<string[]> starGlobs = new List<string[]>(); readonly List<Regex> starGlobRx = new List<Regex>();
        public bool Empty { get { return subs.Count == 0 && globs.Count == 0 && res.Count == 0 && starGlobs.Count == 0; } }
        static bool HasLineTerm(string s) { for (int i = 0; i < s.Length; i++) { char c = s[i]; if (c == '\n' || c == '\r' || c == '\u2028' || c == '\u2029') return true; } return false; }
        static bool StarMatch(string[] segs, string l)
        {
            int n = segs.Length, pos = 0;
            if (n == 1) return l == segs[0];
            if (!l.StartsWith(segs[0], StringComparison.Ordinal)) return false;
            pos = segs[0].Length;
            int endLimit = l.Length - segs[n - 1].Length;
            if (endLimit < pos || !l.EndsWith(segs[n - 1], StringComparison.Ordinal)) return false;
            for (int i = 1; i < n - 1; i++)
            {
                if (segs[i].Length == 0) continue;
                int at = l.IndexOf(segs[i], pos, StringComparison.Ordinal);
                if (at < 0 || at + segs[i].Length > endLimit) return false;
                pos = at + segs[i].Length;
            }
            return true;
        }
        // s may be mixed case
        public bool Test(string s) { if (Empty) return false; return TestImpl(subs.Count + globs.Count > 0 ? Js.Lower(s) : s, s); }
        // dl = lower-cased s (substring/glob parts), s = original (re: parts with IgnoreCase)
        public bool TestImplMixed(string dl, string s) { if (Empty) return false; return TestImpl(dl, s); }
        // lower must already be lower-case
        public bool TestLower(string lower) { if (Empty) return false; return TestImpl(lower, lower); }
        bool TestImpl(string l, string s)
        {
            for (int i = 0; i < subs.Count; i++) if (l.IndexOf(subs[i], StringComparison.Ordinal) >= 0) return true;
            if (starGlobs.Count > 0)
            {
                bool term = HasLineTerm(l);
                for (int i = 0; i < starGlobs.Count; i++) if (term ? starGlobRx[i].IsMatch(l) : StarMatch(starGlobs[i], l)) return true;
            }
            for (int i = 0; i < globs.Count; i++) if (globs[i].IsMatch(l)) return true;
            for (int i = 0; i < res.Count; i++) if (res[i].IsMatch(s)) return true;
            return false;
        }
        public static Matcher Build(List<object> entries)
        {
            var m = new Matcher();
            if (entries != null)
                foreach (object o in entries)
                {
                    string e = o as string;
                    if (string.IsNullOrEmpty(e)) continue;
                    if (e.StartsWith("re:", StringComparison.Ordinal)) m.res.Add(JsRegex.Make(e.Substring(3), true));
                    else if (e.IndexOf('?') < 0 && e.IndexOf('*') >= 0) { string g = Js.Lower(e); m.starGlobs.Add(g.Split('*')); m.starGlobRx.Add(JsRegex.Make(TextUtil.GlobToRegexSrc(g), false)); }
                    else if (e.IndexOf('*') >= 0 || e.IndexOf('?') >= 0) m.globs.Add(JsRegex.Make(TextUtil.GlobToRegexSrc(Js.Lower(e)), false));
                    else m.subs.Add(Js.Lower(e));
                }
            return m;
        }
    }
    public sealed class StemInfo { public string key, dec, ext, dir, b; public bool decErr, exec, stat, ws005, sens, probe, exPath, trav, cmdi, exp001, shellName, upDir, dlEp, loginEp, pubDl, exf, exfHigh, lng, dotnetProbe, axd, svc, php, dotnet; }
    public sealed class QueryInfo { public bool empty, decErr, exp001, trav, cmdi, phpinfo, shellParam, highEnt, lng, versionOnly, hasD, wsdl; public string dec, lower; public int len, sqli; public double ent = double.NaN; }
    public sealed class UaInfo { public string dec, fam; public bool scanner, shellUa, empty; }

    public sealed class Deriver
    {
        public static Dictionary<string, long> RxTicks = new Dictionary<string, long>(); public static Dictionary<string, long> RxCount = new Dictionary<string, long>();
        static bool T(string name, Regex re, string s)
        {
            if (!ScanEngine.Profile) return re.IsMatch(s);
            long a = System.Diagnostics.Stopwatch.GetTimestamp(); bool r = re.IsMatch(s); long d = System.Diagnostics.Stopwatch.GetTimestamp() - a;
            long v; RxTicks.TryGetValue(name, out v); RxTicks[name] = v + d; RxCount.TryGetValue(name, out v); RxCount[name] = v + 1; return r;
        }
        static bool TM(string name, Matcher m, string s)
        {
            if (!ScanEngine.Profile) return m.TestLower(s);
            long a = System.Diagnostics.Stopwatch.GetTimestamp(); bool r = m.TestLower(s); long d = System.Diagnostics.Stopwatch.GetTimestamp() - a;
            long v; RxTicks.TryGetValue(name, out v); RxTicks[name] = v + d; RxCount.TryGetValue(name, out v); RxCount[name] = v + 1; return r;
        }
        HashSet<string> execExt, staticExt, ws005Ext, exfExt, exfHigh; List<string> probeExt;
        Matcher sens, scanUa, loginEp, exPath, upDirs, dlEp, pubDl, shellName, shellParam, dotnetProbe;
        Regex reTrav, reExp001, reSqliHigh, reSqliMed, reCmdi, rePhpinfo, reVersionOnly, reHasD, reWsdl, reAxd, reSvc, reShellUa, rePhp, reDotnet;
        List<KeyValuePair<string, Regex>> uaFamilies = new List<KeyValuePair<string, Regex>>();
        Dictionary<string, StemInfo> sc = new Dictionary<string, StemInfo>(StringComparer.Ordinal);
        Dictionary<string, QueryInfo> qc = new Dictionary<string, QueryInfo>(StringComparer.Ordinal);
        Dictionary<string, UaInfo> uc = new Dictionary<string, UaInfo>(StringComparer.Ordinal);
        Dictionary<string, string> ic = new Dictionary<string, string>(StringComparer.Ordinal);
        static HashSet<string> ExtSet(List<object> l)
        {
            var m = new HashSet<string>(StringComparer.Ordinal);
            if (l != null) foreach (object o in l) { string e = Js.Lower((string)o); if (e.Length == 0 || e[0] != '.') e = "." + e; m.Add(e); }
            return m;
        }
        // All P.RE patterns are applied to lower-cased text, so IgnoreCase can be dropped when the pattern is all lower-case.
        static Regex R(Dictionary<string, object> res, string name)
        {
            var d = (Dictionary<string, object>)res[name]; string src = (string)d["src"];
            bool ic = ((string)d["flags"]).IndexOf('i') >= 0;
            return JsRegex.Make(src, ic && JsRegex.HasUpperLiteral(src));
        }
        static List<object> L(Dictionary<string, object> lists, string k, string[] def)
        {
            object v; if (lists.TryGetValue(k, out v) && v != null) return (List<object>)v;
            if (def == null) return null;
            var o = new List<object>(); foreach (var s in def) o.Add(s); return o;
        }
        public Deriver(Dictionary<string, object> lists, Dictionary<string, object> res, List<object> uaFam)
        {
            execExt = ExtSet(L(lists, "executable-extensions", new[] { ".aspx", ".ashx", ".asmx", ".asp", ".axd", ".svc", ".cshtml", ".vbhtml", ".soap", ".rem", ".php", ".jsp", ".jspx", ".cfm", ".cgi", ".pl", ".py" }));
            staticExt = ExtSet(L(lists, "static-extensions", new[] { ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map", ".htm", ".html", ".txt", ".xml", ".json", ".bmp", ".webp" }));
            ws005Ext = ExtSet(L(lists, "static-abuse-extensions", new[] { ".jpg", ".jpeg", ".gif", ".png", ".txt", ".css", ".ico", ".svg", ".xml", ".config", ".log" }));
            probeExt = new List<string>(); foreach (object o in L(lists, "probe-extensions", new[] { ".bak", ".old", ".orig", ".swp", ".save", ".tmp", ".sql", ".zip", ".tar.gz", ".tgz", ".7z", ".rar", "~", ".backup", ".copy" })) probeExt.Add((string)o);
            sens = Matcher.Build(L(lists, "sensitive-paths", null)); scanUa = Matcher.Build(L(lists, "scanner-user-agents", null));
            loginEp = Matcher.Build(L(lists, "login-endpoints", null)); exPath = Matcher.Build(L(lists, "known-exploit-paths", null));
            upDirs = Matcher.Build(L(lists, "upload-directories", null)); dlEp = Matcher.Build(L(lists, "download-endpoints", null));
            pubDl = Matcher.Build(L(lists, "public-download-directories", null));
            exfExt = ExtSet(L(lists, "exfil-extensions", null)); exfHigh = ExtSet(L(lists, "exfil-high-extensions", null));
            shellName = Matcher.Build(L(lists, "webshell-names", null)); shellParam = Matcher.Build(L(lists, "webshell-parameters", null));
            dotnetProbe = Matcher.Build(L(lists, "dotnet-probe-paths", null));
            reTrav = R(res, "trav"); reExp001 = R(res, "exp001"); reSqliHigh = R(res, "sqliHigh"); reSqliMed = R(res, "sqliMed"); reCmdi = R(res, "cmdi");
            rePhpinfo = R(res, "phpinfo"); reVersionOnly = R(res, "versionOnly"); reHasD = R(res, "hasD"); reWsdl = R(res, "wsdl"); reAxd = R(res, "axd");
            reSvc = R(res, "svc"); reShellUa = R(res, "shellUa"); rePhp = R(res, "php"); reDotnet = R(res, "dotnet");
            foreach (object o in uaFam) { var a = (List<object>)o; string src = (string)a[1]; uaFamilies.Add(new KeyValuePair<string, Regex>((string)a[0], JsRegex.Make(src, ((string)a[2]).IndexOf('i') >= 0 && JsRegex.HasUpperLiteral(src)))); }
        }
        bool EndsWithAny(string s) { foreach (var p in probeExt) if (s.EndsWith(p, StringComparison.Ordinal)) return true; return false; }
        public StemInfo Stem(string raw)
        {
            StemInfo v; if (sc.TryGetValue(raw, out v)) return v;
            if (sc.Count > 150000) sc.Clear();
            bool de; string key = Js.Lower(raw), dec = Js.Lower(TextUtil.PctDecode(raw, false, out de));
            v = new StemInfo { key = key, dec = dec, ext = TextUtil.ExtOf(dec), dir = TextUtil.DirOf(dec), decErr = de };
            v.b = dec.Substring(dec.LastIndexOf('/') + 1);
            v.exec = execExt.Contains(v.ext); v.stat = staticExt.Contains(v.ext); v.ws005 = ws005Ext.Contains(v.ext);
            v.sens = TM("m.sens", sens, dec); v.probe = EndsWithAny(dec); v.exPath = TM("m.exPath", exPath, dec);
            v.trav = T("trav", reTrav, key) || T("trav", reTrav, dec); v.cmdi = T("cmdi", reCmdi, dec); v.exp001 = T("exp001", reExp001, key);
            v.shellName = TM("m.shellName", shellName, v.b); v.upDir = TM("m.upDirs", upDirs, v.dir); v.dlEp = TM("m.dlEp", dlEp, dec); v.loginEp = TM("m.loginEp", loginEp, dec);
            v.pubDl = TM("m.pubDl", pubDl, v.dir); v.exf = exfExt.Contains(v.ext); v.exfHigh = exfHigh.Contains(v.ext); v.lng = raw.Length >= 1024;
            v.dotnetProbe = TM("m.dotnetProbe", dotnetProbe, dec); v.axd = T("axd", reAxd, dec); v.svc = T("svc", reSvc, dec); v.php = T("php", rePhp, dec); v.dotnet = T("dotnet", reDotnet, dec);
            sc[raw] = v; return v;
        }
        public QueryInfo Query(string raw)
        {
            QueryInfo v; if (qc.TryGetValue(raw, out v)) return v;
            if (qc.Count > 150000) qc.Clear();
            if (raw == "-" || raw.Length == 0) v = new QueryInfo { empty = true, dec = "", lower = "" };
            else
            {
                bool de; string d = TextUtil.PctDecode(raw, true, out de), lower = Js.Lower(d), rl = Js.Lower(raw);
                int sq = 0;
                if (T("sqliHigh", reSqliHigh, lower)) sq = 2; else { long a = System.Diagnostics.Stopwatch.GetTimestamp(); if (reSqliMed.Matches(lower).Count >= 2) sq = 1; if (ScanEngine.Profile) { long v0; RxTicks.TryGetValue("sqliMed", out v0); RxTicks["sqliMed"] = v0 + System.Diagnostics.Stopwatch.GetTimestamp() - a; } }
                v = new QueryInfo { dec = d, lower = lower, len = raw.Length, decErr = de, sqli = sq };
                v.exp001 = T("exp001", reExp001, rl) || T("exp001", reExp001, lower); v.trav = T("trav", reTrav, rl) || T("trav", reTrav, lower);
                v.cmdi = T("cmdi", reCmdi, lower); v.phpinfo = T("phpinfo", rePhpinfo, lower); v.shellParam = TM("m.shellParam", shellParam, lower);
                v.highEnt = raw.Length >= 200 && TextUtil.Entropy(raw) >= 5.5; v.lng = raw.Length >= 2048; v.versionOnly = T("versionOnly", reVersionOnly, lower);
                v.hasD = T("hasD", reHasD, lower); v.wsdl = T("wsdl", reWsdl, lower);
            }
            qc[raw] = v; return v;
        }
        public UaInfo Ua(string raw)
        {
            UaInfo v; if (uc.TryGetValue(raw, out v)) return v;
            if (uc.Count > 100000) uc.Clear();
            string dec = raw == "-" ? "" : raw.Replace('+', ' '), dl = Js.Lower(dec);
            bool scanner = TM("m.scanUa", scanUa, dl), shell = T("shellUa", reShellUa, dl); string fam = "other";
            if (dec.Length == 0) fam = "empty"; else if (shell) fam = "webshell-client"; else if (scanner) fam = "scanner";
            else foreach (var f in uaFamilies) if (T("uafam:" + f.Key, f.Value, dl)) { fam = f.Key; break; }
            v = new UaInfo { dec = dec, fam = fam, scanner = scanner, shellUa = shell, empty = dec.Length == 0 };
            uc[raw] = v; return v;
        }
        public string IpClass(string ip)
        {
            string v; if (ic.TryGetValue(ip, out v)) return v;
            if (ic.Count > 200000) ic.Clear();
            v = IpUtil.Classify(ip); ic[ip] = v; return v;
        }
    }

    // ---------------------------------------------------------------- row + W3C parser (P.FileParser)
    // Field slots resolved once from the job's key lists (FileParser.StringKeys / NumKeys).
    public static class F
    {
        public static int date, time, sip, method, stem, query, user, cip, ua, xff, xreal, uri, status, sub, port, win32, taken, scBytes;
    }
    public sealed class Row
    {
        public string[] S; public double[] N;
        public double ts; public string raw = ""; public int lineNo, fileId, blockId; public string reason2 = ""; public bool nonAscii; public string eip = "-";
        public int code; public StemInfo si; public QueryInfo qi; public UaInfo ui; public string cls;
        public Row(int ns, int nn) { S = new string[ns]; N = new double[nn]; }
        public void CopyFrom(Row o)
        {
            Array.Copy(o.S, S, S.Length); Array.Copy(o.N, N, N.Length);
            ts = o.ts; raw = o.raw; lineNo = o.lineNo; fileId = o.fileId; blockId = o.blockId; reason2 = o.reason2; nonAscii = o.nonAscii; eip = o.eip;
        }
        public string Method { get { return S[F.method]; } }
        public string Stem { get { return S[F.stem]; } }
        public string Query { get { return S[F.query]; } }
        public string User { get { return S[F.user]; } }
        public string Ua { get { return S[F.ua]; } }
        public string Sip { get { return S[F.sip]; } }
        public string Date { get { return S[F.date]; } }
        public string Time { get { return S[F.time]; } }
        public double Status { get { return N[F.status]; } }
        public double Sub { get { return N[F.sub]; } }
        public double Port { get { return N[F.port]; } }
        public double Win32 { get { return N[F.win32]; } }
        public double Taken { get { return N[F.taken]; } }
        public double ScBytes { get { return N[F.scBytes]; } }
    }
    public sealed class Block { public double line; public string software, version, date, fields; public double dateTs; public bool assumed; public int schema; }

    public sealed class FileParser
    {
        public static Dictionary<string, string> FieldMap; public static HashSet<string> Numeric; public static string[] StringKeys, NumKeys, DefaultFields;
        public int fileId, lineNo; public List<string> keys; public int nf; int[] kind, slot; static Dictionary<string, int> sIx, nIx; public List<Block> blocks = new List<Block>();
        public string software = "", version = "", dateDir = ""; public bool seenContent, notW3C, splitUri, hasDate; int dIdx, tIdx;
        public FileParser(int fileId) { this.fileId = fileId; }
        public static void InitSlots()
        {
            sIx = new Dictionary<string, int>(StringComparer.Ordinal); nIx = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < StringKeys.Length; i++) sIx[StringKeys[i]] = i;
            for (int i = 0; i < NumKeys.Length; i++) nIx[NumKeys[i]] = i;
            F.date = sIx["date"]; F.time = sIx["time"]; F.sip = sIx["sip"]; F.method = sIx["method"]; F.stem = sIx["stem"]; F.query = sIx["query"];
            F.user = sIx["user"]; F.cip = sIx["cip"]; F.ua = sIx["ua"]; F.xff = sIx["xff"]; F.xreal = sIx["xrealip"]; F.uri = sIx["uri"];
            F.status = nIx["status"]; F.sub = nIx["sub"]; F.port = nIx["port"]; F.win32 = nIx["win32"]; F.taken = nIx["taken"]; F.scBytes = nIx["scBytes"];
        }
        public static Row NewRow() { var r = new Row(StringKeys.Length, NumKeys.Length); Reset(r); return r; }
        public static void Reset(Row r)
        {
            for (int i = 0; i < r.S.Length; i++) r.S[i] = "-";
            for (int i = 0; i < r.N.Length; i++) r.N[i] = -1;
            r.ts = 0; r.raw = ""; r.lineNo = 0; r.fileId = 0; r.blockId = 0; r.reason2 = ""; r.nonAscii = false; r.eip = "-";
        }
        [ThreadStatic] static string lastDayS; [ThreadStatic] static double lastDayV;
        static double DayMs(string d)
        {
            if (d == lastDayS && d != null) return lastDayV;
            double v = DayMsRaw(d); lastDayS = d; lastDayV = v; return v;
        }
        static bool IsDigits(string s, int a, int b) { for (int i = a; i < b; i++) { char c = s[i]; if (c < '0' || c > '9') return false; } return true; }
        static readonly int[] MDays = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        // Strict YYYY-MM-DD (mirrors parser.js dayMs): impossible dates are rejected instead of being rolled over by Date.UTC.
        static double DayMsRaw(string d)
        {
            if (d.Length != 10 || d[4] != '-' || d[7] != '-' || !IsDigits(d, 0, 4) || !IsDigits(d, 5, 7) || !IsDigits(d, 8, 10)) return double.NaN;
            int y = (d[0] - 48) * 1000 + (d[1] - 48) * 100 + (d[2] - 48) * 10 + (d[3] - 48), m = (d[5] - 48) * 10 + (d[6] - 48), dd = (d[8] - 48) * 10 + (d[9] - 48);
            bool leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            if (y < 100 || m < 1 || m > 12 || dd < 1 || dd > ((m == 2 && leap) ? 29 : MDays[m - 1])) return double.NaN;
            return Js.DateUTC(y, m - 1, dd, 0, 0, 0, 0);
        }
        // Strict HH:MM:SS with an optional .fraction (mirrors parser.js timeMs).
        static double TimeMs(string t)
        {
            if (t.Length < 8 || t[2] != ':' || t[5] != ':' || !IsDigits(t, 0, 2) || !IsDigits(t, 3, 5) || !IsDigits(t, 6, 8)) return double.NaN;
            int h = (t[0] - 48) * 10 + (t[1] - 48), m = (t[3] - 48) * 10 + (t[4] - 48), s = (t[6] - 48) * 10 + (t[7] - 48); double frac = 0;
            if (h > 23 || m > 59 || s > 59) return double.NaN;
            if (t.Length > 8)
            {
                if (t[8] != '.' || !IsDigits(t, 9, t.Length)) return double.NaN;
                if (t.Length > 9) frac = Math.Floor(Js.ToNumber("0" + t.Substring(8)) * 1000 + 0.5);
            }
            return ((h * 60 + m) * 60 + s) * 1000.0 + frac;
        }
        public static double ParseW3cDate(string s)
        {
            if (string.IsNullOrEmpty(s)) return double.NaN;
            var parts = Js.SplitWs(Js.Trim(s));
            return DayMs(parts[0]) + (parts.Count > 1 && parts[1].Length > 0 ? TimeMs(parts[1]) : 0);
        }
        void Bind(List<string> names, Row r, bool assumed)
        {
            var ks = new List<string>(); splitUri = false;
            foreach (var n in names)
            {
                string k; if (!FieldMap.TryGetValue(Js.Lower(n), out k)) k = "x:" + n;
                if (k == "uri") splitUri = true;
                ks.Add(k);
            }
            keys = ks; nf = names.Count; hasDate = ks.IndexOf("date") >= 0; dIdx = ks.IndexOf("date"); tIdx = ks.IndexOf("time");
            kind = new int[nf]; slot = new int[nf];
            for (int i = 0; i < nf; i++)
            {
                string k = ks[i]; int ix;
                if (Numeric.Contains(k) && nIx.TryGetValue(k, out ix)) { kind[i] = 1; slot[i] = ix; }
                else if (k.Length > 1 && k[1] == ':') { kind[i] = 2; }
                else if (sIx.TryGetValue(k, out ix)) { kind[i] = 0; slot[i] = ix; }
                else kind[i] = 2;
            }
            blocks.Add(new Block { line = lineNo, software = software, version = version, date = dateDir, dateTs = ParseW3cDate(dateDir), fields = string.Join(" ", names), assumed = assumed });
            Reset(r);
        }
        // 0 = directive/blank, 1 = row, 2 = malformed
        public int Line(string line, Row r)
        {
            lineNo++;
            if (lineNo == 1 && line.StartsWith("\u00ef\u00bb\u00bf", StringComparison.Ordinal)) line = line.Substring(3);
            bool na = false; for (int i = 0; i < line.Length; i++) if (line[i] > 0x7f) { na = true; break; }
            if (na) line = Cp1252.FixUtf8(line);
            if (line.Length == 0) return 0;
            if (line[0] == '#')
            {
                seenContent = true;
                int c = line.IndexOf(':');
                string name = c > 0 ? line.Substring(1, c - 1) : line.Substring(1), val = c > 0 ? Js.Trim(line.Substring(c + 1)) : "";
                switch (name)
                {
                    case "Software": software = val; break;
                    case "Version": version = val; break;
                    case "Date": dateDir = val; break;
                    case "Fields": Bind(Js.SplitWs(val), r, false); break;
                }
                return 0;
            }
            if (!seenContent) { seenContent = true; notW3C = true; Bind(new List<string>(DefaultFields), r, true); }
            r.raw = line; r.lineNo = lineNo; r.fileId = fileId; r.blockId = blocks.Count - 1;
            r.nonAscii = na;
            if (keys == null) { r.reason2 = "unbound row (data before #Fields)"; return 2; }
            int ntok = 1; for (int i = 0; i < line.Length; i++) if (line[i] == ' ') ntok++;
            if (ntok != nf) { r.reason2 = (ntok < nf ? "short row: " : "long row: ") + ntok + " fields, expected " + nf; return 2; }
            if (starts == null || starts.Length < nf + 1) { starts = new int[nf + 1]; }
            { int f = 0; starts[0] = 0; for (int i = 0; i < line.Length; i++) if (line[i] == ' ') starts[++f] = i + 1; starts[nf] = line.Length + 1; }
            for (int i = 0; i < nf; i++)
            {
                int a = starts[i], len = starts[i + 1] - 1 - a, kd = kind[i];
                if (kd == 1)
                {
                    double x;
                    if (len == 1 && line[a] == '-') x = -1;
                    else if (len > 0 && len < 16) { long acc = 0; bool ok = true; for (int q = a; q < a + len; q++) { char ch = line[q]; if (ch < '0' || ch > '9') { ok = false; break; } acc = acc * 10 + (ch - '0'); } x = ok ? acc : Js.ToNumber(line.Substring(a, len)); }
                    else x = Js.ToNumber(line.Substring(a, len));
                    r.N[slot[i]] = double.IsNaN(x) ? -1 : x;
                }
                else if (kd == 0) r.S[slot[i]] = len == 1 && line[a] == '-' ? "-" : line.Substring(a, len);
            }
            if (splitUri)
            {
                string u = r.S[F.uri]; int q = u.IndexOf('?');
                if (q >= 0) { r.S[F.stem] = u.Substring(0, q); string qq = u.Substring(q + 1); r.S[F.query] = qq.Length > 0 ? qq : "-"; } else { r.S[F.stem] = u; r.S[F.query] = "-"; }
            }
            double ts = hasDate ? DayMs(Tok(line, dIdx)) + (tIdx >= 0 ? TimeMs(Tok(line, tIdx)) : 0) : ParseW3cDate(dateDir) + (tIdx >= 0 ? JsMod(TimeMs(Tok(line, tIdx)), 86400000) : 0);
            if (double.IsNaN(ts)) { r.reason2 = "invalid date/time"; return 2; }
            r.ts = ts;
            string xff = r.S[F.xff];
            if (xff != "-")
            {
                bool e; string dx = TextUtil.PctDecode(xff, true, out e); string eip = "-";
                foreach (var hop in SplitHops(dx)) { if (hop.Length > 0 && IpUtil.Classify(hop) == "public") { eip = hop; break; } }
                r.eip = eip == "-" ? r.S[F.cip] : eip;
            }
            else if (r.S[F.xreal] != "-") r.eip = r.S[F.xreal]; else r.eip = r.S[F.cip];
            return 1;
        }
        int[] starts;
        string Tok(string line, int i) { return line.Substring(starts[i], starts[i + 1] - 1 - starts[i]); }
        static bool AllDigits(string v) { for (int i = 0; i < v.Length; i++) if (v[i] < '0' || v[i] > '9') return false; return true; }
        static double JsMod(double a, double b) { if (double.IsNaN(a)) return double.NaN; return a - b * Math.Truncate(a / b); }
        static List<string> SplitHops(string s)
        {
            // s.split(/[,\s]+/)
            var o = new List<string>(); int i = 0, st = 0;
            while (i <= s.Length)
            {
                if (i == s.Length) { o.Add(s.Substring(st)); break; }
                char c = s[i];
                if (c == ',' || Js.IsWs(c)) { o.Add(s.Substring(st, i - st)); while (i < s.Length && (s[i] == ',' || Js.IsWs(s[i]))) i++; st = i; continue; }
                i++;
            }
            return o;
        }
    }

    // ---------------------------------------------------------------- rules (R.Evaluator)
    public sealed class Ctx { public Row r; public StemInfo si; public QueryInfo qi; public UaInfo ui; public string cls, ip; public bool pub, newUser; }
    public sealed class RowRule { public string id, sev; public bool exploit, grade; public Func<Ctx, string> fn; }
    public sealed class ExpWin { public double ts; public HashSet<string> stems = new HashSet<string>(StringComparer.Ordinal); }

    public sealed class Evaluator
    {
        public List<RowRule> list = new List<RowRule>();
        public Dictionary<string, ExpWin> expWin = new Dictionary<string, ExpWin>(StringComparer.Ordinal);
        public HashSet<string> users = new HashSet<string>(StringComparer.Ordinal);
        public Ctx ctx = new Ctx(); public List<string> hits = new List<string>(); public List<string> hitSev = new List<string>(); public int n;
        readonly Deriver D;
        static readonly HashSet<string> ExploitRules = new HashSet<string> { "R-EXP-001", "R-EXP-002", "R-EXP-003", "R-EXP-004", "R-EXP-005", "R-EXP-006" };
        static double P(Dictionary<string, object> p, string k, double d) { object v; return p.TryGetValue(k, out v) && v is double ? (double)v : d; }
        static HashSet<double> NumSet(Dictionary<string, object> p, string k, double[] def)
        {
            var s = new HashSet<double>(); object v;
            if (p.TryGetValue(k, out v) && v is List<object>) { foreach (object o in (List<object>)v) { double d = o is double ? (double)o : Js.ToNumber(Convert.ToString(o, CultureInfo.InvariantCulture)); if (!double.IsNaN(d)) s.Add(d == 0 ? 0 : d); } }
            else if (def != null) foreach (double d in def) s.Add(d);
            return s;
        }
        public Evaluator(List<object> rules, Deriver d, HashSet<string> validMethods)
        {
            D = d;
            foreach (object o in rules)
            {
                var r = (Dictionary<string, object>)o;
                object en; if (!r.TryGetValue("enabled", out en) || !(en is bool) || !(bool)en) continue;
                object sc; if (!r.TryGetValue("scope", out sc) || (string)sc != "row") continue;
                string id = (string)r["id"];
                object pv; var p = r.TryGetValue("params", out pv) && pv is Dictionary<string, object> ? (Dictionary<string, object>)pv : new Dictionary<string, object>();
                Func<Ctx, string> fn = Builtin(id, p, validMethods);
                object mv;
                if (fn == null && r.TryGetValue("match", out mv) && mv is Dictionary<string, object>) fn = CompileMatch((Dictionary<string, object>)mv);
                if (fn == null) continue;
                object gb; bool grade = p.TryGetValue("gradeByStatus", out gb) && gb is bool && (bool)gb;
                list.Add(new RowRule { id = id, sev = (string)r["severity"], fn = fn, exploit = ExploitRules.Contains(id), grade = grade });
            }
        }
        const string T = "\u0001true"; // marker: rule matched with its default severity
        Func<Ctx, string> Builtin(string id, Dictionary<string, object> p, HashSet<string> valid)
        {
            switch (id)
            {
                case "R-SCAN-002": return c => c.si.sens ? (c.r.Status == 200 && c.pub ? "high" : T) : (c.si.probe && c.r.Status == 404 ? T : null);
                case "R-SCAN-003":
                    {
                        object ei; bool exInt = p.TryGetValue("excludeInternal", out ei) && ei is bool && (bool)ei;
                        object eu; bool emptyPub = p.TryGetValue("emptyUaFromPublic", out eu) && eu is bool && (bool)eu;
                        return c => (c.ui.scanner && !(exInt && IpUtil.IsInternalClass(c.cls))) || (emptyPub && c.ui.empty && c.pub) ? T : null;
                    }
                case "R-SCAN-004": return c => !valid.Contains(Js.Upper(c.r.Method)) || c.r.Status == 405 || c.r.Status == 501 ? T : null;
                case "R-SCAN-005": { var sub = NumSet(p, "substatus", null); return c => c.r.Status == 404 && sub.Contains(c.r.Sub) ? T : null; }
                case "R-SCAN-006": { var sub = NumSet(p, "substatus", null); return c => c.r.Status == 403 && sub.Contains(c.r.Sub) ? T : null; }
                case "R-SCAN-008": return c => c.pub && c.qi.phpinfo ? T : null;
                case "R-EXP-001": return c => c.qi.exp001 || c.si.exp001 ? T : null;
                case "R-EXP-002": return c => c.si.trav || c.qi.trav ? T : null;
                case "R-EXP-003":
                    {
                        object im; bool incMed = p.TryGetValue("includeMedium", out im) && im is bool && (bool)im;
                        return c => c.qi.sqli == 2 ? T : (incMed && c.qi.sqli == 1 ? "medium" : null);
                    }
                case "R-EXP-004": return c => c.qi.cmdi || c.si.cmdi ? T : null;
                case "R-EXP-005": return c => c.si.dotnetProbe || (c.si.axd && c.qi.hasD && c.r.Status == 500) || (c.si.svc && c.qi.wsdl && c.r.Status == 500) ? T : null;
                case "R-EXP-006": { var esc = NumSet(p, "escalateStatuses", new double[] { 200, 500 }); return c => c.si.exPath ? (esc.Contains(c.r.Status) ? "high" : T) : null; }
                case "R-EXP-007":
                    {
                        double win = P(p, "windowMinutes", 10); if (win == 0) win = 10;
                        return c =>
                        {
                            if (c.r.Status != 500) return null;
                            ExpWin w; return expWin.TryGetValue(c.ip, out w) && c.r.ts - w.ts <= win * 60000 && w.stems.Contains(c.si.key) ? T : null;
                        };
                    }
                case "R-EXP-008":
                    {
                        double stemLen = P(p, "stemLen", 1024), queryLen = P(p, "queryLen", 2048), entropy = P(p, "entropy", 5.5), entMin = P(p, "entropyMinLen", 200);
                        if (stemLen == 0) stemLen = 1024; if (queryLen == 0) queryLen = 2048; if (entropy == 0) entropy = 5.5; if (entMin == 0) entMin = 200;
                        return c =>
                        {
                            if (c.r.Stem.Length >= stemLen || c.qi.len >= queryLen) return T;
                            if (c.qi.len >= entMin) { if (double.IsNaN(c.qi.ent)) c.qi.ent = TextUtil.Entropy(c.r.Query); return c.qi.ent >= entropy ? T : null; }
                            return null;
                        };
                    }
                case "R-EXP-009":
                    {
                        var st = NumSet(p, "statuses", new double[] { 400, 413, 414, 431 }); var w32 = NumSet(p, "win32", new double[] { 1236, 995 });
                        return c => (c.pub && st.Contains(c.r.Status)) || (w32.Contains(c.r.Win32) && c.r.Method == "POST" && c.si.exec) ? T : null;
                    }
                case "R-WS-004": return c => c.si.shellName || c.qi.shellParam || c.ui.shellUa ? T : null;
                case "R-WS-005": return c => c.si.ws005 && c.pub && c.r.Status == 200 && (c.r.Method == "POST" || (!c.qi.empty && !c.qi.versionOnly)) ? T : null;
                case "R-AUTH-003":
                    {
                        object nv; string names = p.TryGetValue("names", out nv) && nv is string && ((string)nv).Length > 0 ? (string)nv : "re:^admin$";
                        var m = Matcher.Build(new List<object> { names });
                        return c => { string u = c.r.User; if (u == "-" || u.Length == 0) return null; return c.newUser || c.pub || m.Test(u) ? T : null; };
                    }
                case "R-EXF-001": return c => { if (!(c.pub && c.r.Method == "GET" && c.r.Status == 200 && c.si.exf && !c.si.pubDl)) return null; return c.si.exfHigh ? "high" : T; };
                case "R-EXF-002":
                    {
                        double bytes = P(p, "bytes", 52428800), taken = P(p, "takenMs", 60000); if (bytes == 0) bytes = 52428800; if (taken == 0) taken = 60000;
                        return c => c.pub && c.r.Status == 200 && ((c.r.ScBytes >= bytes) || c.r.Taken >= taken) ? T : null;
                    }
                case "R-EXF-003": return c => c.pub && c.si.dlEp ? T : null;
            }
            return null;
        }
        // R.compileMatch for custom JSON rules
        static Func<Ctx, bool> StrCond(object spec, Func<Ctx, string> get)
        {
            if (spec == null) return null;
            Dictionary<string, object> d = spec as Dictionary<string, object>;
            if (spec is string) d = new Dictionary<string, object> { { "contains", spec } };
            if (d == null) return null;
            Regex re = null; object v;
            if (d.TryGetValue("regex", out v) && v is string && ((string)v).Length > 0) re = JsRegex.Make((string)v, true);
            else if (d.TryGetValue("glob", out v) && v is string && ((string)v).Length > 0) re = JsRegex.Make(TextUtil.GlobToRegexSrc((string)v), true);
            else if (d.TryGetValue("contains", out v) && v is string && ((string)v).Length > 0) re = JsRegex.Make(TextUtil.ReEscape((string)v), true);
            else if (d.TryGetValue("equals", out v) && v is string && ((string)v).Length > 0) re = JsRegex.Make("^" + TextUtil.ReEscape((string)v) + "$", true);
            if (re == null) return null;
            return c => re.IsMatch(get(c));
        }
        static Func<Ctx, bool> ListCond(object arr, Func<Ctx, string> get, bool upper)
        {
            var l = arr as List<object>; if (l == null) return null;
            var m = new HashSet<string>(StringComparer.Ordinal);
            foreach (object o in l) { string s = o is double ? Js.NumStr((double)o) : Convert.ToString(o, CultureInfo.InvariantCulture); m.Add(upper ? Js.Upper(s) : s); }
            return c => m.Contains(get(c));
        }
        static Func<Ctx, string> CompileMatch(Dictionary<string, object> match)
        {
            var conds = new List<Func<Ctx, bool>>(); object v; Func<Ctx, bool> f;
            Action<Func<Ctx, bool>> add = x => { if (x != null) conds.Add(x); };
            match.TryGetValue("method", out v); add(ListCond(v, c => Js.Upper(c.r.Method), true));
            match.TryGetValue("stem", out v); add(StrCond(v, c => c.si.dec));
            match.TryGetValue("query", out v); add(StrCond(v, c => c.qi.dec));
            match.TryGetValue("ua", out v); add(StrCond(v, c => c.ui.dec));
            match.TryGetValue("user", out v); add(StrCond(v, c => c.r.User));
            match.TryGetValue("raw", out v); add(StrCond(v, c => c.r.raw));
            match.TryGetValue("ipClass", out v); add(ListCond(v, c => c.cls, false));
            match.TryGetValue("uaFamily", out v); add(ListCond(v, c => c.ui.fam, false));
            match.TryGetValue("ext", out v); add(ListCond(v, c => c.si.ext, false));
            if (match.TryGetValue("status", out v) && v != null)
            {
                var st = new List<string>();
                if (v is List<object>) foreach (object o in (List<object>)v) st.Add(o is double ? Js.NumStr((double)o) : Convert.ToString(o, CultureInfo.InvariantCulture));
                else st.Add(v is double ? Js.NumStr((double)v) : Convert.ToString(v, CultureInfo.InvariantCulture));
                conds.Add(c =>
                {
                    double s = c.r.Status;
                    foreach (string e in st)
                    {
                        if (Regex.IsMatch(e, "^[0-9]xx$", RegexOptions.IgnoreCase)) { if (Math.Floor(s / 100) == Js.ToNumber(e.Substring(0, 1))) return true; }
                        else if (e.IndexOf('.') > 0) { if (Js.NumStr(s) + "." + Js.NumStr(c.r.Sub) == e) return true; }
                        else if (s == Js.ToNumber(e)) return true;
                    }
                    return false;
                });
            }
            if (match.TryGetValue("cip", out v) && v != null)
            {
                var cs = new List<Cidr>(); var src = v is List<object> ? (List<object>)v : new List<object> { v };
                foreach (object o in src) { var cd = IpUtil.ParseCidr(Convert.ToString(o, CultureInfo.InvariantCulture)); if (cd != null) cs.Add(cd); }
                conds.Add(c => { foreach (var cd in cs) if (IpUtil.CidrMatch(cd, c.ip)) return true; return false; });
            }
            if (match.TryGetValue("minTaken", out v) && v is double) { double mt = (double)v; conds.Add(c => c.r.Taken >= mt); }
            if (match.TryGetValue("exec", out v) && v != null) { bool ex = v is bool ? (bool)v : (v is double ? (double)v != 0 : v is string && ((string)v).Length > 0); conds.Add(c => c.si.exec == ex); }
            if (conds.Count == 0) return c => null;
            f = c => { foreach (var x in conds) if (!x(c)) return false; return true; };
            return c => f(c) ? T : null;
        }
        string lStem, lQuery, lUa, lIp, lCls; StemInfo lSi; QueryInfo lQi; UaInfo lUi;
        // Producer-side derivation with previous-value reuse (pure functions of the value).
        public void Derive(Row r)
        {
            string sv = r.Stem, qv = r.Query, uv = r.Ua, iv = r.eip;
            if (sv != lStem) { lStem = sv; lSi = D.Stem(sv); } r.si = lSi;
            if (qv != lQuery) { lQuery = qv; lQi = D.Query(qv); } r.qi = lQi;
            if (uv != lUa) { lUa = uv; lUi = D.Ua(uv); } r.ui = lUi;
            if (iv != lIp) { lIp = iv; lCls = D.IpClass(iv); } r.cls = lCls;
        }
        public int Evaluate(Row r)
        {
            var c = ctx; c.r = r; c.ip = r.eip; c.si = r.si; c.qi = r.qi; c.ui = r.ui; c.cls = r.cls;
            c.pub = c.cls == "public"; c.newUser = false;
            string u = r.User;
            if (u != "-" && u.Length > 0 && !users.Contains(u)) { users.Add(u); c.newUser = true; }
            hits.Clear(); hitSev.Clear(); n = 0; bool anyExp = false;
            foreach (var rule in list)
            {
                string res = rule.fn(c);
                if (res != null) { string sv = res == T ? rule.sev : res; if (rule.grade) sv = GradeSev(sv, r.Status); hits.Add(rule.id); hitSev.Add(sv); n++; if (rule.exploit) anyExp = true; }
            }
            if (anyExp)
            {
                ExpWin w;
                if (!expWin.TryGetValue(c.ip, out w) || r.ts - w.ts > 600000) { w = new ExpWin { ts = r.ts }; expWin[c.ip] = w; }
                w.ts = r.ts; w.stems.Add(c.si.key);
            }
            return n;
        }
        static readonly Dictionary<string, int> Sev = new Dictionary<string, int> { { "critical", 5 }, { "high", 4 }, { "medium", 3 }, { "low", 2 }, { "info", 1 } };
        public static string MaxSev(string a, string b) { int x, y; Sev.TryGetValue(a ?? "", out x); Sev.TryGetValue(b ?? "", out y); return x >= y ? a : b; }
        // Outcome grading, mirrors rules.js R.gradeSev: 2xx/5xx keep the severity, 3xx drops one level, 4xx and others drop to low.
        static readonly string[] SevOrder = { "info", "low", "medium", "high", "critical" };
        public static string GradeSev(string sev, double status)
        {
            if (!(status >= 0)) return sev;
            double c = Math.Floor(status / 100); int i = Array.IndexOf(SevOrder, sev);
            if (c == 2 || c == 5) return sev;
            if (c == 3) return i > 1 ? SevOrder[i - 1] : sev;
            return i > 1 ? "low" : sev;
        }
    }

    // ---------------------------------------------------------------- index records
    public sealed class IpRec
    {
        public double n, first, last, s2, s3, s4, s5, stOv, uaOv, exec, stat, post, dOv, php, dn, firstExp, ms5, ms5t, mlogin, mlogint, m401, m401t, a401ok, muaDay, mdl, mdlt, menum, md4;
        public int stN, uaN, dN; public string cls, muaDayD = "", menumS = "", md4d = "";
        public OMap<double> m = new OMap<double>(), st = new OMap<double>(), ua = new OMap<double>(), d = new OMap<double>(), hits = new OMap<double>(), off = new OMap<double>();
    }
    public sealed class StemRec { public double n, first, last, fFile, fLine, ipOv, pubN, post, ok, okPub, s4, s5; public int ipN; public string fIp, raw; public bool exec, upDir; public OMap<double> ips = new OMap<double>(), sts = new OMap<double>(); }
    public sealed class UaRec { public double n, first, last, ipOv; public int ipN; public string fam; public OMap<double> ips = new OMap<double>(); }
    public sealed class UserRec { public double n, first, last, fFile, fLine, pub; public int ipN; public OMap<double> ips = new OMap<double>(); }
    public sealed class RuleHit { public double n, first, last; public string sev; public List<object[]> kept = new List<object[]>(); public OMap<double> ips = new OMap<double>(), stems = new OMap<double>(); public int ipN, stN; public double[] sx = new double[5]; }
    public sealed class EnumRec { public int n; public HashSet<string> q = new HashSet<string>(StringComparer.Ordinal); }
    public sealed class Win
    {
        public double b5 = -1, b10 = -1, b10b = -1, h = -1, last401; public int n5, login, e401, dUaN, d4, dn, dOff, dl; public string dDay = "";
        public HashSet<string> s5, dUas; public Dictionary<string, EnumRec> en;
    }
    public sealed class FileRec
    {
        public string path, name, openError = ""; public double size;
        public double lines, rows, malformed, crlf, lfOnly, nonAscii, decodeErr, backSteps, firstTs, lastTs, minTs, maxTs; public bool scanned, notW3C, tailNoEol;
        public List<object[]> malformedSamples = new List<object[]>(); public List<double[]> backSamples = new List<double[]>(); public List<double> s500 = new List<double>();
        public List<Block> blocks = new List<Block>();
    }
    public sealed class Schema { public string fields; public double firstFile, firstLine, blocks; public bool assumed; }

    // ---------------------------------------------------------------- engine
    public sealed class ScanEngine
    {
        const double HOUR = 3600000, DAY = 86400000;
        // inputs
        List<FileRec> files = new List<FileRec>(); Deriver D; Evaluator ev; int chunk; double retention, ipCap, stemCap, uaCap, gapMs;
        int IP_STEM_CAP, IP_UA_CAP, WIN_PURGE_ROWS, KEEP_RAW; double s7win, a1win, a2win, a2count, a4rows, s1dayMin, s1ratio;
        string bhStart, bhEnd; double bhStartMin, bhEndMin;
        Dictionary<long, string> statusKeys = new Dictionary<long, string>(); Dictionary<double, string> numStrs = new Dictionary<double, string>();
        string lastSip, lastSport; double lastPort = double.NaN; string lastDk, lastHh, lastHk; HashSet<int> bhDays = new HashSet<int>(); double[] tzT; double[] tzO;
        string outPath, progressPath, cancelPath;
        // index state
        OMap<double[]> perDay = new OMap<double[]>(), perHour = new OMap<double[]>();
        OMap<IpRec> ips = new OMap<IpRec>(); OMap<StemRec> stems = new OMap<StemRec>(); OMap<UaRec> uas = new OMap<UaRec>(); OMap<UserRec> users = new OMap<UserRec>();
        OMap<double> statuses = new OMap<double>(), methods = new OMap<double>(), sports = new OMap<double>(), exts = new OMap<double>(), uaFams = new OMap<double>(), lbKeys = new OMap<double>();
        OMap<RuleHit> ruleHits = new OMap<RuleHit>();
        List<Schema> schemas = new List<Schema>(); OMap<double[]> softwares = new OMap<double[]>();
        List<double[]> restarts = new List<double[]>(); List<string> restartDates = new List<string>(); List<double[]> gaps = new List<double[]>();
        double tRows, tLines, tMalformed, tBlocks, tNonAscii, tDecodeErr, tFirst, tLast, tBytes, ipEvicted, stemEvicted, uaEvicted, lbOv;
        int cIps, cStems, cUas; double evAtIps, evAtStems, evAtUas;
        Dictionary<string, Win> win = new Dictionary<string, Win>(StringComparer.Ordinal);
        double prevTs; int sincePurge; int lastBlock; double blockPrevTs;
        int filesDone; int partialFile = -1; int partialLine; bool cancelled; double cancelAfterRows;

        public static int Run(string jobPath)
        {
            var e = new ScanEngine(); string donePath = null;
            try
            {
                var job = (Dictionary<string, object>)Json.Parse(File.ReadAllText(jobPath, Encoding.UTF8));
                donePath = (string)job["output"] + ".done";
                e.Load(job);
                var sw = System.Diagnostics.Stopwatch.StartNew();
                e.Scan();
                string resume = e.cancelled ? e.ResumeStateJson() : null; // detection state at the cancel point, before windows close
                e.CloseAllWindows();
                e.Write(sw.ElapsedMilliseconds, resume);
                File.WriteAllText(donePath, e.cancelled ? "cancelled" : "ok");
                return 0;
            }
            catch (Exception ex)
            {
                if (donePath != null) File.WriteAllText(donePath, "ERROR " + ex.GetType().Name + ": " + ex.Message + "\r\n" + ex.StackTrace);
                throw;
            }
        }

        static double D0(Dictionary<string, object> d, string k, double def) { object v; return d.TryGetValue(k, out v) && v is double ? (double)v : def; }
        void Load(Dictionary<string, object> job)
        {
            object pf; Profile = job.TryGetValue("profile", out pf) && pf is bool && (bool)pf;
            outPath = (string)job["output"]; progressPath = (string)job["progress"]; cancelPath = (string)job["cancel"];
            cancelAfterRows = D0(job, "cancelAfterRows", 0); // test hook: cancel at the first chunk boundary after N rows
            foreach (object o in (List<object>)job["files"]) { var f = (Dictionary<string, object>)o; files.Add(new FileRec { path = (string)f["path"], name = (string)f["name"], size = (double)f["size"] }); }
            var st = (Dictionary<string, object>)job["settings"];
            chunk = (int)D0(st, "chunkChars", 4194304); retention = D0(st, "ruleHitRetention", 50000);
            ipCap = D0(st, "ipCap", 250000); stemCap = D0(st, "stemCap", 500000); uaCap = D0(st, "uaCap", 100000); gapMs = D0(st, "gapMs", 4 * HOUR);
            var bh = (Dictionary<string, object>)st["businessHours"]; bhStart = (string)bh["start"]; bhEnd = (string)bh["end"];
            foreach (object o in (List<object>)bh["days"]) bhDays.Add((int)(double)o);
            foreach (object o in (List<object>)st["internalCidrs"]) { var c = IpUtil.ParseCidr((string)o); if (c != null) IpUtil.ExtraInternal.Add(c); }
            foreach (object o in (List<object>)st["allowlist"]) IpUtil.Allow.Add(Js.Lower(Js.Trim((string)o)));
            object tnp; IpUtil.TestNetsPublic = st.TryGetValue("testNetsPublic", out tnp) && tnp is bool && (bool)tnp;
            var tz = (Dictionary<string, object>)job["tz"]; var tt = (List<object>)tz["t"]; var to = (List<object>)tz["o"];
            tzT = new double[tt.Count]; tzO = new double[to.Count]; for (int i = 0; i < tt.Count; i++) { tzT[i] = (double)tt[i]; tzO[i] = (double)to[i]; }
            var k = (Dictionary<string, object>)job["consts"];
            IP_STEM_CAP = (int)D0(k, "IP_STEM_CAP", 32); IP_UA_CAP = (int)D0(k, "IP_UA_CAP", 8); WIN_PURGE_ROWS = (int)D0(k, "WIN_PURGE_ROWS", 400000); KEEP_RAW = (int)D0(k, "KEEP_RAW", 200);
            var p = (Dictionary<string, object>)job["scanParams"];
            s7win = D0(p, "s7win", 300000); a1win = D0(p, "a1win", 600000); a2win = D0(p, "a2win", 600000); a2count = D0(p, "a2count", 10);
            a4rows = D0(p, "a4rows", 50); s1dayMin = D0(p, "s1dayMin", 100); s1ratio = D0(p, "s1ratio", 0.8);
            var parser = (Dictionary<string, object>)job["parser"];
            FileParser.FieldMap = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in (Dictionary<string, object>)parser["fieldMap"]) FileParser.FieldMap[kv.Key] = (string)kv.Value;
            FileParser.Numeric = new HashSet<string>(StringComparer.Ordinal); foreach (object o in (List<object>)parser["numeric"]) FileParser.Numeric.Add((string)o);
            FileParser.StringKeys = ToArr((List<object>)parser["stringKeys"]); FileParser.NumKeys = ToArr((List<object>)parser["numKeys"]); FileParser.DefaultFields = ToArr((List<object>)parser["defaultFields"]);
            FileParser.InitSlots();
            var bs = bhStart.Split(':'); var be = bhEnd.Split(':');
            bhStartMin = Js.ToNumber(bs[0]) * 60 + (bs.Length > 1 ? Js.ToNumber(bs[1]) : double.NaN); bhEndMin = Js.ToNumber(be[0]) * 60 + (be.Length > 1 ? Js.ToNumber(be[1]) : double.NaN);
            var valid = new HashSet<string>(StringComparer.Ordinal); foreach (object o in (List<object>)parser["methodsValid"]) valid.Add((string)o);
            D = new Deriver((Dictionary<string, object>)job["lists"], (Dictionary<string, object>)parser["regex"], (List<object>)parser["uaFamilies"]);
            ev = new Evaluator((List<object>)job["rules"], D, valid);
        }
        static string[] ToArr(List<object> l) { var a = new string[l.Count]; for (int i = 0; i < l.Count; i++) a[i] = (string)l[i]; return a; }

        double TzOff(double ms)
        {
            int lo = 0, hi = tzT.Length - 1;
            if (ms < tzT[0]) return tzO[0];
            while (lo < hi) { int mid = (lo + hi + 1) >> 1; if (tzT[mid] <= ms) lo = mid; else hi = mid - 1; }
            return tzO[lo];
        }
        bool IsBusinessTime(double ms)
        {
            double local = ms + TzOff(ms) * 60000;
            double dow = (Math.Floor(local / DAY) + 4) % 7; if (dow < 0) dow += 7;
            if (!bhDays.Contains((int)dow)) return false;
            double mins = Math.Floor((local % DAY) / 60000); if (mins < 0) mins += 1440;
            // +undefined is NaN in JavaScript, so a missing minutes part makes the comparison false
            return mins >= bhStartMin && mins < bhEndMin;
        }

        // ------------------------------------------------ streaming pass
        // ---- two-stage pipeline: producer = read + decode + split + parse + derive; consumer = rules + aggregation.
        // Batches flow in file order; cancellation is honoured only at read-chunk boundaries (as in the JS engine).
        sealed class Batch
        {
            public int kind; // 0 rows, 1 end of file, 2 open error, 3 producer failure
            public int fileIdx, n; public Row[] rows; public bool chunkEnd; public int lineNoAfter; public double charsRead;
            public FileParser fp; public bool tailNoEol; public double crlf, lfOnly; public string error;
        }
        const int BATCH_ROWS = 4096;
        BlockingCollection<Batch> queue, pool; volatile bool stopProducer;
        Batch Take() { Batch b; if (!pool.TryTake(out b)) { b = new Batch { rows = new Row[BATCH_ROWS] }; for (int i = 0; i < BATCH_ROWS; i++) b.rows[i] = FileParser.NewRow(); } b.kind = 0; b.n = 0; b.chunkEnd = false; b.fp = null; b.error = null; return b; }
        void Producer()
        {
            try
            {
                var scratch = FileParser.NewRow();
                var enc = Encoding.GetEncoding(1252); /* lossless byte mapping, independent of the system code page */
                var buf = new char[Math.Max(65536, chunk)];
                for (int fi = 0; fi < files.Count && !stopProducer; fi++)
                {
                    var fr = files[fi]; StreamReader rd;
                    try { rd = new StreamReader(new FileStream(fr.path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20), enc, false, 1 << 20); }
                    catch (Exception ex) { var eb = Take(); eb.kind = 2; eb.fileIdx = fi; eb.error = ex.Message; queue.Add(eb); continue; }
                    var fp = new FileParser(fi); var rest = new StringBuilder(); bool tailNoEol = false; double crlf = 0, lfOnly = 0, charsRead = 0;
                    var b = Take(); b.fileIdx = fi;
                    Action<string> line = l =>
                    {
                        int code = fp.Line(l, scratch);
                        if (code == 0) return;
                        if (b.n == BATCH_ROWS) { var nb = Take(); nb.fileIdx = fi; b.lineNoAfter = fp.lineNo; b.charsRead = charsRead; queue.Add(b); b = nb; }
                        var r = b.rows[b.n++]; r.CopyFrom(scratch); r.code = code;
                        if (code == 1) ev.Derive(r);
                    };
                    using (rd)
                    {
                        while (!stopProducer)
                        {
                            int n = rd.Read(buf, 0, buf.Length);
                            if (n <= 0)
                            {
                                if (rest.Length > 0) { tailNoEol = true; string last = rest.ToString(); rest.Clear(); if (last.Length > 0 && last[last.Length - 1] == '\r') { last = last.Substring(0, last.Length - 1); crlf++; } line(last); }
                                break;
                            }
                            charsRead += n; int st = 0;
                            for (int i = 0; i < n; i++)
                            {
                                if (buf[i] != '\n') continue;
                                string ln;
                                if (rest.Length > 0) { rest.Append(buf, st, i - st); ln = rest.ToString(); rest.Clear(); } else ln = new string(buf, st, i - st);
                                st = i + 1;
                                if (ln.Length > 0 && ln[ln.Length - 1] == '\r') { ln = ln.Substring(0, ln.Length - 1); crlf++; } else lfOnly++;
                                line(ln);
                            }
                            if (st < n) rest.Append(buf, st, n - st);
                            // chunk boundary: hand over the batch so cancellation can stop exactly here
                            b.chunkEnd = true; b.lineNoAfter = fp.lineNo; b.charsRead = charsRead; queue.Add(b); b = Take(); b.fileIdx = fi;
                        }
                    }
                    if (stopProducer) break;
                    if (b.n > 0) { b.chunkEnd = true; b.lineNoAfter = fp.lineNo; b.charsRead = charsRead; queue.Add(b); } else pool.TryAdd(b);
                    var eof = Take(); eof.kind = 1; eof.fileIdx = fi; eof.fp = fp; eof.tailNoEol = tailNoEol; eof.crlf = crlf; eof.lfOnly = lfOnly; eof.lineNoAfter = fp.lineNo; queue.Add(eof);
                }
            }
            catch (Exception ex) { var fb = new Batch { kind = 3, error = ex.GetType().Name + ": " + ex.Message + "\r\n" + ex.StackTrace }; queue.Add(fb); }
            finally { queue.CompleteAdding(); }
        }
        void Scan()
        {
            double bytesTotal = 0, bytesDone = 0; foreach (var f in files) bytesTotal += f.size;
            var clock = System.Diagnostics.Stopwatch.StartNew(); long lastProg = -1000;
            queue = new BlockingCollection<Batch>(new ConcurrentQueue<Batch>(), 64); pool = new BlockingCollection<Batch>(new ConcurrentQueue<Batch>(), 128);
            var th = new Thread(Producer) { IsBackground = true, Name = "IISLA producer" }; th.Start();
            int curFile = -1;
            try
            {
                foreach (var b in queue.GetConsumingEnumerable())
                {
                    if (b.kind == 3) throw new Exception("producer failed: " + b.error);
                    var fr = files[b.fileIdx];
                    if (b.fileIdx != curFile) { curFile = b.fileIdx; lastBlock = -1; blockPrevTs = 0; }
                    if (b.kind == 2) { fr.openError = b.error; fr.scanned = true; filesDone = b.fileIdx + 1; pool.TryAdd(b); continue; }
                    if (b.kind == 1)
                    {
                        var fp = b.fp;
                        fr.lines = fp.lineNo; fr.blocks = fp.blocks; fr.notW3C = fp.notW3C; fr.tailNoEol = b.tailNoEol; fr.crlf = b.crlf; fr.lfOnly = b.lfOnly; fr.scanned = true;
                        tLines += fp.lineNo; tBlocks += fp.blocks.Count; tBytes += fr.size;
                        FileBlocks(b.fileIdx, fp.blocks);
                        bytesDone += fr.size; filesDone = b.fileIdx + 1;
                        pool.TryAdd(b); continue;
                    }
                    for (int i = 0; i < b.n; i++)
                    {
                        var r = b.rows[i];
                        if (r.code == 1) RowAgg(r, fr);
                        else { fr.malformed++; tMalformed++; if (fr.malformedSamples.Count < 20) fr.malformedSamples.Add(new object[] { (double)r.lineNo, r.reason2, r.raw.Length > 2000 ? r.raw.Substring(0, 2000) : r.raw }); }
                    }
                    if (b.chunkEnd && cancelAfterRows > 0 && tRows >= cancelAfterRows) { cancelAfterRows = 0; cancelled = true; partialFile = b.fileIdx; partialLine = b.lineNoAfter; filesDone = b.fileIdx; stopProducer = true; pool.TryAdd(b); break; }
                    if (b.chunkEnd)
                    {
                        long now = clock.ElapsedMilliseconds;
                        if (now - lastProg >= 250)
                        {
                            lastProg = now;
                            if (File.Exists(cancelPath)) { cancelled = true; partialFile = b.fileIdx; partialLine = b.lineNoAfter; filesDone = b.fileIdx; stopProducer = true; pool.TryAdd(b); break; }
                            Progress(b.fileIdx, fr.name, bytesDone + b.charsRead, bytesTotal, now);
                        }
                    }
                    pool.TryAdd(b);
                }
            }
            finally
            {
                stopProducer = true;
                Batch x; while (queue.TryTake(out x)) { } // unblock a producer waiting on a full queue
                th.Join(30000);
            }
            if (!cancelled) Progress(files.Count, "", bytesTotal, bytesTotal, clock.ElapsedMilliseconds);
        }
        void Progress(int fi, string current, double done, double total, long ms)
        {
            try
            {
                string s = "{\"file\":" + fi + ",\"files\":" + files.Count + ",\"current\":\"" + current.Replace("\\", "\\\\").Replace("\"", "") + "\",\"rows\":" + Js.JsonNum(tRows) +
                    ",\"bytesDone\":" + Js.JsonNum(done) + ",\"bytesTotal\":" + Js.JsonNum(total) + ",\"ms\":" + ms + "}";
                File.WriteAllText(progressPath + ".tmp", s); if (File.Exists(progressPath)) File.Delete(progressPath); File.Move(progressPath + ".tmp", progressPath);
            }
            catch (IOException) { }
        }
        public static bool Profile; public static long tParse, tEval, tAgg, tDerive;
        void FileBlocks(int fileId, List<Block> blocks)
        {
            for (int i = 0; i < blocks.Count; i++)
            {
                var b = blocks[i]; Schema found = null; int j;
                for (j = 0; j < schemas.Count; j++) if (schemas[j].fields == b.fields) { found = schemas[j]; break; }
                if (found == null) { found = new Schema { fields = b.fields, firstFile = fileId, firstLine = b.line, blocks = 1, assumed = b.assumed }; schemas.Add(found); j = schemas.Count - 1; } else found.blocks++;
                b.schema = j;
                if (!string.IsNullOrEmpty(b.software)) { double[] sw; if (!softwares.TryGet(b.software, out sw)) { sw = new double[] { fileId, 0 }; softwares[b.software] = sw; } sw[1]++; }
                if (i > 0) { restarts.Add(new double[] { fileId, b.line, b.dateTs }); restartDates.Add(b.date); }
            }
        }
        string NumS(double v) { string s; if (!numStrs.TryGetValue(v, out s)) { s = Js.NumStr(v); if (numStrs.Count < 100000) numStrs[v] = s; } return s; }
        string StatusKey(double st, double sub)
        {
            if (st == Math.Floor(st) && sub == Math.Floor(sub) && st >= -1 && st < 1e7 && sub >= 0 && sub < 1e7)
            {
                long k = (long)(st + 1) * 10000000L + (long)sub; string v;
                if (!statusKeys.TryGetValue(k, out v)) { v = NumS(st) + "." + NumS(sub); statusKeys[k] = v; }
                return v;
            }
            return NumS(st) + "." + NumS(sub);
        }
        static void Inc(OMap<double> m, string k) { double v; if (m.TryGet(k, out v)) m[k] = v + 1; else m[k] = 1; }

        void RowAgg(Row r, FileRec frec)
        {
            long a0 = Profile ? System.Diagnostics.Stopwatch.GetTimestamp() : 0;
            double t = r.ts; int nh = ev.Evaluate(r);
            if (Profile) { long a1 = System.Diagnostics.Stopwatch.GetTimestamp(); tEval += a1 - a0; a0 = a1; } var c = ev.ctx; var si = c.si; var qi = c.qi; var ui = c.ui; string cls = c.cls; bool pub = c.pub; string ip = r.eip;
            double st = r.Status; double scl = st >= 0 ? Math.Floor(st / 100) : 0; bool isPost = r.Method == "POST", lb = cls == "loopback";
            tRows++;
            if (++sincePurge >= WIN_PURGE_ROWS) { sincePurge = 0; PurgeWindows(t); }
            if (tFirst == 0 || t < tFirst) tFirst = t;
            if (t > tLast) tLast = t;
            if (r.nonAscii) { tNonAscii++; frec.nonAscii++; }
            if (qi.decErr || si.decErr) { tDecodeErr++; frec.decodeErr++; }
            frec.rows++;
            if (frec.firstTs == 0) { frec.firstTs = t; frec.minTs = t; }
            frec.lastTs = t;
            if (t < frec.minTs) frec.minTs = t;
            if (t > frec.maxTs) frec.maxTs = t;
            if (r.blockId != lastBlock) { lastBlock = r.blockId; blockPrevTs = 0; }
            if (blockPrevTs != 0 && t < blockPrevTs) { frec.backSteps++; if (frec.backSamples.Count < 5) frec.backSamples.Add(new double[] { r.lineNo, t, blockPrevTs }); }
            blockPrevTs = t;
            if (st == 500 && frec.s500.Count < 500) frec.s500.Add(t);
            if (prevTs != 0 && t - prevTs >= gapMs) gaps.Add(new double[] { prevTs, t, (t - prevTs) / HOUR, r.fileId, r.lineNo });
            if (t > prevTs) prevTs = t;

            string date = r.Date, time = r.Time;
            string dk = date.Length == 10 ? date : Js.DayKey(t);
            string hh = time.Length >= 2 ? time.Substring(0, 2) : Js.P2(Js.UtcHours(t)), hk;
            if (ReferenceEquals(dk, lastDk) || dk == lastDk) { if (hh == lastHh) hk = lastHk; else { hk = dk + "T" + hh; lastHh = hh; lastHk = hk; } } else { hk = dk + "T" + hh; lastDk = dk; lastHh = hh; lastHk = hk; }
            double[] pd; if (!perDay.TryGet(dk, out pd)) { pd = new double[8]; perDay[dk] = pd; }
            pd[0]++; if (scl >= 2 && scl <= 5) pd[(int)scl - 1]++; if (pub) pd[5]++; if (lb) pd[6]++; if (nh > 0) pd[7]++;
            double[] ph; if (!perHour.TryGet(hk, out ph)) { ph = new double[5]; perHour[hk] = ph; }
            ph[0]++; if (scl == 5) ph[1]++; if (pub) ph[2]++; if (lb) ph[3]++; if (nh > 0) ph[4]++;

            double sub = r.Sub, port = r.Port;
            Inc(statuses, StatusKey(st, sub < 0 ? 0 : sub));
            Inc(methods, r.Method);
            string sip = r.Sip;
            if (!(ReferenceEquals(sip, lastSip) || sip == lastSip) || port != lastPort) { lastSip = sip; lastPort = port; lastSport = sip + ":" + (port < 0 ? "-" : NumS(port)); }
            Inc(sports, lastSport);
            Inc(exts, si.ext.Length > 0 ? si.ext : "(none)");
            Inc(uaFams, ui.fam);
            if (lb)
            {
                string lk = si.key + "?" + r.Query;
                if (lbKeys.Has(lk) || lbKeys.Count < 2000) Inc(lbKeys, lk); else lbOv++;
            }

            // IP aggregate
            IpRec rec;
            if (!ips.TryGet(ip, out rec))
            {
                if (cIps >= ipCap && cIps >= evAtIps) EvictIps();
                rec = new IpRec { first = t, last = t, cls = cls }; ips[ip] = rec; cIps++;
            }
            rec.n++; if (t < rec.first) rec.first = t; if (t > rec.last) rec.last = t;
            if (scl == 2) rec.s2++; else if (scl == 3) rec.s3++; else if (scl == 4) rec.s4++; else if (scl == 5) rec.s5++;
            Inc(rec.m, r.Method);
            double cur;
            if (rec.st.TryGet(si.key, out cur)) rec.st[si.key] = cur + 1; else if (rec.stN < IP_STEM_CAP) { rec.st[si.key] = 1; rec.stN++; } else rec.stOv++;
            string ua = r.Ua;
            if (rec.ua.TryGet(ua, out cur)) rec.ua[ua] = cur + 1; else if (rec.uaN < IP_UA_CAP) { rec.ua[ua] = 1; rec.uaN++; } else rec.uaOv++;
            if (si.exec) rec.exec++; if (si.stat) rec.stat++; if (isPost) rec.post++;
            if (si.php) rec.php++; if (si.dotnet) rec.dn++;
            if (rec.d.TryGet(dk, out cur)) rec.d[dk] = cur + 1; else if (rec.dN < 400) { rec.d[dk] = 1; rec.dN++; } else rec.dOv++;

            // stem aggregate
            StemRec s;
            if (!stems.TryGet(si.key, out s))
            {
                if (cStems >= stemCap && cStems >= evAtStems) EvictStems();
                s = new StemRec { first = t, last = t, fFile = r.fileId, fLine = r.lineNo, fIp = ip, raw = r.Stem, exec = si.exec, upDir = si.upDir }; stems[si.key] = s; cStems++;
            }
            s.n++; if (t > s.last) s.last = t;
            if (t < s.first) { s.first = t; s.fFile = r.fileId; s.fLine = r.lineNo; s.fIp = ip; }
            if (isPost) s.post++;
            if (st == 200) { s.ok++; if (pub) s.okPub++; }
            if (scl == 4) s.s4++; else if (scl == 5) s.s5++;
            Inc(s.sts, NumS(st));
            if (!s.ips.Has(ip)) { if (s.ipN < 20) { s.ips[ip] = 1; s.ipN++; if (pub) s.pubN++; } else s.ipOv = 1; }

            // UA aggregate
            UaRec u;
            if (!uas.TryGet(ua, out u))
            {
                if (cUas >= uaCap && cUas >= evAtUas) EvictUas();
                u = new UaRec { first = t, last = t, fam = ui.fam }; uas[ua] = u; cUas++;
            }
            u.n++; if (t > u.last) u.last = t; if (t < u.first) u.first = t;
            if (!u.ips.Has(ip)) { if (u.ipN < 20) { u.ips[ip] = 1; u.ipN++; } else u.ipOv = 1; }

            // users
            string user = r.User;
            if (user != "-" && user.Length > 0)
            {
                UserRec us; if (!users.TryGet(user, out us)) { us = new UserRec { first = t, last = t, fFile = r.fileId, fLine = r.lineNo }; users[user] = us; }
                us.n++; if (t > us.last) us.last = t;
                if (!us.ips.Has(ip) && us.ipN < 50) { us.ips[ip] = 1; us.ipN++; }
                if (pub) us.pub++;
            }

            // rule hits
            for (int j = 0; j < nh; j++)
            {
                string id = ev.hits[j]; RuleHit h;
                if (!ruleHits.TryGet(id, out h)) { h = new RuleHit { sev = ev.hitSev[j], first = t, last = t }; ruleHits[id] = h; }
                h.n++; if (t > h.last) h.last = t; if (t < h.first) h.first = t;
                h.sev = Evaluator.MaxSev(h.sev, ev.hitSev[j]);
                h.sx[scl >= 2 && scl <= 5 ? (int)scl - 2 : 4]++; // response mix: 2xx, 3xx, 4xx, 5xx, other
                if (h.kept.Count < retention) h.kept.Add(new object[] { (double)r.fileId, (double)r.lineNo, t, ip, h.kept.Count < KEEP_RAW ? (r.raw.Length > 1500 ? r.raw.Substring(0, 1500) : r.raw) : "" });
                if (h.ips.TryGet(ip, out cur)) h.ips[ip] = cur + 1; else if (h.ipN < 1000) { h.ips[ip] = 1; h.ipN++; }
                if (h.stems.TryGet(si.key, out cur)) h.stems[si.key] = cur + 1; else if (h.stN < 1000) { h.stems[si.key] = 1; h.stN++; }
                Inc(rec.hits, id);
                if ((id == "R-EXP-001" || id == "R-EXP-002" || id == "R-EXP-003" || id == "R-EXP-004" || id == "R-EXP-005" || id == "R-EXP-006") && rec.firstExp == 0) rec.firstExp = t;
            }

            if (Profile) { tAgg += System.Diagnostics.Stopwatch.GetTimestamp() - a0; a0 = System.Diagnostics.Stopwatch.GetTimestamp(); }
            // per-client windows
            Win w; if (!win.TryGetValue(ip, out w)) { w = new Win(); win[ip] = w; }
            double b = Math.Floor(t / s7win);
            if (b != w.b5) { w.b5 = b; w.s5 = new HashSet<string>(StringComparer.Ordinal); w.n5 = 0; }
            if (w.s5.Add(si.key)) { w.n5++; if (w.n5 > rec.ms5) { rec.ms5 = w.n5; rec.ms5t = t; } }
            b = Math.Floor(t / a1win);
            if (b != w.b10) { w.b10 = b; w.login = 0; }
            if (isPost && si.loginEp) { w.login++; if (w.login > rec.mlogin) { rec.mlogin = w.login; rec.mlogint = t; } }
            b = Math.Floor(t / a2win);
            if (b != w.b10b) { w.b10b = b; w.e401 = 0; }
            if (st == 401) { w.e401++; w.last401 = t; if (w.e401 > rec.m401) { rec.m401 = w.e401; rec.m401t = t; } }
            else if ((st == 200 || st == 302) && w.last401 != 0 && t - w.last401 <= 300000 && rec.m401 >= a2count) rec.a401ok = 1;
            if (dk != w.dDay) { CloseDay(rec, w); w.dDay = dk; w.dUas = new HashSet<string>(StringComparer.Ordinal); w.dUaN = 0; w.d4 = 0; w.dn = 0; w.dOff = 0; }
            w.dn++; if (scl == 4) w.d4++;
            if (pub && w.dUas.Add(ua)) { w.dUaN++; if (w.dUaN > rec.muaDay) { rec.muaDay = w.dUaN; rec.muaDayD = dk; } }
            if ((cls == "rfc1918" || cls == "internal") && si.exec && !IsBusinessTime(t)) w.dOff++;
            if (pub && si.dlEp)
            {
                b = Math.Floor(t / HOUR);
                if (b != w.h) { w.h = b; w.dl = 0; w.en = new Dictionary<string, EnumRec>(StringComparer.Ordinal); }
                w.dl++; if (w.dl > rec.mdl) { rec.mdl = w.dl; rec.mdlt = t; }
                EnumRec e; if (!w.en.TryGetValue(si.key, out e)) { e = new EnumRec(); w.en[si.key] = e; }
                if (e.n < 1000 && e.q.Add(r.Query)) { e.n++; if (e.n > rec.menum) { rec.menum = e.n; rec.menumS = si.key; } }
            }
            CloseDayProfileEnd(a0);
        }
        void CloseDayProfileEnd(long a0) { if (Profile) tDerive += System.Diagnostics.Stopwatch.GetTimestamp() - a0; }
        void CloseDay(IpRec rec, Win w)
        {
            if (string.IsNullOrEmpty(w.dDay)) return;
            if (w.dOff >= a4rows) rec.off[w.dDay] = w.dOff;
            if (w.d4 >= s1dayMin && (double)w.d4 / w.dn >= s1ratio && w.d4 > rec.md4) { rec.md4 = w.d4; rec.md4d = w.dDay; }
        }
        void PurgeWindows(double now)
        {
            double cut = now - DAY; var del = new List<string>();
            foreach (var kv in win)
            {
                IpRec rec; if (!ips.TryGet(kv.Key, out rec)) { del.Add(kv.Key); continue; }
                if (rec.last < cut) { CloseDay(rec, kv.Value); del.Add(kv.Key); }
            }
            foreach (var k in del) win.Remove(k);
        }
        // Detection state at a cancel point, in the format of scan.js Scanner.saveState, so the built-in engine can
        // resume exactly: [ip, b5, s5[], n5, b10, login, e401, last401, b10b, dDay, dUas[], dUaN, d4, dn, dOff, h, dl, en, offBefore, md4, md4d]
        string ResumeStateJson()
        {
            var sw = new StringWriter(CultureInfo.InvariantCulture); var j = new JW(sw);
            j.BeginObj().KNum("v", 1).KNum("prevTs", prevTs).KNum("lastBlock", lastBlock).KNum("blockPrevTs", blockPrevTs).KNum("sincePurge", sincePurge);
            j.Key("evictAt").ArrStart().Num(evAtIps).Num(evAtStems).Num(evAtUas).EndArr();
            j.Key("win").ArrStart();
            foreach (var kv in win)
            {
                var w = kv.Value; IpRec rec; bool has = ips.TryGet(kv.Key, out rec); double prev;
                j.ArrStart().Str(kv.Key).Num(w.b5); SetJ(j, w.s5); j.Num(w.n5).Num(w.b10).Num(w.login).Num(w.e401).Num(w.last401).Num(w.b10b).Str(w.dDay); SetJ(j, w.dUas);
                j.Num(w.dUaN).Num(w.d4).Num(w.dn).Num(w.dOff).Num(w.h).Num(w.dl);
                if (w.en == null) j.Null(); else { j.ArrStart(); foreach (var e in w.en) { j.ArrStart().Str(e.Key).Num(e.Value.n); SetJ(j, e.Value.q); j.EndArr(); } j.EndArr(); }
                if (has && w.dDay.Length > 0 && rec.off.TryGet(w.dDay, out prev)) j.Num(prev); else j.Null();
                j.Num(has ? rec.md4 : 0).Str(has ? rec.md4d : "");
                j.EndArr();
            }
            j.EndArr();
            j.Key("expWin").ArrStart();
            foreach (var kv in ev.expWin) { j.ArrStart().Str(kv.Key).Num(kv.Value.ts); SetJ(j, kv.Value.stems); j.EndArr(); }
            j.EndArr().EndObj();
            return sw.ToString();
        }
        static void SetJ(JW j, HashSet<string> s) { if (s == null) { j.Null(); return; } j.ArrStart(); foreach (var x in s) j.Str(x); j.EndArr(); }
        void CloseAllWindows() { foreach (var kv in win) { IpRec rec; if (ips.TryGet(kv.Key, out rec)) CloseDay(rec, kv.Value); } win.Clear(); }
        void EvictIps()
        {
            double thr = 1, removed = 0;
            while (cIps >= ipCap * 0.9 && thr < 1000)
            {
                foreach (var k in ips.Keys()) { var r = ips[k]; if (r.n <= thr && r.hits.Count == 0) { ips.Remove(k); win.Remove(k); cIps--; removed++; } }
                thr *= 2;
            }
            ipEvicted += removed;
            if (cIps >= ipCap * 0.9) evAtIps = cIps + Math.Ceiling(ipCap * 0.1); // backoff, mirrors scan.js
        }
        void EvictStems()
        {
            double thr = 1, removed = 0;
            while (cStems >= stemCap * 0.9 && thr < 1000)
            {
                foreach (var k in stems.Keys()) { var s = stems[k]; if (s.n <= thr && (!s.exec || s.ok == 0)) { stems.Remove(k); cStems--; removed++; } }
                thr *= 2;
            }
            stemEvicted += removed;
            if (cStems >= stemCap * 0.9) evAtStems = cStems + Math.Ceiling(stemCap * 0.1);
        }
        void EvictUas()
        {
            double thr = 1, removed = 0;
            while (cUas >= uaCap * 0.9 && thr < 1000)
            {
                foreach (var k in uas.Keys()) { if (uas[k].n <= thr) { uas.Remove(k); cUas--; removed++; } }
                thr *= 2;
            }
            uaEvicted += removed;
            if (cUas >= uaCap * 0.9) evAtUas = cUas + Math.Ceiling(uaCap * 0.1);
        }

        // ------------------------------------------------ output
        static void MapNum(JW j, string key, OMap<double> m) { j.Key(key).ObjStart(); foreach (var k in m.Keys()) j.KNum(k, m[k]); j.EndObj(); }
        void Write(long ms, string resume)
        {
            using (var sw = new StreamWriter(outPath + ".tmp", false, new ASCIIEncoding(), 1 << 20))
            {
                var j = new JW(sw);
                j.BeginObj();
                double tf = 1000.0 / System.Diagnostics.Stopwatch.Frequency;
                j.KStr("engine", "IISScanEngine (C#) 1"); if (Profile) { j.Key("profile").ObjStart().KNum("parseMs", Math.Round(tParse * tf)).KNum("evalMs", Math.Round(tEval * tf)).KNum("aggMs", Math.Round(tAgg * tf)).KNum("windowsMs", Math.Round(tDerive * tf)); j.Key("rx").ObjStart(); foreach (var kv in Deriver.RxTicks) j.KNum(kv.Key, Math.Round(kv.Value * tf)); j.EndObj(); j.EndObj(); } j.KNum("scanMs", ms); j.KBool("partial", cancelled); j.KNum("filesDone", filesDone);
                j.KNum("partialFile", partialFile); j.KNum("partialLine", partialLine);
                if (resume != null) j.Key("resumeState").Raw(resume);
                j.Key("files").ArrStart();
                foreach (var f in files)
                {
                    j.ObjStart();
                    j.KBool("scanned", f.scanned); j.KNum("lines", f.lines); j.KNum("rows", f.rows); j.KNum("malformed", f.malformed);
                    j.Key("malformedSamples").ArrStart(); foreach (var m in f.malformedSamples) { j.ObjStart().KNum("line", (double)m[0]).KStr("reason", (string)m[1]).KStr("raw", (string)m[2]).EndObj(); } j.EndArr();
                    j.Key("blocks").ArrStart();
                    foreach (var b in f.blocks) { j.ObjStart().KNum("line", b.line).KStr("software", b.software).KStr("version", b.version).KStr("date", b.date).KNum("dateTs", b.dateTs).KBool("assumed", b.assumed).KNum("schema", b.schema).EndObj(); }
                    j.EndArr();
                    j.KBool("notW3C", f.notW3C); j.KBool("tailNoEol", f.tailNoEol); j.KNum("crlf", f.crlf); j.KNum("lfOnly", f.lfOnly); j.KNum("nonAscii", f.nonAscii); j.KNum("decodeErr", f.decodeErr);
                    j.KNum("backSteps", f.backSteps);
                    j.Key("backSamples").ArrStart(); foreach (var bs in f.backSamples) j.ObjStart().KNum("line", bs[0]).KNum("ts", bs[1]).KNum("prev", bs[2]).EndObj(); j.EndArr();
                    j.KNum("firstTs", f.firstTs); j.KNum("lastTs", f.lastTs); j.KNum("minTs", f.minTs); j.KNum("maxTs", f.maxTs);
                    j.Key("s500").ArrStart(); foreach (var x in f.s500) j.Num(x); j.EndArr();
                    j.KStr("openError", f.openError);
                    j.EndObj();
                }
                j.EndArr();
                j.Key("schemas").ArrStart(); foreach (var s in schemas) j.ObjStart().KStr("fields", s.fields).KNum("firstFile", s.firstFile).KNum("firstLine", s.firstLine).KNum("blocks", s.blocks).KBool("assumed", s.assumed).EndObj(); j.EndArr();
                j.Key("softwares").ObjStart(); foreach (var k in softwares.Keys()) j.Key(k).ObjStart().KNum("firstFile", softwares[k][0]).KNum("blocks", softwares[k][1]).EndObj(); j.EndObj();
                j.Key("totals").ObjStart().KNum("rows", tRows).KNum("lines", tLines).KNum("malformed", tMalformed).KNum("blocks", tBlocks).KNum("nonAscii", tNonAscii)
                    .KNum("decodeErr", tDecodeErr).KNum("firstTs", tFirst).KNum("lastTs", tLast).KNum("bytes", tBytes).EndObj();
                j.Key("perDay").ObjStart(); foreach (var k in perDay.Keys()) { j.Key(k).ArrStart(); foreach (var x in perDay[k]) j.Num(x); j.EndArr(); } j.EndObj();
                j.Key("perHour").ObjStart(); foreach (var k in perHour.Keys()) { j.Key(k).ArrStart(); foreach (var x in perHour[k]) j.Num(x); j.EndArr(); } j.EndObj();
                j.Key("ips").ObjStart();
                foreach (var k in ips.Keys())
                {
                    var r = ips[k]; j.Key(k).ObjStart();
                    j.KNum("n", r.n).KNum("first", r.first).KNum("last", r.last).KStr("cls", r.cls).KNum("s2", r.s2).KNum("s3", r.s3).KNum("s4", r.s4).KNum("s5", r.s5);
                    MapNum(j, "m", r.m); MapNum(j, "st", r.st); j.KNum("stN", r.stN).KNum("stOv", r.stOv); MapNum(j, "ua", r.ua); j.KNum("uaN", r.uaN).KNum("uaOv", r.uaOv);
                    j.KNum("exec", r.exec).KNum("stat", r.stat).KNum("post", r.post); MapNum(j, "d", r.d); j.KNum("dN", r.dN).KNum("dOv", r.dOv); MapNum(j, "hits", r.hits);
                    j.KNum("php", r.php).KNum("dn", r.dn).KNum("firstExp", r.firstExp).KNum("ms5", r.ms5).KNum("ms5t", r.ms5t).KNum("mlogin", r.mlogin).KNum("mlogint", r.mlogint)
                     .KNum("m401", r.m401).KNum("m401t", r.m401t).KNum("a401ok", r.a401ok).KNum("muaDay", r.muaDay).KStr("muaDayD", r.muaDayD).KNum("mdl", r.mdl).KNum("mdlt", r.mdlt)
                     .KNum("menum", r.menum).KStr("menumS", r.menumS).KNum("md4", r.md4).KStr("md4d", r.md4d);
                    MapNum(j, "off", r.off);
                    j.EndObj();
                }
                j.EndObj();
                j.Key("stems").ObjStart();
                foreach (var k in stems.Keys())
                {
                    var s = stems[k]; j.Key(k).ObjStart();
                    j.KNum("n", s.n).KNum("first", s.first).KNum("last", s.last).KNum("fFile", s.fFile).KNum("fLine", s.fLine).KStr("fIp", s.fIp).KStr("raw", s.raw);
                    MapNum(j, "ips", s.ips); j.KNum("ipN", s.ipN).KNum("ipOv", s.ipOv).KNum("pubN", s.pubN).KNum("post", s.post).KNum("ok", s.ok).KNum("okPub", s.okPub).KNum("s4", s.s4).KNum("s5", s.s5);
                    MapNum(j, "sts", s.sts); j.KBool("exec", s.exec).KBool("upDir", s.upDir);
                    j.EndObj();
                }
                j.EndObj();
                j.Key("uas").ObjStart();
                foreach (var k in uas.Keys()) { var u = uas[k]; j.Key(k).ObjStart().KNum("n", u.n).KNum("first", u.first).KNum("last", u.last); MapNum(j, "ips", u.ips); j.KNum("ipN", u.ipN).KNum("ipOv", u.ipOv).KStr("fam", u.fam).EndObj(); }
                j.EndObj();
                j.Key("users").ObjStart();
                foreach (var k in users.Keys()) { var u = users[k]; j.Key(k).ObjStart().KNum("n", u.n).KNum("first", u.first).KNum("last", u.last).KNum("fFile", u.fFile).KNum("fLine", u.fLine); MapNum(j, "ips", u.ips); j.KNum("ipN", u.ipN).KNum("pub", u.pub).EndObj(); }
                j.EndObj();
                MapNum(j, "statuses", statuses); MapNum(j, "methods", methods); MapNum(j, "sports", sports); MapNum(j, "exts", exts); MapNum(j, "uaFams", uaFams);
                j.Key("restarts").ArrStart(); for (int i = 0; i < restarts.Count; i++) j.ObjStart().KNum("fileId", restarts[i][0]).KNum("line", restarts[i][1]).KStr("date", restartDates[i]).KNum("ts", restarts[i][2]).EndObj(); j.EndArr();
                j.Key("gaps").ArrStart(); foreach (var g in gaps) j.ObjStart().KNum("from", g[0]).KNum("to", g[1]).KNum("hours", g[2]).KNum("fileId", g[3]).KNum("line", g[4]).EndObj(); j.EndArr();
                MapNum(j, "lbKeys", lbKeys);
                j.Key("ruleHits").ObjStart();
                foreach (var k in ruleHits.Keys())
                {
                    var h = ruleHits[k]; j.Key(k).ObjStart().KNum("n", h.n).KStr("sev", h.sev).KNum("first", h.first).KNum("last", h.last);
                    j.Key("kept").ArrStart(); foreach (var e in h.kept) { j.ArrStart().Num((double)e[0]).Num((double)e[1]).Num((double)e[2]).Str((string)e[3]).Str((string)e[4]).EndArr(); } j.EndArr();
                    MapNum(j, "ips", h.ips); j.KNum("ipN", h.ipN); MapNum(j, "stems", h.stems); j.KNum("stN", h.stN);
                    j.Key("sx").ArrStart(); foreach (var x in h.sx) j.Num(x); j.EndArr();
                    j.EndObj();
                }
                j.EndObj();
                j.Key("caps").ObjStart().KNum("ipEvicted", ipEvicted).KNum("stemEvicted", stemEvicted).KNum("uaEvicted", uaEvicted).KNum("lbOv", lbOv).EndObj();
                j.Key("counts").ObjStart().KNum("ips", cIps).KNum("stems", cStems).KNum("uas", cUas).EndObj();
                j.EndObj();
            }
            if (File.Exists(outPath)) File.Delete(outPath);
            File.Move(outPath + ".tmp", outPath);
        }
    }
}
