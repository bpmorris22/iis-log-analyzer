# Builds an oracle of UTC offsets for every Windows time zone: instants around every offset change
# 1990-2035 plus random instants.  -Engine win32 (default) uses the Win32 API that Windows itself uses
# (SystemTimeToTzSpecificLocalTimeEx with the zone's dynamic DST data); -Engine dotnet uses .NET TimeZoneInfo.
# Output: { engine, zones: { "<id>": [[utcMs, offsetMinutes], ...] } } -- consumed by the HTA /tztest self test.
param([string]$Out = (Join-Path $env:TEMP 'iisla-tz-oracle.json'), [ValidateSet('win32', 'dotnet')][string]$Engine = 'win32',
  [int]$FromYear = 1990, [int]$ToYear = 2035, [int]$Random = 300)
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class TzOracle {
  [StructLayout(LayoutKind.Sequential)] public struct SYSTEMTIME { public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds; }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct DTZI {
    public int Bias; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string StandardName; public SYSTEMTIME StandardDate; public int StandardBias;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DaylightName; public SYSTEMTIME DaylightDate; public int DaylightBias;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string TimeZoneKeyName; [MarshalAs(UnmanagedType.U1)] public bool DynamicDaylightTimeDisabled; }
  [DllImport("advapi32.dll")] static extern uint EnumDynamicTimeZoneInformation(uint index, out DTZI tz);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool SystemTimeToTzSpecificLocalTimeEx(ref DTZI tz, ref SYSTEMTIME utc, out SYSTEMTIME local);
  static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
  static int OffWin(DTZI z, long ms) {
    DateTime u = Epoch.AddMilliseconds(ms); SYSTEMTIME su = new SYSTEMTIME { Year = (ushort)u.Year, Month = (ushort)u.Month, Day = (ushort)u.Day, Hour = (ushort)u.Hour, Minute = (ushort)u.Minute, Second = (ushort)u.Second, Milliseconds = (ushort)u.Millisecond };
    SYSTEMTIME sl; if (!SystemTimeToTzSpecificLocalTimeEx(ref z, ref su, out sl)) throw new Exception("conversion failed " + Marshal.GetLastWin32Error());
    DateTime l = new DateTime(sl.Year, sl.Month, sl.Day, sl.Hour, sl.Minute, sl.Second, sl.Milliseconds, DateTimeKind.Utc);
    return (int)Math.Round((l - u).TotalMinutes);
  }
  static int OffNet(TimeZoneInfo z, long ms) { return (int)z.GetUtcOffset(DateTimeOffset.FromUnixTimeMilliseconds(ms)).TotalMinutes; }
  static void Zone(StringBuilder sb, string id, Func<long, int> off, int fromYear, int toYear, int random, Random rnd) {
    var pts = new List<long>();
    long a = (long)(new DateTime(fromYear, 1, 1, 0, 0, 0, DateTimeKind.Utc) - Epoch).TotalMilliseconds, b = (long)(new DateTime(toYear, 12, 31, 0, 0, 0, DateTimeKind.Utc) - Epoch).TotalMilliseconds;
    int prev = off(a);
    for (long t = a + 86400000L; t <= b; t += 86400000L) {
      int cur = off(t);
      if (cur != prev) {
        long lo = t - 86400000L, hi = t;
        while (hi - lo > 60000L) { long mid = lo + ((hi - lo) / 120000L) * 60000L; if (mid == lo) mid = lo + 60000L; if (off(mid) == prev) lo = mid; else hi = mid; }
        pts.Add(hi - 60000L); pts.Add(hi); pts.Add(hi + 60000L);
        prev = cur;
      }
    }
    for (int i = 0; i < random; i++) { pts.Add(a + (long)(rnd.NextDouble() * (b - a)) / 60000L * 60000L); }
    if (sb[sb.Length - 1] != '{') sb.Append(',');
    sb.Append('"').Append(id.Replace("\"", "")).Append("\":[");
    for (int i = 0; i < pts.Count; i++) { if (i > 0) sb.Append(','); sb.Append('[').Append(pts[i]).Append(',').Append(off(pts[i])).Append(']'); }
    sb.Append(']');
  }
  public static string Build(string engine, int fromYear, int toYear, int random) {
    var sb = new StringBuilder(); sb.Append("{\"engine\":\"" + engine + "\",\"zones\":{");
    var rnd = new Random(12345);
    if (engine == "win32") {
      for (uint i = 0; ; i++) {
        DTZI z; if (EnumDynamicTimeZoneInformation(i, out z) != 0) break;
        DTZI zz = z; Zone(sb, z.TimeZoneKeyName, ms => OffWin(zz, ms), fromYear, toYear, random, rnd);
      }
    } else {
      foreach (var z in TimeZoneInfo.GetSystemTimeZones()) { var zz = z; Zone(sb, z.Id, ms => OffNet(zz, ms), fromYear, toYear, random, rnd); }
    }
    sb.Append("}}");
    return sb.ToString();
  }
}
'@
$json = [TzOracle]::Build($Engine, $FromYear, $ToYear, $Random)
[IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding($false)))
Write-Output ("{0} oracle written: {1} ({2:N0} bytes)" -f $Engine, $Out, (Get-Item $Out).Length)
