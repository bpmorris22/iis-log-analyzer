# Produces the screenshots used by docs\manual.html and README.md from the synthetic demo logs.
#   node tools\make-demo-logs.js
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\capture-screens.ps1
# How: the HTA self-test runs on demo\LogFiles\W3SVC1 with /shots, which writes a static, script-free HTML snapshot of
# each view to test\snapshots. The desktop is never captured: each snapshot is rendered by headless Microsoft Edge (with a
# throw-away profile), and the PNG is scaled down to -MaxWidth. Paths under %USERPROFILE% are replaced with a neutral
# prefix first, and only the views listed in -Views are produced (the Case view lists recent evidence folders and other
# cases, so it is not included by default).
param(
  [string]$Root = (Join-Path (Split-Path $PSScriptRoot -Parent) 'demo\LogFiles\W3SVC1'),
  [string]$OutDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'docs\images'),
  [string]$Case = 'DEMO-2026-001',
  [string]$TimeZone = 'Eastern Standard Time',
  [string[]]$Views = @('overview', 'findings', 'grid', 'ipProfile', 'timeline', 'integrity'),
  [double]$Zoom = 1.2,          # UI scale = Windows display scale x Zoom; 1.2 at 200% gives a ~1600 px wide layout on a 3840 px screen
  [int]$MaxWidth = 1600,
  [string]$NeutralProfile = 'C:\Users\analyst'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing, System.Windows.Forms
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class CapDpi { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }'
[void][CapDpi]::SetProcessDPIAware()
$app = Split-Path $PSScriptRoot -Parent
$snap = Join-Path $app 'test\snapshots'
$result = Join-Path $env:TEMP 'iisla-capture.json'
if (Test-Path $result) { [IO.File]::Delete($result) }
if (Test-Path $snap) { Get-ChildItem $snap -Filter *.html | ForEach-Object { [IO.File]::Delete($_.FullName) } }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 1. snapshots (the HTA window is left alone: it opens maximized and closes itself)
$a = '"' + (Join-Path $app 'IISLogAnalyzer.hta') + '" /autotest "' + $Root + '" "/out:' + $result + '" /case:' + $Case + ' "/tz:' + $TimeZone + '" /testnets /engine:fast /load /shots /shotms:1500 /zoom:' + $Zoom
$p = Start-Process -FilePath "$env:WINDIR\System32\mshta.exe" -ArgumentList $a -PassThru
if (-not $p.WaitForExit(600000)) { $p.Kill(); throw 'self-test did not finish' }
$r = Get-Content $result -Raw | ConvertFrom-Json
if ($r.errors.Count) { throw ('self-test errors: ' + ($r.errors -join '; ')) }

# 2. render with headless Edge at the size of the maximized window's client area
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) { throw 'Microsoft Edge not found' }
$wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$vw = $wa.Width - 16; $vh = $wa.Height - 40
$profileDir = Join-Path $env:TEMP ('iisla-edge-' + [guid]::NewGuid().ToString('N'))
$work = Join-Path $env:TEMP ('iisla-snap-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $work | Out-Null
try {
  foreach ($v in $Views) {
    $src = Get-ChildItem $snap -Filter "*-$v.html" | Select-Object -First 1
    if (-not $src) { Write-Warning "no snapshot for $v"; continue }
    $html = [IO.File]::ReadAllText($src.FullName, [Text.Encoding]::UTF8).Replace($env:USERPROFILE, $NeutralProfile).Replace('</head>', '<style>#toasts{display:none !important}</style></head>')
    $tmp = Join-Path $work "$v.html"; [IO.File]::WriteAllText($tmp, $html, (New-Object Text.UTF8Encoding $false))
    $png = Join-Path $work "$v.png"
    $args2 = @('--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--disable-extensions', "--user-data-dir=$profileDir",
      '--force-device-scale-factor=1', "--window-size=$vw,$vh", "--screenshot=$png", ('file:///' + $tmp.Replace('\', '/')))
    $e = Start-Process -FilePath $edge -ArgumentList $args2 -PassThru -WindowStyle Hidden
    if (-not $e.WaitForExit(60000)) { $e.Kill() }
    if (-not (Test-Path $png)) { Write-Warning "Edge produced no image for $v"; continue }
    $img = [System.Drawing.Image]::FromFile($png)
    try {
      $w = [Math]::Min($MaxWidth, $img.Width); $hh = [int]($img.Height * $w / $img.Width)
      $small = New-Object System.Drawing.Bitmap $w, $hh
      $g = [System.Drawing.Graphics]::FromImage($small)
      $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
      $g.DrawImage($img, 0, 0, $w, $hh); $g.Dispose()
      $dst = Join-Path $OutDir "$v.png"; $small.Save($dst, [System.Drawing.Imaging.ImageFormat]::Png); $small.Dispose()
      Write-Output ("{0} ({1}x{2})" -f $dst, $w, $hh)
    } finally { $img.Dispose() }
  }
} finally {
  foreach ($d in $work, $profileDir) { if (Test-Path $d) { Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { try { [IO.File]::Delete($_.FullName) } catch { } } } }
}
