# Runs IISLogAnalyzer.hta in self-test mode inside the real mshta engine and prints the result JSON.
# Usage: powershell -NoProfile -File test\run-autotest.ps1 -Root <siteFolder> [-Files <regex>] [-Load] [-Hash] [-NoScan] [-TimeoutSec 900]
#   -NoScan  reuse the case's cached index (measures index reload instead of scanning)
# The mshta process is stopped if its private memory exceeds -MaxMemGB (default 12).
param(
  [Parameter(Mandatory = $true)][string]$Root,
  [string]$Files = '',
  [switch]$Load,
  [switch]$Hash,
  [switch]$NoScan,
  [string]$FilterQ = '',
  [int]$CancelAfter = 0,
  [string]$Case = 'AUTOTEST-IISLA',
  [string]$Out = '',
  [int]$TimeoutSec = 900,
  [int]$MaxMemGB = 12,
  [string]$Extra = ''   # extra HTA switches, e.g. '/engine:builtin /rawbundle /streammb:16'
)
$hta = Join-Path (Split-Path $PSScriptRoot -Parent) 'IISLogAnalyzer.hta'
if (-not $Out) { $Out = Join-Path $PSScriptRoot ('autotest-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json') }
$trace = Join-Path $env:TEMP 'iisla-trace.log'
Remove-Item $Out, $trace -ErrorAction SilentlyContinue
$a = '"' + $hta + '" /autotest "' + $Root + '" "/out:' + $Out + '" /case:' + $Case
if ($Files) { $a += ' "/files:' + $Files + '"' }
if ($Load) { $a += ' /load' }
if ($Hash) { $a += ' /hash' }
if ($NoScan) { $a += ' /noscan' }
if ($FilterQ) { $a += ' "/filterq:' + $FilterQ + '"' }
if ($CancelAfter) { $a += ' /cancelafter:' + $CancelAfter }
if ($Extra) { $a += ' ' + $Extra }
$p = Start-Process -FilePath "$env:WINDIR\System32\mshta.exe" -ArgumentList $a -PassThru
$t0 = Get-Date
$peak = 0
while (-not (Test-Path $Out) -and -not $p.HasExited -and ((Get-Date) - $t0).TotalSeconds -lt $TimeoutSec) {
  Start-Sleep -Milliseconds 1000
  try { $m = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p.Id)).PrivatePageCount; if ($m -gt $peak) { $peak = $m } } catch { }
  if ($peak -gt ($MaxMemGB * 1GB)) { Write-Output "ABORT: mshta private memory exceeded $MaxMemGB GB"; break }
}
Start-Sleep -Milliseconds 800
$elapsed = [int]((Get-Date) - $t0).TotalSeconds
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Confirm:$false -ErrorAction SilentlyContinue; Write-Output "mshta stopped after $elapsed s" }
Write-Output ("elapsed: {0} s; peak private memory: {1:N0} MB; result: {2} exists={3}" -f $elapsed, ($peak / 1MB), $Out, (Test-Path $Out))
if (Test-Path $trace) { Write-Output '--- trace ---'; Get-Content $trace | Select-Object -Last 60 }
if (Test-Path $Out) { Write-Output '--- result ---'; Get-Content $Out -Raw }
