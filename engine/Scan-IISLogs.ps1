# IIS Log Analyzer - fast scan engine launcher.
# Compiles IISScanEngine.cs once per source version (cached under %LOCALAPPDATA%\IISLogAnalyzer\engine)
# and runs it on a job file written by the HTA. Requires only Windows PowerShell 5.1 / .NET Framework 4.x.
#   powershell -NoProfile -ExecutionPolicy Bypass -File Scan-IISLogs.ps1 -Job <job.json>
#   powershell -NoProfile -ExecutionPolicy Bypass -File Scan-IISLogs.ps1 -CompileOnly
param([string]$Job = '', [switch]$CompileOnly)
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'IISScanEngine.cs'
$code = [IO.File]::ReadAllText($src)
$sha = [Security.Cryptography.SHA256]::Create()
$hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($code))[0..7] | ForEach-Object { $_.ToString('x2') })
$cache = Join-Path $env:LOCALAPPDATA 'IISLogAnalyzer\engine'
$dll = Join-Path $cache ("IISScanEngine-$hash.dll")
$doneFile = ''
try {
  if ($Job) {
    $j = Get-Content -LiteralPath $Job -Raw | ConvertFrom-Json
    $doneFile = $j.output + '.done'
    # PID for the HTA watchdog (detects an engine that dies without writing the completion marker)
    [IO.File]::WriteAllText($j.output + '.pid', [string]$PID)
  }
  if (-not (Test-Path -LiteralPath $dll)) {
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    Add-Type -TypeDefinition $code -Language CSharp -OutputAssembly $dll -OutputType Library -ReferencedAssemblies 'System.Core'
  }
  if ($CompileOnly) { Write-Output "compiled: $dll"; exit 0 }
  [void][Reflection.Assembly]::LoadFile($dll)
  [void][IISLA.ScanEngine]::Run($Job)
  exit 0
} catch {
  $msg = 'ERROR ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message
  if ($doneFile -and -not (Test-Path -LiteralPath $doneFile)) { [IO.File]::WriteAllText($doneFile, $msg) }
  Write-Error $msg
  exit 1
}
