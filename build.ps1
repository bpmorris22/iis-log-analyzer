# Builds a single-file distribution: dist\IISLogAnalyzer.hta with all CSS/JS inlined and the
# rules, lists and default settings embedded as <script type="text/plain" data-res="..."> blocks.
# The folder layout (IISLogAnalyzer.hta + lib\ + rules\ + lists\ + config\) remains the primary,
# editable form; the single file is convenient for copying onto a forensic workstation.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
function ReadText($rel) { [IO.File]::ReadAllText((Join-Path $root $rel), [Text.Encoding]::UTF8) }
function Guard($text, $rel, $tag = 'script') { if ($text -match ('</' + $tag)) { throw "$rel contains a closing $tag tag and cannot be inlined" } }

$html = ReadText 'IISLogAnalyzer.hta'
$css = ReadText 'lib\app.css'; Guard $css 'lib\app.css'
$html = $html.Replace('<link rel="stylesheet" id="appcss" href="lib/app.css">', "<style id=""appcss"">`r`n" + $css + "`r`n</style>")
$scripts = [regex]::Matches($html, '<script src="(lib/[a-z0-9]+\.js)"></script>')
foreach ($m in $scripts) {
  $rel = $m.Groups[1].Value
  $js = ReadText ($rel -replace '/', '\'); Guard $js $rel
  $html = $html.Replace($m.Value, "<script>/* $rel */`r`n" + $js + "`r`n</script>")
}
$res = New-Object System.Text.StringBuilder
$resFiles = @('rules\default-rules.json', 'config\settings.json', 'engine\IISScanEngine.cs', 'engine\Scan-IISLogs.ps1') + (Get-ChildItem (Join-Path $root 'lists') -Filter *.txt | ForEach-Object { 'lists\' + $_.Name })
foreach ($rel in $resFiles) {
  $t = ReadText $rel; Guard $t $rel
  [void]$res.Append('<script type="text/plain" data-res="' + ($rel -replace '\\', '/') + '">' + $t + "</script>`r`n")
}
$html = $html.Replace('<div id="toasts"></div>', '<div id="toasts"></div>' + "`r`n" + $res.ToString())
$out = Join-Path $dist 'IISLogAnalyzer.hta'
[IO.File]::WriteAllText($out, $html, $utf8)
$h = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower()
"$h  IISLogAnalyzer.hta" | Set-Content -LiteralPath ($out + '.sha256') -Encoding ascii
Write-Output ("Built {0} ({1:N0} bytes, {2} scripts, {3} resources) SHA-256 {4}" -f $out, (Get-Item $out).Length, $scripts.Count, $resFiles.Count, $h)
