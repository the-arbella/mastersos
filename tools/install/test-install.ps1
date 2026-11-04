<#
.SYNOPSIS
Tests tools/install/install.ps1 against a release served from this computer (python -m http.server).

.DESCRIPTION
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\install\test-install.ps1 -ReleaseDir <DIR> -Tag cli-<sha>

<DIR> holds mastersos-x86_64-pc-windows-msvc.zip and SHA256SUMS. Each case installs into its own empty
LOCALAPPDATA. The installer adds to the user PATH; the test puts the user PATH back as it was when it ends.
#>
param(
    [Parameter(Mandatory = $true)][string]$ReleaseDir,
    [Parameter(Mandatory = $true)][string]$Tag,
    # What `mastersos --version` prints: a real build says "mastersos 0.3.0"
    [string]$VersionPattern = '^mastersos [0-9]'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$installer = Join-Path $PSScriptRoot 'install.ps1'
$asset = 'mastersos-x86_64-pc-windows-msvc.zip'

function Fail([string]$Message, [string]$Log) {
    if ($Log -and (Test-Path -LiteralPath $Log)) { Get-Content -LiteralPath $Log | Write-Host }
    throw "FAIL: $Message"
}
function Pass([string]$Message) { Write-Host "ok: $Message" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("mastersos-install-test-" + [Guid]::NewGuid().ToString('N'))
$www = Join-Path $tmp 'www'
New-Item -ItemType Directory -Path (Join-Path $www $Tag) | Out-Null
Copy-Item -Path (Join-Path $ReleaseDir '*') -Destination (Join-Path $www $Tag)
if (-not (Test-Path -LiteralPath (Join-Path $www "$Tag\SHA256SUMS"))) { Fail "no SHA256SUMS in $ReleaseDir" }

# The tampered copy: every line of SHA256SUMS names another hash
$tampered = Join-Path $www "tampered\$Tag"
New-Item -ItemType Directory -Path $tampered | Out-Null
Copy-Item -Path (Join-Path $www "$Tag\*") -Destination $tampered
$zeros = '0' * 64
Get-Content -LiteralPath (Join-Path $www "$Tag\SHA256SUMS") |
    ForEach-Object { "$zeros  " + ($_.Trim() -split '\s+')[1] } |
    Set-Content -LiteralPath (Join-Path $tampered 'SHA256SUMS') -Encoding Ascii

# The newest-release lookup reads the GitHub API's list; a fake list with an image release first
@"
[
  {"tag_name": "image-release-20261101.1", "draft": false},
  {"tag_name": "$Tag", "draft": false},
  {"tag_name": "cli-000000000000", "draft": false}
]
"@ | Set-Content -LiteralPath (Join-Path $www 'releases.json') -Encoding Ascii

$python = (Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $python) { Fail 'no python to serve the release' }
$port = Get-Random -Minimum 20000 -Maximum 60000
$server = Start-Process -FilePath $python -ArgumentList @('-m', 'http.server', '--bind', '127.0.0.1', '--directory', $www, "$port") `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $tmp 'server.out') -RedirectStandardError (Join-Path $tmp 'server.err')
$base = "http://127.0.0.1:$port"

$envKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
$savedPath = $envKey.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$savedKind = if ($null -ne $savedPath) { $envKey.GetValueKind('Path') } else { $null }

# Runs the installer in a new Windows PowerShell, as IT would; returns its exit code
function Invoke-Installer([string]$Name, [string]$ReleaseBase, [string[]]$Arguments, [switch]$Piped) {
    $home_ = Join-Path $tmp $Name
    New-Item -ItemType Directory -Force -Path $home_ | Out-Null
    $log = Join-Path $tmp "$Name.log"
    $env:LOCALAPPDATA = $home_
    $env:MASTERSOS_RELEASE_BASE = $ReleaseBase
    $env:MASTERSOS_RELEASES_API = "$base/releases.json"
    if ($Piped) {
        # `irm … | iex`, the way the README gives it
        & powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -Raw -LiteralPath '$installer' | Invoke-Expression" *> $log
    } else {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $installer @Arguments *> $log
    }
    return $LASTEXITCODE
}

$savedLocalAppData = $env:LOCALAPPDATA
try {
    $up = $false
    foreach ($i in 1..50) {
        try { Invoke-WebRequest -UseBasicParsing -Uri "$base/releases.json" | Out-Null; $up = $true; break } catch { Start-Sleep -Milliseconds 200 }
    }
    if (-not $up) { Fail 'the local release server did not start' }

    # 1. A given version: both programs installed, the absolute path and the version printed, user PATH updated
    $code = Invoke-Installer -Name 'case1' -ReleaseBase $base -Arguments @('-Version', $Tag)
    $log = Join-Path $tmp 'case1.log'
    $dir = Join-Path $tmp 'case1\Programs\mastersos'
    if ($code -ne 0) { Fail "install -Version $Tag exited $code" $log }
    foreach ($name in 'mastersos.exe', 'mastersos-sign.exe') {
        if (-not (Test-Path -LiteralPath (Join-Path $dir $name) -PathType Leaf)) { Fail "$name not installed" $log }
    }
    $out = & (Join-Path $dir 'mastersos.exe') --version
    if ("$out" -notmatch $VersionPattern) { Fail "installed mastersos --version printed: $out" $log }
    $text = Get-Content -Raw -LiteralPath $log
    if (-not $text.Contains((Join-Path $dir 'mastersos.exe'))) { Fail 'installed path not printed' $log }
    if ($text -notmatch "(?m)$VersionPattern") { Fail 'version not printed' $log }
    $userPath = [string]$envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (@($userPath -split ';') -notcontains $dir) { Fail "user PATH does not have $dir" $log }
    Pass "install -Version $Tag"

    # 2. Again over the installed copy (an upgrade); the user PATH gets no second entry
    $code = Invoke-Installer -Name 'case1' -ReleaseBase $base -Arguments @('-Version', $Tag)
    if ($code -ne 0) { Fail "reinstall exited $code" $log }
    $userPath = [string]$envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (@($userPath -split ';' | Where-Object { $_ -eq $dir }).Count -ne 1) { Fail 'user PATH has the folder twice' $log }
    Pass 'reinstall over an existing copy'

    # 3. No version, piped into Invoke-Expression: the newest cli-* release in the list
    $code = Invoke-Installer -Name 'case3' -ReleaseBase $base -Piped
    $log = Join-Path $tmp 'case3.log'
    if ($code -ne 0) { Fail "piped install of the newest exited $code" $log }
    if (-not (Get-Content -Raw -LiteralPath $log).Contains($Tag)) { Fail "newest release was not $Tag" $log }
    if (-not (Test-Path -LiteralPath (Join-Path $tmp 'case3\Programs\mastersos\mastersos.exe'))) { Fail 'newest: not installed' $log }
    Pass 'install the newest release through irm | iex'

    # 4. A tampered SHA256SUMS: refused, nothing installed
    $code = Invoke-Installer -Name 'case4' -ReleaseBase "$base/tampered" -Arguments @('-Version', $Tag)
    $log = Join-Path $tmp 'case4.log'
    if ($code -eq 0) { Fail 'tampered SHA256SUMS accepted' $log }
    if ((Get-Content -Raw -LiteralPath $log) -notmatch 'SHA-256') { Fail 'tampered: no checksum message' $log }
    if (Test-Path -LiteralPath (Join-Path $tmp 'case4\Programs\mastersos')) { Fail 'tampered: something was installed' $log }
    Pass 'tampered SHA256SUMS refused, nothing installed'

    # 5. A version that does not exist: refused, nothing installed
    $code = Invoke-Installer -Name 'case5' -ReleaseBase $base -Arguments @('-Version', 'cli-ffffffffffff')
    if ($code -eq 0) { Fail 'missing release accepted' (Join-Path $tmp 'case5.log') }
    if (Test-Path -LiteralPath (Join-Path $tmp 'case5\Programs\mastersos')) { Fail 'missing release: something was installed' }
    Pass 'missing release refused'

    # 6. A version that is not a cli-* tag
    $code = Invoke-Installer -Name 'case6' -ReleaseBase $base -Arguments @('-Version', '..\evil')
    if ($code -eq 0) { Fail 'bad version accepted' (Join-Path $tmp 'case6.log') }
    Pass 'bad version refused'

    Write-Host 'all install.ps1 tests passed'
} finally {
    $env:LOCALAPPDATA = $savedLocalAppData
    if ($null -ne $savedPath) {
        $envKey.SetValue('Path', $savedPath, $savedKind)
    } else {
        $envKey.DeleteValue('Path', $false)
    }
    $envKey.Close()
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
