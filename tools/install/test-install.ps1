<#
.SYNOPSIS
Tests tools/install/install.ps1 against a release served from this computer (tools/install/fake-release.py).

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

# The newest-release lookup pages through the GitHub API's list: page 1 holds only image releases
@"
[
  {"tag_name": "image-release-20261102.1", "draft": false},
  {"tag_name": "image-release-20261101.1", "draft": false}
]
"@ | Set-Content -LiteralPath (Join-Path $www 'releases-1.json') -Encoding Ascii
@"
[
  {"tag_name": "image-release-20261031.1", "draft": false},
  {"tag_name": "$Tag", "draft": false},
  {"tag_name": "cli-000000000000", "draft": false}
]
"@ | Set-Content -LiteralPath (Join-Path $www 'releases-2.json') -Encoding Ascii

# `python` first: on a fresh Windows `python3` may be the Microsoft Store stub
$python = $null
foreach ($name in 'python', 'python3') {
    $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd -and $cmd.Source -notlike '*\WindowsApps\*') { $python = $cmd.Source; break }
}
if (-not $python) { Fail 'no python to serve the release' }
$portFile = Join-Path $tmp 'port'
$server = Start-Process -FilePath $python -PassThru -WindowStyle Hidden `
    -ArgumentList @('-I', "`"$(Join-Path $PSScriptRoot 'fake-release.py')`"", "`"$www`"", "`"$portFile`"") `
    -RedirectStandardOutput (Join-Path $tmp 'server.out') -RedirectStandardError (Join-Path $tmp 'server.err')

$envKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
$savedPath = $envKey.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$savedKind = if ($null -ne $savedPath) { $envKey.GetValueKind('Path') } else { $null }

# Runs the installer in a new Windows PowerShell, as IT would; returns its exit code. A refusing installer writes
# to stderr: that is the case under test, not an error of this script.
function Invoke-Installer {
    param(
        [string]$Name,
        [AllowEmptyString()][string]$ReleaseBase,
        [string[]]$Arguments = @(),
        [string]$Api = "$base/releases?per_page=100",
        [string]$VersionEnv = '',
        [switch]$Piped
    )
    $ErrorActionPreference = 'Continue'
    $home_ = Join-Path $tmp $Name
    New-Item -ItemType Directory -Force -Path $home_ | Out-Null
    $log = Join-Path $tmp "$Name.log"
    $env:LOCALAPPDATA = $home_
    $env:MASTERSOS_RELEASE_BASE = $ReleaseBase
    $env:MASTERSOS_RELEASES_API = $Api
    $env:MASTERSOS_VERSION = $VersionEnv
    try {
        if ($Piped) {
            # `irm … | iex`, the way the README gives it
            & powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -Raw -LiteralPath '$installer' | Invoke-Expression" *> $log
        } else {
            & powershell -NoProfile -ExecutionPolicy Bypass -File $installer @Arguments *> $log
        }
        return $LASTEXITCODE
    } finally {
        $env:MASTERSOS_VERSION = $null
    }
}

# Asserts a refused install: non-zero exit, the message, and nothing in the install folder
function Assert-Refused([string]$Name, [int]$Code, [string]$Message) {
    $log = Join-Path $tmp "$Name.log"
    if ($Code -eq 0) { Fail "${Name}: accepted" $log }
    if ($Message -and (Get-Content -Raw -LiteralPath $log) -notmatch $Message) { Fail "${Name}: no message like '$Message'" $log }
    if (Test-Path -LiteralPath (Join-Path $tmp "$Name\Programs\mastersos")) { Fail "${Name}: something was installed" $log }
}

$savedLocalAppData = $env:LOCALAPPDATA
try {
    foreach ($i in 1..50) {
        if ((Test-Path -LiteralPath $portFile) -and (Get-Content -Raw -LiteralPath $portFile)) { break }
        Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Path -LiteralPath $portFile)) { Fail 'the local release server did not start' (Join-Path $tmp 'server.err') }
    $base = "http://127.0.0.1:$((Get-Content -Raw -LiteralPath $portFile).Trim())"

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

    # 2. Again over the installed copy (an upgrade), with a stale .old left behind; the user PATH gets no second entry
    Set-Content -LiteralPath (Join-Path $dir 'mastersos.exe.0123.old') -Value 'stale'
    $code = Invoke-Installer -Name 'case1' -ReleaseBase $base -Arguments @('-Version', $Tag)
    if ($code -ne 0) { Fail "reinstall exited $code" $log }
    $userPath = [string]$envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (@($userPath -split ';' | Where-Object { $_ -eq $dir }).Count -ne 1) { Fail 'user PATH has the folder twice' $log }
    if (@(Get-ChildItem -LiteralPath $dir -Filter '*.old').Count -ne 0) { Fail 'old copies left behind' $log }
    Pass 'reinstall over an existing copy'

    # 3. No version, piped into Invoke-Expression: the newest cli-* release, on the list's second page
    $code = Invoke-Installer -Name 'case3' -ReleaseBase $base -Piped
    $log = Join-Path $tmp 'case3.log'
    if ($code -ne 0) { Fail "piped install of the newest exited $code" $log }
    if (-not (Get-Content -Raw -LiteralPath $log).Contains($Tag)) { Fail "newest release was not $Tag" $log }
    if (-not (Test-Path -LiteralPath (Join-Path $tmp 'case3\Programs\mastersos\mastersos.exe'))) { Fail 'newest: not installed' $log }
    Pass 'install the newest release through irm | iex'

    # 4. A tampered SHA256SUMS
    $code = Invoke-Installer -Name 'case4' -ReleaseBase "$base/tampered" -Arguments @('-Version', $Tag)
    Assert-Refused 'case4' $code 'SHA-256'
    Pass 'tampered SHA256SUMS refused, nothing installed'

    # 5. A version that does not exist
    $code = Invoke-Installer -Name 'case5' -ReleaseBase $base -Arguments @('-Version', 'cli-ffffffffffff')
    Assert-Refused 'case5' $code 'could not download'
    Pass 'missing release refused'

    # 6. A version that is not a cli-* tag
    $code = Invoke-Installer -Name 'case6' -ReleaseBase $base -Arguments @('-Version', '..\evil')
    Assert-Refused 'case6' $code 'must look like'
    Pass 'bad version refused'

    # 7. A version with a newline in it (through MASTERSOS_VERSION): refused as a whole, not line by line
    $code = Invoke-Installer -Name 'case7' -ReleaseBase $base -VersionEnv "$Tag`n..\evil"
    Assert-Refused 'case7' $code 'must look like'
    Pass 'version with a newline refused'

    # 8. Without the test override, plain http is refused
    $code = Invoke-Installer -Name 'case8' -ReleaseBase '' -Arguments @('-Version', $Tag)
    Assert-Refused 'case8' $code 'only https://'
    Pass 'plain http refused without MASTERSOS_RELEASE_BASE'

    # 9. The release list cannot be read (GitHub's anonymous rate limit answers 403)
    $code = Invoke-Installer -Name 'case9' -ReleaseBase $base -Api "$base/no-such-list"
    Assert-Refused 'case9' $code 'GitHub limits anonymous lookups'
    Pass 'unreadable release list explained'

    Write-Host 'all install.ps1 tests passed'
} finally {
    $env:LOCALAPPDATA = $savedLocalAppData
    $env:MASTERSOS_RELEASE_BASE = $null
    $env:MASTERSOS_RELEASES_API = $null
    if ($null -ne $savedPath) {
        $envKey.SetValue('Path', $savedPath, $savedKind)
    } else {
        $envKey.DeleteValue('Path', $false)
    }
    $envKey.Close()
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
