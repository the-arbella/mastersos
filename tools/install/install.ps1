<#
.SYNOPSIS
Installs the MastersOS command line (mastersos.exe, mastersos-sign.exe) for the current Windows user.

.DESCRIPTION
Downloads mastersos-x86_64-pc-windows-msvc.zip and SHA256SUMS from the GitHub release, checks the SHA-256 before
anything is installed, installs into %LOCALAPPDATA%\Programs\mastersos and adds that folder to the user PATH.
No administrator rights.

  irm https://raw.githubusercontent.com/the-arbella/mastersos/master/tools/install/install.ps1 | iex
  & ([scriptblock]::Create((irm https://raw.githubusercontent.com/the-arbella/mastersos/master/tools/install/install.ps1))) -Version cli-0123456789ab

Environment (for tests and mirrors):
  MASTERSOS_VERSION        the release to install, like -Version
  MASTERSOS_RELEASE_BASE   download base; assets are read from <base>/<version>/<asset>
  MASTERSOS_RELEASES_API   the release list (GitHub API JSON) used to find the newest cli-* release

.PARAMETER Version
The release tag, such as cli-0123456789ab. Default: the newest cli-* release.
#>
param(
    [string]$Version = $env:MASTERSOS_VERSION
)

# Everything runs inside the function, so `irm | iex` leaves IT's PowerShell session as it was (preferences,
# strict mode). Errors throw instead of `exit`: run through `irm | iex`, exit would close IT's window.
function Install-MastersOS([string]$Version) {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 3
    # Invoke-WebRequest in Windows PowerShell 5.1 is slow with its progress bar on
    $ProgressPreference = 'SilentlyContinue'
    # Windows PowerShell 5.1 may not offer TLS 1.2 by default (this one adds to the process's list, it removes nothing)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    function Stop-Install([string]$Message) {
        throw "mastersos install: $Message"
    }

    $repo = 'the-arbella/mastersos'
    $base = if ($env:MASTERSOS_RELEASE_BASE) { $env:MASTERSOS_RELEASE_BASE } else { "https://github.com/$repo/releases/download" }
    $api = if ($env:MASTERSOS_RELEASES_API) { $env:MASTERSOS_RELEASES_API } else { "https://api.github.com/repos/$repo/releases?per_page=100" }
    # HTTPS only; plain http only for a release served by a test (MASTERSOS_RELEASE_BASE set)
    foreach ($url in @($base, $api)) {
        if ($url -notlike 'https://*' -and -not $env:MASTERSOS_RELEASE_BASE) {
            Stop-Install "only https:// addresses are used, not: $url"
        }
    }

    # Only an x64 build: Windows 11 on ARM runs it through its x64 emulation
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -ne 'AMD64' -and $arch -ne 'ARM64') {
        Stop-Install "no build for Windows on $arch"
    }
    $target = 'x86_64-pc-windows-msvc'
    $asset = "mastersos-$target.zip"

    $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [Environment]::GetFolderPath('LocalApplicationData') }
    if (-not $localAppData) {
        Stop-Install 'LOCALAPPDATA is not set'
    }
    $dir = [IO.Path]::GetFullPath((Join-Path $localAppData 'Programs\mastersos'))

    $version = $Version
    if (-not $version) {
        # The list is newest first, 100 to a page; the first cli-* tag is the newest command line release.
        # Image releases come in between, so read further pages until one has a cli-* tag or the list ends.
        $sep = if ($api.Contains('?')) { '&' } else { '?' }
        for ($page = 1; $page -le 30 -and -not $version; $page++) {
            try {
                $releases = @(Invoke-RestMethod -UseBasicParsing -Uri "$api${sep}page=$page")
            } catch {
                Stop-Install "could not read the list of releases from $api ($($_.Exception.Message)). GitHub limits anonymous lookups; try again later or pass -Version cli-<commit>"
            }
            # Windows PowerShell 5.1 hands a JSON array over as one object
            $releases = @($releases | ForEach-Object { $_ })
            if ($releases.Count -eq 0) { break }
            $newest = @($releases | Where-Object { $_.tag_name -like 'cli-*' }) | Select-Object -First 1
            if ($newest) { $version = [string]$newest.tag_name }
        }
        if (-not $version) {
            Stop-Install "no cli-* release found at $api"
        }
    }
    # \A…\z: `$` would also match before a trailing newline
    if ($version -cnotmatch '\Acli-[0-9a-z]+\z') {
        Stop-Install "the version must look like cli-0123456789ab (a release tag), not: $version"
    }

    Write-Output "Installing MastersOS command line $version for $target"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mastersos-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $sums = Join-Path $tmp 'SHA256SUMS'
        $zip = Join-Path $tmp $asset
        foreach ($pair in @(@("$base/$version/SHA256SUMS", $sums), @("$base/$version/$asset", $zip))) {
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $pair[0] -OutFile $pair[1]
            } catch {
                Stop-Install "could not download $($pair[0]): $($_.Exception.Message)"
            }
        }

        $expected = $null
        foreach ($line in Get-Content -LiteralPath $sums) {
            $fields = $line.Trim() -split '\s+'
            if ($fields.Count -eq 2 -and ($fields[1] -ceq $asset -or $fields[1] -ceq "*$asset")) {
                $expected = $fields[0].ToLowerInvariant()
                break
            }
        }
        if (-not $expected) {
            Stop-Install "SHA256SUMS has no line for ${asset}: nothing installed"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
        if ($expected -ne $actual) {
            Stop-Install "the SHA-256 of $asset does not match SHA256SUMS (expected $expected, got $actual): nothing installed"
        }

        $unpacked = Join-Path $tmp 'x'
        Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
        $names = @('mastersos.exe', 'mastersos-sign.exe')
        foreach ($name in $names) {
            if (-not (Test-Path -LiteralPath (Join-Path $unpacked $name) -PathType Leaf)) {
                Stop-Install "$asset has no ${name}: nothing installed"
            }
        }

        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        foreach ($name in $names) {
            Copy-Item -LiteralPath (Join-Path $unpacked $name) -Destination (Join-Path $dir "$name.new") -Force
        }
        # Leftovers of earlier installs that were still running then
        Get-ChildItem -LiteralPath $dir -Filter '*.old' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        foreach ($name in $names) {
            $path = Join-Path $dir $name
            # A running mastersos.exe (`mastersos mcp`) cannot be overwritten, but it can be renamed; the name is new
            # every time, so a locked leftover can never stop the second program from being replaced
            if (Test-Path -LiteralPath $path) {
                $old = "$path.$([Guid]::NewGuid().ToString('N')).old"
                Move-Item -LiteralPath $path -Destination $old -Force
                Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            }
            Move-Item -LiteralPath "$path.new" -Destination $path -Force
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $exe = Join-Path $dir 'mastersos.exe'
    $installed = & $exe --version
    if ($LASTEXITCODE -ne 0) {
        Stop-Install "installed $exe, but it does not run on this computer"
    }
    Write-Output "Installed $exe"
    Write-Output "Installed $(Join-Path $dir 'mastersos-sign.exe')"
    Write-Output "$installed"

    # The user PATH (never the machine PATH), read and written raw so %VARIABLES% in it stay unexpanded
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $entries = @($userPath -split ';' | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') })
        if ($entries -notcontains $dir.TrimEnd('\')) {
            $newPath = if ($userPath.TrimEnd(';')) { $userPath.TrimEnd(';') + ";$dir" } else { $dir }
            $key.SetValue('Path', $newPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            # Setting a user variable through .NET tells open programs (Explorer, new terminals) that the environment changed
            [Environment]::SetEnvironmentVariable('MASTERSOS_INSTALL_NOTIFY', '1', 'User')
            [Environment]::SetEnvironmentVariable('MASTERSOS_INSTALL_NOTIFY', $null, 'User')
            Write-Output "Added $dir to your user PATH. Open a new terminal to use mastersos."
        }
    } finally {
        $key.Close()
    }
    if (@($env:Path -split ';' | ForEach-Object { $_.TrimEnd('\') }) -notcontains $dir.TrimEnd('\')) {
        $env:Path = "$env:Path;$dir"
    }
    Write-Output ''
    Write-Output "Next: mastersos connect <your school's admin address>"
}

try {
    Install-MastersOS -Version $Version
} finally {
    Remove-Item -LiteralPath Function:\Install-MastersOS -ErrorAction SilentlyContinue
}
