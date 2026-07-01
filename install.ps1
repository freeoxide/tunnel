<#
.SYNOPSIS
    Installs the Freeoxide Tunnel CLI (`ft`) on Windows from a GitHub release.
.DESCRIPTION
    Designed for the one-liner:

        irm https://tunnel.freeoxide.com/install.ps1 | iex

    Downloads the prebuilt freeoxide-tunnel-<target>.zip and its matching
    SHA256SUMS, verifies the archive hash against that file (a missing or
    mismatching checksum is a hard failure, never silently skipped), extracts
    ft.exe, and places it in the install directory. Adds the install directory
    to the USER Path if it is not already present.

    Runs on both Windows PowerShell 5.1 and PowerShell 7+ (pwsh).
.PARAMETER InstallDir
    Directory to place ft.exe. Defaults to $env:USERPROFILE\.local\bin.
.PARAMETER Version
    Release tag to install, or "latest" (the default).
.EXAMPLE
    irm https://tunnel.freeoxide.com/install.ps1 | iex
.EXAMPLE
    ./install.ps1 -Version v0.1.0
.EXAMPLE
    ./install.ps1 -InstallDir D:\tools\bin
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:USERPROFILE '.local\bin'),
    [string]$Version = 'latest'
)

# --- Bootstrap ---------------------------------------------------------------
# irm | iex runs the script in an untitled environment without access to the
# original $ErrorActionPreference, so force non-terminating cmdlet errors to
# throw. This makes every Invoke-WebRequest / Get-FileHash below land in our
# catch blocks with an actionable message instead of silently continuing.
$ErrorActionPreference = 'Stop'

# Force TLS 1.2+ for downloads. Windows PowerShell 5.1 defaults to TLS 1.0,
# which GitHub refuses; PS 7+ already negotiates higher, so this is a harmless
# no-op there. Set before any Invoke-WebRequest below.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # pwsh has no [Net.ServicePointManager]; it negotiates TLS 1.2+ by default.
}

$Repo = 'freeoxide/tunnel'
$AssetStem = 'freeoxide-tunnel'   # release asset: <stem>-<target>.zip

# Tiny wrappers around Write-Host/Warning so the colored output is consistent
# and shows up under `irm | iex` (success stream, not just redirected files).
function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "    $Message" -ForegroundColor Green }
function Write-WarnLine([string]$Message) { Write-Warning $Message }

# --- Resolve architecture -> Rust target -------------------------------------
# Map the running process architecture to the Rust release target triple. Use
# [RuntimeInformation] when available (PS 7+, and PS 5.1 on .NET 4.7.1+); fall
# back to the PROCESSOR_ARCHITECTURE env var which 5.1 always exposes.
function Resolve-Target {
    $arch = $null
    try {
        # Architecture enum values: Arm, Arm64, X86, X64.
        $pa = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
        $arch = [string]$pa
    } catch {
        # PS 5.1 on older .NET lacks RuntimeInformation; the env var is the
        # documented fallback. Values: AMD64, ARM64, x86.
        $arch = $env:PROCESSOR_ARCHITECTURE
    }

    # -match is case-insensitive by default, so X64/AMD64 and Arm64 from either
    # source (the .NET enum string or the env var) both resolve correctly.
    $a = "$arch"
    if ($a -match '^(X64|AMD64)$') { return 'x86_64-pc-windows-msvc' }
    if ($a -match '^Arm64$')       { return 'aarch64-pc-windows-msvc' }

    throw "Unsupported process architecture: '$arch'. Freeoxide Tunnel ships Windows builds for x64 and ARM64 only."
}

# --- Build the download URL for a given asset name ---------------------------
function Resolve-AssetUrl([string]$AssetName) {
    $base = "https://github.com/$Repo/releases"
    if ($Version -eq 'latest') {
        return "$base/latest/download/$AssetName"
    }
    # Pinned tag. Accept both "0.1.0" and "v0.1.0"; GitHub tags are v-prefixed.
    $tag = if ($Version -match '^v') { $Version } else { "v$Version" }
    return "$base/download/$tag/$AssetName"
}

try {
    Write-Step 'Detecting architecture'
    $target = Resolve-Target
    Write-Ok "Target triple: $target"

    $assetName = "$AssetStem-$target.zip"
    $assetUrl  = Resolve-AssetUrl $assetName
    $sumsName  = 'SHA256SUMS'
    $sumsUrl   = Resolve-AssetUrl $sumsName

    Write-Step 'Preparing download locations'
    # Unique temp subdir so concurrent installs (or a re-run) never collide,
    # and so cleanup is a single recursive delete in finally {}.
    $tempRoot = [System.IO.Path]::GetTempPath()
    $tempDir  = Join-Path $tempRoot ("ft-install-" + [System.Diagnostics.Process]::GetCurrentProcess().Id + '-' + ([System.Guid]::NewGuid().ToString('N')))
    $null = New-Item -ItemType Directory -Path $tempDir -Force
    Write-Ok "Temp dir: $tempDir"

    $zipPath = Join-Path $tempDir $assetName
    $sumsPath = Join-Path $tempDir $sumsName

    Write-Step "Downloading $sumsName"
    # SHA256SUMS first: if it is missing we fail before installing an
    # unverifiable binary. -UseBasicParsing avoids the IE engine dependency on
    # PS 5.1 (no COM/ Trident, no `iex` warnings).
    try {
        Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsPath -UseBasicParsing
    } catch {
        throw "Could not download SHA256SUMS from $sumsUrl. Refusing to install without integrity verification. ($($_.Exception.Message))"
    }
    Write-Ok "Saved $sumsName"

    Write-Step "Downloading $assetName"
    try {
        Invoke-WebRequest -Uri $assetUrl -OutFile $zipPath -UseBasicParsing
    } catch {
        throw "Could not download $assetName from $assetUrl. Check that the release/version exists. ($($_.Exception.Message))"
    }
    Write-Ok "Saved $assetName"

    Write-Step 'Verifying SHA-256 against SHA256SUMS'
    # Format is the standard coreutils style: "<64-hex-hash>  <filename>" per
    # line, two spaces separating hash and name. Match the entry whose name is
    # exactly our asset (basename), so a stray checksum for a different file
    # can never satisfy our verification.
    $sumsText = Get-Content -Raw -Path $sumsPath
    $expected = $null
    foreach ($line in ($sumsText -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        # Split on whitespace; first field is the hash, last is the name.
        $parts = $line -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($parts.Count -lt 2) { continue }
        $hash = $parts[0]
        $name = $parts[$parts.Count - 1]
        if ($name -eq $assetName) { $expected = $hash.ToLowerInvariant(); break }
    }
    if (-not $expected) {
        throw "SHA256SUMS has no entry for '$assetName'. Refusing to install without a matching checksum."
    }

    $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $assetName.`n  expected: $expected`n  actual:   $actual`nThe downloaded archive is corrupt or was tampered with."
    }
    Write-Ok "Checksum OK ($expected)"

    Write-Step "Installing to $InstallDir"
    $null = New-Item -ItemType Directory -Path $InstallDir -Force

    # The archive ships ft.exe at its root. Expand to the temp dir, then move
    # just the binary into place so we never clobber unrelated files in
    # InstallDir.
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
    $extractedExe = Join-Path $tempDir 'ft.exe'
    if (-not (Test-Path -LiteralPath $extractedExe)) {
        throw "Archive did not contain ft.exe at its root. The release packaging may have changed."
    }

    $destExe = Join-Path $InstallDir 'ft.exe'
    # If an older ft.exe is already present, remove it first: on Windows a
    # running/locked binary would make Move-Item fail, and an explicit replace
    # gives a clearer error than a partial overwrite.
    if (Test-Path -LiteralPath $destExe) {
        Remove-Item -LiteralPath $destExe -Force
    }
    Move-Item -LiteralPath $extractedExe -Destination $destExe -Force
    Write-Ok "Installed $destExe"

    Write-Step 'Updating USER Path'
    # Read the persistent USER Path (not the merged process Path) so we append
    # exactly once and never duplicate or clobber Machine/system entries.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $userPathEntries = if ([string]::IsNullOrEmpty($userPath)) { @() } else { $userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } }

    # Normalize for comparison without altering the stored casing/separators.
    $alreadyPresent = $false
    foreach ($entry in $userPathEntries) {
        if ([string]::Equals($entry, $InstallDir, [System.StringComparison]::OrdinalIgnoreCase)) {
            $alreadyPresent = $true
            break
        }
    }

    if ($alreadyPresent) {
        Write-Ok 'Install dir already on USER Path'
    } else {
        $newUserPath = if ($userPathEntries.Count -gt 0) {
            ($userPathEntries + $InstallDir) -join ';'
        } else {
            $InstallDir
        }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
        Write-Ok "Added $InstallDir to USER Path"
    }

    # Reflect the change in the current session too, if it isn't already there.
    $sessionEntries = $env:PATH -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $inSession = $false
    foreach ($entry in $sessionEntries) {
        if ([string]::Equals($entry, $InstallDir, [System.StringComparison]::OrdinalIgnoreCase)) {
            $inSession = $true
            break
        }
    }
    if (-not $inSession) {
        $env:PATH = if ([string]::IsNullOrEmpty($env:PATH)) { $InstallDir } else { ($env:PATH.TrimEnd(';') + ';' + $InstallDir) }
    }

    Write-Step 'Verifying install'
    # Call the freshly-installed binary by absolute path so a stale copy
    # elsewhere on PATH can't fool the verification.
    $versionOutput = & $destExe --version
    if ($LASTEXITCODE -ne 0) {
        throw "ft.exe --version exited with code $LASTEXITCODE. Installation may be incomplete."
    }
    Write-Ok "ft $($versionOutput) installed successfully."

    Write-Host ''
    Write-Host 'Freeoxide Tunnel installed.' -ForegroundColor Green
    if (-not $alreadyPresent) {
        Write-WarnLine 'The USER Path was updated. Open a NEW terminal for `ft` to appear on your PATH.'
    }
    Write-Host 'Reminder: ft requires cloudflared on your PATH to create tunnels.'
    Write-Host '  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/'
}
catch {
    # Friendly, actionable top-level error. Preserve the original message so a
    # user filing a bug has something concrete to paste.
    Write-Host ''
    Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'If this keeps failing, file an issue: https://github.com/freeoxide/tunnel/issues' -ForegroundColor Yellow
    exit 1
}
finally {
    # Always clean up the temp dir, even on failure, so we never leave the
    # downloaded zip / extracted exe lying around in $env:TEMP.
    if ($tempDir -and (Test-Path -LiteralPath $tempDir)) {
        try {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Best-effort; don't mask a real install error with cleanup noise.
        }
    }
}
