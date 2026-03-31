<#
.SYNOPSIS
    Scans C:\Windows\Installer for orphaned installer files and optionally removes them.

.DESCRIPTION
    Replicates the core behaviour of the PatchCleaner application.

    The Windows Installer service maintains a cache of every .msi and .msp file
    it has ever used under C:\Windows\Installer.  When products are uninstalled
    the associated cached files are frequently left behind.  These "orphaned"
    files are safe to delete because no currently-installed product or patch
    references them.

    Detection method
    ----------------
    The script uses the Windows Installer COM automation object
    (WindowsInstaller.Installer) to enumerate:
      - Every installed product  (MSI)  via Products / ProductInfo("LocalPackage")
      - Every applied patch       (MSP)  via Patches("","",MSIPATCHSTATE_APPLIED)
                                          via PatchInfo("LocalPackage")

    Every file found under C:\Windows\Installer is then compared against that
    set of known-registered paths.  A file not present in the registered set is
    considered orphaned.

    Exclusion filters
    -----------------
    The -ExcludePatterns parameter accepts an array of wildcard strings matched
    against the file NAME (not the full path).  Any orphaned file whose name
    matches one of the patterns is skipped rather than deleted.  A built-in
    default list covers Adobe Acrobat / Reader, but additional patterns can be
    supplied or the defaults can be suppressed with -NoDefaultExclusions.

.PARAMETER WhatIf
    Report what would be deleted without actually deleting anything.

.PARAMETER LogPath
    Path to a log file.  Defaults to $env:TEMP\InstallerCleanup_<timestamp>.log.

.PARAMETER ExcludePatterns
    Additional wildcard patterns (matched against the file name) to exclude from
    deletion even when the file is orphaned.

.PARAMETER NoDefaultExclusions
    When specified, the built-in exclusion list (Acrobat etc.) is not applied.
    Only patterns supplied via -ExcludePatterns are used.

.PARAMETER Force
    Suppress the confirmation prompt before deleting files.

.EXAMPLE
    # Dry run – show what would be deleted, no changes made
    .\Invoke-InstallerCleanup.ps1 -WhatIf

.EXAMPLE
    # Delete orphaned files, keep anything matching *acro* or *adobe*
    .\Invoke-InstallerCleanup.ps1 -ExcludePatterns '*acro*','*adobe*' -Force

.EXAMPLE
    # Delete all orphaned files with no exclusions at all
    .\Invoke-InstallerCleanup.ps1 -NoDefaultExclusions -Force

.NOTES
    Must be run as Administrator.
    Tested on Windows 10 / Windows 11 / Windows Server 2016+.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string[]] $ExcludePatterns    = @(),
    [switch]   $NoDefaultExclusions,
    [string]   $LogPath            = (Join-Path $env:TEMP ("InstallerCleanup_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]   $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $LogPath -Value $line
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error   $Message }
        default { Write-Verbose $Message }
    }
}

function Format-Bytes {
    param([long]$Bytes)
    switch ($Bytes) {
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($_ / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($_ / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($_ / 1KB) }
        default        { return "$_ B" }
    }
}

# ---------------------------------------------------------------------------
# Elevation check
# ---------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

# ---------------------------------------------------------------------------
# Initialise log
# ---------------------------------------------------------------------------
$null = New-Item -ItemType File -Path $LogPath -Force
Write-Log "=== Installer Cleanup started ==="
Write-Log "Log path : $LogPath"
Write-Log "WhatIf   : $($WhatIfPreference)"

# ---------------------------------------------------------------------------
# Build the exclusion pattern list
# ---------------------------------------------------------------------------
# Default exclusions – covers Adobe Acrobat, Reader, and common redistributables
# that are known to cause problems if their cached MSI/MSP is removed.
$defaultExclusions = @(
    '*acrobat*',
    '*adobe*',
    '*reader*',
    # Visual C++ runtimes – removing these can break repair of VC++ installs
    '*vcredist*',
    '*vc_red*',
    # .NET Framework patches are sometimes shared across products
    '*netfx*',
    '*dotnetfx*'
)

$allExclusions = if ($NoDefaultExclusions) {
    $ExcludePatterns
} else {
    $defaultExclusions + $ExcludePatterns
}

if ($allExclusions.Count -gt 0) {
    Write-Log ("Exclusion patterns ({0}): {1}" -f $allExclusions.Count, ($allExclusions -join ', '))
} else {
    Write-Log "No exclusion patterns configured."
}

# ---------------------------------------------------------------------------
# Connect to Windows Installer COM object
# ---------------------------------------------------------------------------
Write-Host "`nConnecting to Windows Installer database..." -ForegroundColor Cyan
Write-Log "Connecting to Windows Installer COM object."

try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
} catch {
    throw "Failed to create WindowsInstaller.Installer COM object: $_"
}

# MSIPATCHSTATE_APPLIED = 1
$MSIPATCHSTATE_APPLIED = 1

# ---------------------------------------------------------------------------
# Enumerate all registered local package paths (MSI product caches)
# ---------------------------------------------------------------------------
Write-Host "Enumerating registered MSI product packages..." -ForegroundColor Cyan
Write-Log "Enumerating registered MSI products."

$registeredFiles = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

$productList = @()

try {
    foreach ($productCode in $installer.Products()) {
        try {
            $localPkg = $installer.ProductInfo($productCode, 'LocalPackage')
            if ($localPkg -and (Test-Path -LiteralPath $localPkg)) {
                $null = $registeredFiles.Add($localPkg)
            }

            $productName    = try { $installer.ProductInfo($productCode, 'ProductName')    } catch { 'Unknown' }
            $productVersion = try { $installer.ProductInfo($productCode, 'VersionString')  } catch { 'Unknown' }

            $productList += [PSCustomObject]@{
                ProductCode = $productCode
                Name        = $productName
                Version     = $productVersion
                LocalPackage = $localPkg
            }
        } catch {
            Write-Log ("Skipped product {0}: {1}" -f $productCode, $_) 'WARN'
        }
    }
} catch {
    Write-Log "Error enumerating products: $_" 'WARN'
}

Write-Log ("Found {0} registered product packages." -f $registeredFiles.Count)

# ---------------------------------------------------------------------------
# Enumerate all applied patch packages (MSP)
# ---------------------------------------------------------------------------
Write-Host "Enumerating registered MSP patch packages..." -ForegroundColor Cyan
Write-Log "Enumerating registered MSP patches."

$patchCount = 0
try {
    # Passing empty strings for product/user context returns patches for all
    # products for the current machine context.
    foreach ($patchCode in $installer.Patches('', '', $MSIPATCHSTATE_APPLIED)) {
        try {
            $localPkg = $installer.PatchInfo($patchCode, 'LocalPackage')
            if ($localPkg -and (Test-Path -LiteralPath $localPkg)) {
                $null = $registeredFiles.Add($localPkg)
                $patchCount++
            }
        } catch {
            Write-Log ("Skipped patch {0}: {1}" -f $patchCode, $_) 'WARN'
        }
    }
} catch {
    Write-Log "Error enumerating patches: $_" 'WARN'
}

Write-Log ("Found {0} registered patch packages." -f $patchCount)
Write-Log ("Total registered installer files: {0}" -f $registeredFiles.Count)

# ---------------------------------------------------------------------------
# Scan C:\Windows\Installer
# ---------------------------------------------------------------------------
$installerPath = 'C:\Windows\Installer'
Write-Host ("`nScanning {0} ..." -f $installerPath) -ForegroundColor Cyan
Write-Log ("Scanning {0}" -f $installerPath)

if (-not (Test-Path $installerPath)) {
    throw "Installer cache directory not found: $installerPath"
}

$allInstallerFiles = Get-ChildItem -LiteralPath $installerPath -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.msi', '.msp' }

Write-Log ("Total .msi/.msp files found: {0}" -f $allInstallerFiles.Count)

# ---------------------------------------------------------------------------
# Classify files
# ---------------------------------------------------------------------------
$inUseFiles  = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$orphanFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$excludedFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

foreach ($file in $allInstallerFiles) {
    if ($registeredFiles.Contains($file.FullName)) {
        $inUseFiles.Add($file)
    } else {
        # Check exclusion patterns against the file name only
        $excluded = $false
        foreach ($pattern in $allExclusions) {
            if ($file.Name -like $pattern) {
                $excluded = $true
                break
            }
        }

        if ($excluded) {
            $excludedFiles.Add($file)
        } else {
            $orphanFiles.Add($file)
        }
    }
}

# ---------------------------------------------------------------------------
# Summary table – In-Use files
# ---------------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Green
Write-Host " FILES IN USE (registered with installer)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$inUseSize = ($inUseFiles | Measure-Object -Property Length -Sum).Sum
if (-not $inUseSize) { $inUseSize = 0 }

$inUseFiles | Sort-Object Name | Format-Table -AutoSize -Property `
    @{Name='File'; Expression={$_.Name}},
    @{Name='Size';  Expression={Format-Bytes $_.Length}},
    @{Name='Last Modified'; Expression={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')}}

Write-Host ("In-use files : {0}  ({1})" -f $inUseFiles.Count, (Format-Bytes $inUseSize))
Write-Log  ("In-use files : {0}  ({1})" -f $inUseFiles.Count, (Format-Bytes $inUseSize))

# ---------------------------------------------------------------------------
# Summary table – Excluded orphaned files
# ---------------------------------------------------------------------------
if ($excludedFiles.Count -gt 0) {
    Write-Host "`n==========================================" -ForegroundColor Yellow
    Write-Host " ORPHANED – EXCLUDED (matched filter rule)" -ForegroundColor Yellow
    Write-Host "==========================================" -ForegroundColor Yellow

    $excludedSize = ($excludedFiles | Measure-Object -Property Length -Sum).Sum
    if (-not $excludedSize) { $excludedSize = 0 }

    $excludedFiles | Sort-Object Name | Format-Table -AutoSize -Property `
        @{Name='File'; Expression={$_.Name}},
        @{Name='Size';  Expression={Format-Bytes $_.Length}},
        @{Name='Last Modified'; Expression={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')}}

    Write-Host ("Excluded orphans : {0}  ({1})  – will NOT be deleted." -f $excludedFiles.Count, (Format-Bytes $excludedSize))
    Write-Log  ("Excluded orphans : {0}  ({1})" -f $excludedFiles.Count, (Format-Bytes $excludedSize))
}

# ---------------------------------------------------------------------------
# Summary table – Orphaned files (candidates for deletion)
# ---------------------------------------------------------------------------
Write-Host "`n=============================================" -ForegroundColor Red
Write-Host " ORPHANED FILES (no registered product/patch)" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red

$orphanSize = ($orphanFiles | Measure-Object -Property Length -Sum).Sum
if (-not $orphanSize) { $orphanSize = 0 }

if ($orphanFiles.Count -eq 0) {
    Write-Host "No orphaned files found.  Nothing to clean up." -ForegroundColor Green
    Write-Log "No orphaned files found."
} else {
    $orphanFiles | Sort-Object Length -Descending | Format-Table -AutoSize -Property `
        @{Name='File'; Expression={$_.Name}},
        @{Name='Size';  Expression={Format-Bytes $_.Length}},
        @{Name='Last Modified'; Expression={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')}},
        @{Name='Full Path'; Expression={$_.FullName}}

    Write-Host ("Orphaned files   : {0}  ({1})  – candidates for deletion." -f $orphanFiles.Count, (Format-Bytes $orphanSize))
    Write-Log  ("Orphaned files   : {0}  ({1})" -f $orphanFiles.Count, (Format-Bytes $orphanSize))
}

# ---------------------------------------------------------------------------
# Overall size summary
# ---------------------------------------------------------------------------
$totalSize = $inUseSize + $orphanSize + (($excludedFiles | Measure-Object -Property Length -Sum).Sum)
Write-Host "`n--- Space summary ---"
Write-Host ("Total cache size   : {0}" -f (Format-Bytes $totalSize))
Write-Host ("Reclaimable space  : {0}" -f (Format-Bytes $orphanSize)) -ForegroundColor Cyan
Write-Log  ("Total: {0}  |  Reclaimable: {1}" -f (Format-Bytes $totalSize), (Format-Bytes $orphanSize))

# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------
if ($orphanFiles.Count -eq 0) {
    Write-Host "`nNothing to delete.  Exiting cleanly." -ForegroundColor Green
    Write-Log "No files deleted."
    exit 0
}

if ($WhatIfPreference) {
    Write-Host "`n[WhatIf] No files were deleted.  Re-run without -WhatIf to perform deletion." -ForegroundColor Yellow
    Write-Log "WhatIf mode – no files deleted."
    exit 0
}

# Prompt unless -Force was supplied
if (-not $Force) {
    $answer = Read-Host ("`nDelete {0} orphaned file(s) and reclaim {1}? [y/N]" -f $orphanFiles.Count, (Format-Bytes $orphanSize))
    if ($answer -notmatch '^[Yy]') {
        Write-Host "Aborted.  No files were deleted." -ForegroundColor Yellow
        Write-Log "User aborted deletion."
        exit 0
    }
}

Write-Host "`nDeleting orphaned files..." -ForegroundColor Red
Write-Log "Beginning deletion of $($orphanFiles.Count) orphaned files."

$deletedCount = 0
$deletedBytes = 0L
$failedFiles  = [System.Collections.Generic.List[string]]::new()

foreach ($file in $orphanFiles) {
    try {
        $size = $file.Length
        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
        $deletedCount++
        $deletedBytes += $size
        Write-Log ("Deleted: {0}  ({1})" -f $file.FullName, (Format-Bytes $size))
        Write-Verbose ("Deleted: {0}" -f $file.Name)
    } catch {
        $failedFiles.Add($file.FullName)
        Write-Log ("FAILED to delete: {0}  Error: {1}" -f $file.FullName, $_) 'WARN'
        Write-Warning ("Could not delete {0}: {1}" -f $file.Name, $_)
    }
}

# ---------------------------------------------------------------------------
# Deletion summary
# ---------------------------------------------------------------------------
Write-Host "`n=== Deletion complete ===" -ForegroundColor Green
Write-Host ("Files deleted : {0}  ({1})" -f $deletedCount, (Format-Bytes $deletedBytes))
Write-Log  ("Files deleted : {0}  ({1})" -f $deletedCount, (Format-Bytes $deletedBytes))

if ($failedFiles.Count -gt 0) {
    Write-Host ("Files failed  : {0}" -f $failedFiles.Count) -ForegroundColor Yellow
    Write-Log  ("Files failed  : {0}" -f $failedFiles.Count) 'WARN'
    foreach ($f in $failedFiles) {
        Write-Host "  FAILED: $f" -ForegroundColor Yellow
    }
}

Write-Host ("`nLog written to: {0}" -f $LogPath) -ForegroundColor Cyan
Write-Log "=== Installer Cleanup finished ==="
