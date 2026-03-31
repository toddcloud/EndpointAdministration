<#
.SYNOPSIS
    Detects and removes orphaned files from C:\Windows\Installer.

.DESCRIPTION
    Scans C:\Windows\Installer for .msi and .msp files, queries the Windows
    Installer database to determine which files are actively referenced by
    installed products and patches, and identifies orphaned files that are
    no longer associated with any installed application.

    Replicates the core behaviour of the PatchCleaner utility:
      - Enumerates every registered product and patch via the Windows Installer COM API.
      - Resolves each registration to a LocalPackage path inside C:\Windows\Installer.
      - Any .msi / .msp file in that folder NOT referenced by a registration is orphaned.
      - Supports exclusion filters so that specific vendors or products (e.g. Adobe Acrobat)
        are never flagged for deletion.
      - Supports Report, Delete, and Move operating modes.

.PARAMETER Mode
    Report  - Display results only; no files are modified (default).
    Delete  - Permanently delete orphaned files.
    Move    - Move orphaned files to the path specified by -BackupPath.

.PARAMETER BackupPath
    Destination folder when using -Mode Move.  Created automatically if it
    does not exist.  Defaults to C:\Windows\Installer\_Orphaned.

.PARAMETER ExcludeVendors
    Array of vendor-name substrings.  Any product whose publisher or name
    matches one of these strings (case-insensitive) will have its files
    protected from cleanup even if Windows Installer no longer references them.
    Defaults to @('Adobe', 'Acrobat').

.PARAMETER ExcludeProductCodes
    Array of product GUIDs to protect unconditionally.

.PARAMETER Force
    Suppress the confirmation prompt when using Delete or Move mode.

.PARAMETER LogPath
    Path to a log file.  Defaults to $env:TEMP\InstallerPatchCleanup.log.

.EXAMPLE
    .\Invoke-InstallerPatchCleanup.ps1
    Report mode - lists orphaned files, space reclaimable, and in-use files.

.EXAMPLE
    .\Invoke-InstallerPatchCleanup.ps1 -Mode Delete -Force
    Deletes all orphaned files without prompting.

.EXAMPLE
    .\Invoke-InstallerPatchCleanup.ps1 -Mode Move -BackupPath D:\InstallerBackup
    Moves orphaned files to D:\InstallerBackup.

.EXAMPLE
    .\Invoke-InstallerPatchCleanup.ps1 -ExcludeVendors 'Adobe','Microsoft Office'
    Report mode, protecting anything matching Adobe or Microsoft Office.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseBOMForUnicodeEncodedFile', '')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Report', 'Delete', 'Move')]
    [string]$Mode = 'Report',

    [string]$BackupPath = 'C:\Windows\Installer\_Orphaned',

    [string[]]$ExcludeVendors = @('Adobe', 'Acrobat'),

    [string[]]$ExcludeProductCodes = @(),

    [switch]$Force,

    [string]$LogPath = (Join-Path $env:TEMP 'InstallerPatchCleanup.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Logging

function Write-CleanupLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
        default { Write-Information $Message -InformationAction Continue }
    }
}

#endregion

#region Privilege check

function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must be run as Administrator. Right-click PowerShell and select "Run as Administrator".'
    }
}

#endregion

#region Windows Installer COM helpers

function Get-RegisteredInstallerFileMap {
    <#
    .SYNOPSIS
        Returns a hashtable of every file path referenced by the Windows Installer
        database, keyed by normalised full path.  Each value is a PSCustomObject
        with product/patch metadata.
    #>

    $referenced = @{}

    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
    }
    catch {
        Write-CleanupLog 'Failed to create WindowsInstaller.Installer COM object.' -Level ERROR
        throw
    }

    # --- Enumerate products ---------------------------------------------------
    $productList = @()
    try {
        $products = $installer.GetType().InvokeMember(
            'Products', [System.Reflection.BindingFlags]::GetProperty, $null, $installer, $null
        )
        foreach ($productCode in $products) {
            $productList += $productCode
        }
    }
    catch {
        Write-CleanupLog "Error enumerating products: $_" -Level WARN
    }

    foreach ($productCode in $productList) {
        $localPackage = $null
        $productName  = ''
        $publisher    = ''

        try {
            $localPackage = $installer.GetType().InvokeMember(
                'ProductInfo',
                [System.Reflection.BindingFlags]::GetProperty,
                $null, $installer, @($productCode, 'LocalPackage')
            )
        }
        catch [System.Exception] { $null = $_ }

        try {
            $productName = $installer.GetType().InvokeMember(
                'ProductInfo',
                [System.Reflection.BindingFlags]::GetProperty,
                $null, $installer, @($productCode, 'ProductName')
            )
        }
        catch [System.Exception] { $null = $_ }

        try {
            $publisher = $installer.GetType().InvokeMember(
                'ProductInfo',
                [System.Reflection.BindingFlags]::GetProperty,
                $null, $installer, @($productCode, 'Publisher')
            )
        }
        catch [System.Exception] { $null = $_ }

        if ($localPackage -and (Test-Path $localPackage -ErrorAction SilentlyContinue)) {
            $key = $localPackage.ToLower()
            if (-not $referenced.ContainsKey($key)) {
                $referenced[$key] = [PSCustomObject]@{
                    Path        = $localPackage
                    Type        = 'MSI'
                    ProductCode = $productCode
                    ProductName = $productName
                    Publisher   = $publisher
                }
            }
        }

        # Patches registered under this product
        try {
            $patches = $installer.GetType().InvokeMember(
                'Patches',
                [System.Reflection.BindingFlags]::GetProperty,
                $null, $installer, @($productCode)
            )

            foreach ($patchCode in $patches) {
                $patchPackage = $null
                try {
                    $patchPackage = $installer.GetType().InvokeMember(
                        'PatchInfo',
                        [System.Reflection.BindingFlags]::GetProperty,
                        $null, $installer, @($patchCode, 'LocalPackage')
                    )
                }
                catch [System.Exception] { $null = $_ }

                if ($patchPackage -and (Test-Path $patchPackage -ErrorAction SilentlyContinue)) {
                    $key = $patchPackage.ToLower()
                    if (-not $referenced.ContainsKey($key)) {
                        $referenced[$key] = [PSCustomObject]@{
                            Path        = $patchPackage
                            Type        = 'MSP'
                            ProductCode = $productCode
                            ProductName = $productName
                            Publisher   = $publisher
                        }
                    }
                }
            }
        }
        catch [System.Exception] { $null = $_ }
    }

    # --- Fallback: registry scan for patches not tied to a product entry ------
    $patchRegPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Patches',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
    )

    foreach ($regRoot in $patchRegPaths) {
        if (-not (Test-Path $regRoot)) { continue }

        Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
            $subKeys = @('InstallProperties', '')
            foreach ($sub in $subKeys) {
                $testPath = if ($sub) { Join-Path $_.PSPath $sub } else { $_.PSPath }
                if (-not (Test-Path $testPath)) { continue }

                try {
                    $props = Get-ItemProperty -Path $testPath -ErrorAction SilentlyContinue
                    if ($props.LocalPackage -and (Test-Path $props.LocalPackage -ErrorAction SilentlyContinue)) {
                        $key = $props.LocalPackage.ToLower()
                        if (-not $referenced.ContainsKey($key)) {
                            $displayName = if ($props.DisplayName) { $props.DisplayName } else { '' }
                            $pub = if ($props.Publisher) { $props.Publisher } else { '' }
                            $referenced[$key] = [PSCustomObject]@{
                                Path        = $props.LocalPackage
                                Type        = if ($props.LocalPackage -match '\.msp$') { 'MSP' } else { 'MSI' }
                                ProductCode = $_.PSChildName
                                ProductName = $displayName
                                Publisher   = $pub
                            }
                        }
                    }
                }
                catch [System.Exception] { $null = $_ }
            }
        }
    }

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null

    return $referenced
}

#endregion

#region File scanning

function Get-InstallerDirectoryContent {
    <#
    .SYNOPSIS
        Returns all .msi and .msp files in C:\Windows\Installer (non-recursive).
    #>
    param(
        [string]$InstallerPath = 'C:\Windows\Installer'
    )

    if (-not (Test-Path $InstallerPath)) {
        throw "Installer directory not found: $InstallerPath"
    }

    Get-ChildItem -Path $InstallerPath -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.msi', '.msp' }
}

#endregion

#region Exclusion filter

function Test-Excluded {
    <#
    .SYNOPSIS
        Returns $true if the file should be excluded from cleanup based on
        vendor/product filters or explicit product-code exclusions.
    #>
    param(
        [string]$FilePath,
        [hashtable]$ReferencedFiles,
        [string[]]$Vendors,
        [string[]]$ProductCodes
    )

    $key = $FilePath.ToLower()

    if ($ReferencedFiles.ContainsKey($key)) {
        return $false
    }

    # Check explicit product-code exclusion list against all referenced entries
    # that share a directory neighbour pattern (belt-and-suspenders guard).
    foreach ($entry in $ReferencedFiles.Values) {
        if ($ProductCodes -and $ProductCodes -contains $entry.ProductCode) {
            return $true
        }
    }

    # Check if the filename itself hints at an excluded vendor.
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    foreach ($vendor in $Vendors) {
        if ($fileName -match [regex]::Escape($vendor)) {
            return $true
        }
    }

    # Attempt to read the MSI/MSP summary stream for a vendor match.
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = $installer.GetType().InvokeMember(
            'OpenDatabase',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null, $installer, @($FilePath, 0)
        )
        $summary = $db.GetType().InvokeMember(
            'SummaryInformation',
            [System.Reflection.BindingFlags]::GetProperty,
            $null, $db, $null
        )

        $author = $summary.GetType().InvokeMember(
            'Property',
            [System.Reflection.BindingFlags]::GetProperty,
            $null, $summary, @(4)
        )
        $subject = $summary.GetType().InvokeMember(
            'Property',
            [System.Reflection.BindingFlags]::GetProperty,
            $null, $summary, @(3)
        )
        $title = $summary.GetType().InvokeMember(
            'Property',
            [System.Reflection.BindingFlags]::GetProperty,
            $null, $summary, @(2)
        )

        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($summary) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($db)      | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer)| Out-Null

        foreach ($vendor in $Vendors) {
            $vendorEscaped = [regex]::Escape($vendor)
            if (($author  -and $author  -match $vendorEscaped) -or
                ($subject -and $subject -match $vendorEscaped) -or
                ($title   -and $title   -match $vendorEscaped)) {
                return $true
            }
        }
    }
    catch [System.Exception] {
        $null = $_
    }

    return $false
}

#endregion

#region Formatting helpers

function Format-FileSize {
    param([long]$Bytes)
    switch ($Bytes) {
        { $_ -ge 1GB } { '{0:N2} GB' -f ($_ / 1GB); break }
        { $_ -ge 1MB } { '{0:N2} MB' -f ($_ / 1MB); break }
        { $_ -ge 1KB } { '{0:N2} KB' -f ($_ / 1KB); break }
        default         { "$_ Bytes" }
    }
}

#endregion

#region Main

function Invoke-InstallerPatchCleanup {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Assert-Administrator

    Write-CleanupLog '======================================================================'
    Write-CleanupLog "Installer Patch Cleanup — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-CleanupLog "Mode            : $Mode"
    Write-CleanupLog "Backup Path     : $BackupPath"
    Write-CleanupLog "Excluded Vendors: $($ExcludeVendors -join ', ')"
    Write-CleanupLog '======================================================================'

    # ---- Step 1: Query Windows Installer for all referenced files ------------
    Write-CleanupLog 'Querying Windows Installer database for registered products and patches...'
    $referencedFiles = Get-RegisteredInstallerFileMap
    Write-CleanupLog "  Found $($referencedFiles.Count) referenced installer file(s)."

    # ---- Step 2: Enumerate files on disk -------------------------------------
    Write-CleanupLog 'Scanning C:\Windows\Installer for .msi and .msp files...'
    $diskFiles = @(Get-InstallerDirectoryContent)
    $totalDiskSize = ($diskFiles | Measure-Object -Property Length -Sum).Sum
    Write-CleanupLog "  Found $($diskFiles.Count) file(s) on disk totalling $(Format-FileSize $totalDiskSize)."

    # ---- Step 3: Classify each file ------------------------------------------
    $inUseFiles     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $orphanedFiles  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $excludedFiles  = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($file in $diskFiles) {
        $key = $file.FullName.ToLower()

        if ($referencedFiles.ContainsKey($key)) {
            $ref = $referencedFiles[$key]
            $inUseFiles.Add([PSCustomObject]@{
                FileName    = $file.Name
                FullPath    = $file.FullName
                SizeBytes   = $file.Length
                Size        = Format-FileSize $file.Length
                Type        = $ref.Type
                ProductName = $ref.ProductName
                Publisher   = $ref.Publisher
                ProductCode = $ref.ProductCode
                Status      = 'InUse'
            })
            continue
        }

        # Check exclusion filters
        $isExcluded = Test-Excluded -FilePath $file.FullName `
                                     -ReferencedFiles $referencedFiles `
                                     -Vendors $ExcludeVendors `
                                     -ProductCodes $ExcludeProductCodes

        if ($isExcluded) {
            $excludedFiles.Add([PSCustomObject]@{
                FileName  = $file.Name
                FullPath  = $file.FullName
                SizeBytes = $file.Length
                Size      = Format-FileSize $file.Length
                Status    = 'Excluded'
            })
            continue
        }

        $orphanedFiles.Add([PSCustomObject]@{
            FileName  = $file.Name
            FullPath  = $file.FullName
            SizeBytes = $file.Length
            Size      = Format-FileSize $file.Length
            Status    = 'Orphaned'
        })
    }

    $orphanedSize = ($orphanedFiles | Measure-Object -Property SizeBytes -Sum).Sum
    if (-not $orphanedSize) { $orphanedSize = 0 }
    $inUseSize    = ($inUseFiles | Measure-Object -Property SizeBytes -Sum).Sum
    if (-not $inUseSize) { $inUseSize = 0 }
    $excludedSize = ($excludedFiles | Measure-Object -Property SizeBytes -Sum).Sum
    if (-not $excludedSize) { $excludedSize = 0 }

    # ---- Step 4: Report ------------------------------------------------------
    Write-CleanupLog ''
    Write-CleanupLog '========================= SUMMARY ========================='
    Write-CleanupLog "Total files on disk   : $($diskFiles.Count)  ($(Format-FileSize $totalDiskSize))"
    Write-CleanupLog "In-use (referenced)   : $($inUseFiles.Count)  ($(Format-FileSize $inUseSize))"
    Write-CleanupLog "Excluded by filter    : $($excludedFiles.Count)  ($(Format-FileSize $excludedSize))"
    Write-CleanupLog "Orphaned (removable)  : $($orphanedFiles.Count)  ($(Format-FileSize $orphanedSize))"
    Write-CleanupLog '============================================================'
    Write-CleanupLog ''

    if ($inUseFiles.Count -gt 0) {
        Write-CleanupLog '--- IN-USE FILES (will NOT be touched) ---'
        foreach ($f in $inUseFiles) {
            Write-CleanupLog "  [IN USE]  $($f.FileName)  $($f.Size)  — $($f.ProductName) ($($f.Publisher))"
        }
        Write-CleanupLog ''
    }

    if ($excludedFiles.Count -gt 0) {
        Write-CleanupLog '--- EXCLUDED FILES (protected by filter) ---'
        foreach ($f in $excludedFiles) {
            Write-CleanupLog "  [EXCLUDED]  $($f.FileName)  $($f.Size)"
        }
        Write-CleanupLog ''
    }

    if ($orphanedFiles.Count -gt 0) {
        Write-CleanupLog '--- ORPHANED FILES ---'
        foreach ($f in $orphanedFiles) {
            Write-CleanupLog "  [ORPHANED]  $($f.FileName)  $($f.Size)"
        }
        Write-CleanupLog ''
    }

    # ---- Step 5: Act on orphaned files if requested --------------------------
    if ($Mode -eq 'Report') {
        Write-CleanupLog 'Mode is Report — no files were modified.'
        Write-CleanupLog "Re-run with -Mode Delete or -Mode Move to reclaim $(Format-FileSize $orphanedSize)."

        return [PSCustomObject]@{
            TotalFiles    = $diskFiles.Count
            TotalSize     = $totalDiskSize
            InUseCount    = $inUseFiles.Count
            InUseSize     = $inUseSize
            ExcludedCount = $excludedFiles.Count
            ExcludedSize  = $excludedSize
            OrphanedCount = $orphanedFiles.Count
            OrphanedSize  = $orphanedSize
            InUseFiles    = $inUseFiles
            ExcludedFiles = $excludedFiles
            OrphanedFiles = $orphanedFiles
        }
    }

    if ($orphanedFiles.Count -eq 0) {
        Write-CleanupLog 'No orphaned files to process.'
        return
    }

    # Confirmation prompt unless -Force
    if (-not $Force) {
        $action = if ($Mode -eq 'Delete') { 'permanently DELETE' } else { "MOVE to $BackupPath" }
        $prompt = "You are about to $action $($orphanedFiles.Count) orphaned file(s) totalling $(Format-FileSize $orphanedSize). Continue?"
        $answer = Read-Host "$prompt (Y/N)"
        if ($answer -notin 'Y', 'y', 'Yes', 'yes') {
            Write-CleanupLog 'Operation cancelled by user.'
            return
        }
    }

    if ($Mode -eq 'Move') {
        if (-not (Test-Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
            Write-CleanupLog "Created backup directory: $BackupPath"
        }
    }

    $successCount = 0
    $failCount    = 0

    foreach ($f in $orphanedFiles) {
        try {
            if ($PSCmdlet.ShouldProcess($f.FullPath, $Mode)) {
                if ($Mode -eq 'Delete') {
                    Remove-Item -Path $f.FullPath -Force
                    Write-CleanupLog "  Deleted: $($f.FileName)  ($($f.Size))"
                }
                else {
                    $dest = Join-Path $BackupPath $f.FileName
                    # Handle name collisions in backup directory
                    if (Test-Path $dest) {
                        $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($f.FileName)
                        $extension = [System.IO.Path]::GetExtension($f.FileName)
                        $counter   = 1
                        do {
                            $dest = Join-Path $BackupPath "$baseName`_$counter$extension"
                            $counter++
                        } while (Test-Path $dest)
                    }
                    Move-Item -Path $f.FullPath -Destination $dest -Force
                    Write-CleanupLog "  Moved: $($f.FileName) -> $dest  ($($f.Size))"
                }
                $successCount++
            }
        }
        catch {
            $failCount++
            Write-CleanupLog "  FAILED ($Mode): $($f.FileName) — $($_.Exception.Message)" -Level WARN
        }
    }

    Write-CleanupLog ''
    Write-CleanupLog "Operation complete. Success: $successCount  Failed: $failCount"
    $reclaimedBytes = 0
    foreach ($orphan in $orphanedFiles) {
        if (-not (Test-Path $orphan.FullPath -ErrorAction SilentlyContinue)) {
            $reclaimedBytes += $orphan.SizeBytes
        }
    }
    Write-CleanupLog "Space reclaimed: $(Format-FileSize $reclaimedBytes)"

    return [PSCustomObject]@{
        TotalFiles    = $diskFiles.Count
        TotalSize     = $totalDiskSize
        InUseCount    = $inUseFiles.Count
        InUseSize     = $inUseSize
        ExcludedCount = $excludedFiles.Count
        ExcludedSize  = $excludedSize
        OrphanedCount = $orphanedFiles.Count
        OrphanedSize  = $orphanedSize
        Processed     = $successCount
        Failed        = $failCount
        Mode          = $Mode
    }
}

Invoke-InstallerPatchCleanup

#endregion
