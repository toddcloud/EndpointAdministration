<#
.SYNOPSIS
    Identifies and removes orphaned files from C:\Windows\Installer.

.DESCRIPTION
    Replicates the behaviour of PatchCleaner by using the Windows Installer COM API
    (WindowsInstaller.Installer) to enumerate every product and patch registered with
    the system, collecting their LocalPackage paths.  It then scans C:\Windows\Installer
    for .msi, .msp, and subdirectory entries, cross-referencing them against the
    registered set.  Any file or folder that is NOT referenced is classified as orphaned.

    Built-in exclusion filters protect known-sensitive applications (e.g. Adobe Acrobat)
    from accidental removal.

    Three action modes are available:
      - ReportOnly  (default) : produces a report; changes nothing on disk.
      - Move                  : moves orphaned files to a backup directory.
      - Delete                : permanently deletes orphaned files.

.PARAMETER Action
    ReportOnly | Move | Delete.  Defaults to ReportOnly.

.PARAMETER BackupPath
    Destination folder when Action is Move.  Defaults to C:\WindowsInstallerBackup.

.PARAMETER ExclusionFile
    Optional path to a JSON file containing additional exclusion rules.  The file
    must contain a JSON array of objects with optional keys: ProductName, ProductCode,
    PatchCode, PathPattern.

.PARAMETER SkipDefaultExclusions
    When specified, the built-in exclusion list (Adobe Acrobat, etc.) is not applied.

.PARAMETER Force
    Suppresses the confirmation prompt before destructive operations.

.PARAMETER LogPath
    Path to write a detailed CSV log of every file evaluated.
    Defaults to .\InstallerCleanup_<timestamp>.csv.

.EXAMPLE
    .\Invoke-InstallerCleanup.ps1
    # Report-only scan — no files are touched.

.EXAMPLE
    .\Invoke-InstallerCleanup.ps1 -Action Move -BackupPath D:\InstallerBackup
    # Moves orphaned files to D:\InstallerBackup.

.EXAMPLE
    .\Invoke-InstallerCleanup.ps1 -Action Delete -Force
    # Permanently deletes orphaned files without confirmation.

.NOTES
    Must be run as Administrator.
    Requires Windows PowerShell 5.1+ or PowerShell 7+ on Windows.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('ReportOnly', 'Move', 'Delete')]
    [string]$Action = 'ReportOnly',

    [string]$BackupPath = 'C:\WindowsInstallerBackup',

    [string]$ExclusionFile,

    [switch]$SkipDefaultExclusions,

    [switch]$Force,

    [string]$LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Privilege check ────────────────────────────────────────────────────

function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must be run as Administrator. Re-launch an elevated PowerShell session.'
    }
}

Assert-Administrator

#endregion

#region ── Logging helpers ────────────────────────────────────────────────────

if (-not $LogPath) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $LogPath   = Join-Path $PSScriptRoot "InstallerCleanup_$timestamp.csv"
}

$script:logEntries = [System.Collections.Generic.List[PSObject]]::new()

function Write-Log {
    param(
        [string]$Path,
        [string]$Type,
        [string]$Status,
        [long]$SizeBytes = 0,
        [string]$Detail  = ''
    )
    $script:logEntries.Add([PSCustomObject]@{
        Timestamp = (Get-Date -Format 'o')
        Path      = $Path
        Type      = $Type
        Status    = $Status
        SizeMB    = [math]::Round($SizeBytes / 1MB, 2)
        Detail    = $Detail
    })
}

#endregion

#region ── Default exclusion list ─────────────────────────────────────────────

$defaultExclusions = @(
    @{
        Name         = 'Adobe Acrobat / Reader'
        ProductName  = @('Adobe Acrobat*', 'Adobe Reader*')
        PatchCode    = @('{AC7*')
        PathPattern  = @('*\AcroRd*', '*\Acrobat*')
    },
    @{
        Name         = 'Adobe Creative Cloud'
        ProductName  = @('Adobe Creative Cloud*')
        PathPattern  = @('*\Adobe*CC*')
    },
    @{
        Name         = 'Microsoft Office (Click-to-Run)'
        ProductName  = @('Microsoft Office*', 'Microsoft 365*')
        PathPattern  = @()
    },
    @{
        Name         = 'Microsoft Visual C++ Redistributable'
        ProductName  = @('Microsoft Visual C++*')
        PathPattern  = @()
    },
    @{
        Name         = 'Microsoft .NET Framework'
        ProductName  = @('Microsoft .NET*')
        PathPattern  = @()
    }
)

#endregion

#region ── Exclusion engine ───────────────────────────────────────────────────

function Build-ExclusionSet {
    [CmdletBinding()]
    param()

    $rules = [System.Collections.Generic.List[hashtable]]::new()

    if (-not $SkipDefaultExclusions) {
        foreach ($ex in $defaultExclusions) { $rules.Add($ex) }
    }

    if ($ExclusionFile -and (Test-Path $ExclusionFile)) {
        $custom = Get-Content -Path $ExclusionFile -Raw | ConvertFrom-Json
        foreach ($item in $custom) {
            $ht = @{}
            if ($item.PSObject.Properties['Name'])         { $ht['Name']         = $item.Name }
            if ($item.PSObject.Properties['ProductName'])   { $ht['ProductName']  = @($item.ProductName) }
            if ($item.PSObject.Properties['ProductCode'])   { $ht['ProductCode']  = @($item.ProductCode) }
            if ($item.PSObject.Properties['PatchCode'])     { $ht['PatchCode']    = @($item.PatchCode) }
            if ($item.PSObject.Properties['PathPattern'])   { $ht['PathPattern']  = @($item.PathPattern) }
            $rules.Add($ht)
        }
    }
    return $rules
}

function Test-Excluded {
    [CmdletBinding()]
    param(
        [string]$FilePath,
        [AllowNull()][string]$ProductName,
        [AllowNull()][string]$ProductCode,
        [AllowNull()][string]$PatchCode,
        [System.Collections.Generic.List[hashtable]]$Rules
    )

    foreach ($rule in $Rules) {
        # Path-pattern match
        if ($rule.ContainsKey('PathPattern')) {
            foreach ($pattern in $rule['PathPattern']) {
                if ($pattern -and ($FilePath -like $pattern)) {
                    return $rule['Name']
                }
            }
        }
        # Product name wildcard match
        if ($ProductName -and $rule.ContainsKey('ProductName')) {
            foreach ($pattern in $rule['ProductName']) {
                if ($ProductName -like $pattern) {
                    return $rule['Name']
                }
            }
        }
        # Explicit product-code match
        if ($ProductCode -and $rule.ContainsKey('ProductCode')) {
            foreach ($pattern in $rule['ProductCode']) {
                if ($ProductCode -like $pattern) {
                    return $rule['Name']
                }
            }
        }
        # Patch-code wildcard match
        if ($PatchCode -and $rule.ContainsKey('PatchCode')) {
            foreach ($pattern in $rule['PatchCode']) {
                if ($PatchCode -like $pattern) {
                    return $rule['Name']
                }
            }
        }
    }
    return $null
}

#endregion

#region ── Windows Installer COM enumeration ──────────────────────────────────

function Get-RegisteredInstallerItems {
    <#
    .SYNOPSIS
        Returns every product and patch registered with the Windows Installer,
        including their LocalPackage paths.
    #>
    [CmdletBinding()]
    param()

    $msi = New-Object -ComObject 'WindowsInstaller.Installer'

    $msi | Add-Member -Name 'GetProperty' -MemberType ScriptMethod -Value {
        $type       = $this.GetType()
        $index      = $args.Count - 1
        $methodArgs = $args[1..$index]
        $type.InvokeMember($args[0], [System.Reflection.BindingFlags]::GetProperty, $null, $this, $methodArgs)
    }

    $results = @{
        Products       = [System.Collections.Generic.List[PSObject]]::new()
        Patches        = [System.Collections.Generic.List[PSObject]]::new()
        KnownPaths     = [System.Collections.Generic.HashSet[string]]::new(
                              [StringComparer]::OrdinalIgnoreCase)
        ProductCodes   = [System.Collections.Generic.HashSet[string]]::new(
                              [StringComparer]::OrdinalIgnoreCase)
        PatchCodes     = [System.Collections.Generic.HashSet[string]]::new(
                              [StringComparer]::OrdinalIgnoreCase)
        ProductNameMap = @{}
    }

    Write-Host '[1/4] Enumerating registered products ...' -ForegroundColor Cyan
    $products = $msi.GetProperty('Products')

    foreach ($productCode in $products) {
        try {
            $localPackage = $msi.GetProperty('ProductInfo', $productCode, 'LocalPackage')
            $productName  = try { $msi.GetProperty('ProductInfo', $productCode, 'ProductName') } catch { '' }
            $version      = try { $msi.GetProperty('ProductInfo', $productCode, 'VersionString') } catch { '' }
        }
        catch {
            Write-Verbose "Could not read product $productCode : $_"
            continue
        }

        $results.Products.Add([PSCustomObject]@{
            ProductCode  = $productCode
            ProductName  = $productName
            Version      = $version
            LocalPackage = $localPackage
        })

        if ($localPackage) { [void]$results.KnownPaths.Add($localPackage) }
        [void]$results.ProductCodes.Add($productCode)
        $results.ProductNameMap[$productCode] = $productName
    }

    Write-Host "   Found $($results.Products.Count) registered products." -ForegroundColor Green

    Write-Host '[2/4] Enumerating registered patches ...' -ForegroundColor Cyan
    $patchCount = 0

    foreach ($productCode in $products) {
        try {
            $patches = $msi.GetProperty('Patches', $productCode)
        }
        catch {
            continue
        }
        if (-not $patches) { continue }

        foreach ($patchCode in $patches) {
            try {
                $location = $msi.GetProperty('PatchInfo', $patchCode, 'LocalPackage')
            }
            catch {
                Write-Verbose "Could not read patch $patchCode for product $productCode : $_"
                continue
            }

            $results.Patches.Add([PSCustomObject]@{
                ProductCode  = $productCode
                PatchCode    = $patchCode
                LocalPackage = $location
            })

            if ($location) { [void]$results.KnownPaths.Add($location) }
            [void]$results.PatchCodes.Add($patchCode)
            $patchCount++
        }
    }

    Write-Host "   Found $patchCount registered patches." -ForegroundColor Green

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($msi) | Out-Null

    return $results
}

#endregion

#region ── Disk scan & classification ─────────────────────────────────────────

function Get-InstallerDirectoryItems {
    [CmdletBinding()]
    param(
        [string]$InstallerPath = (Join-Path $env:windir 'Installer')
    )

    if (-not (Test-Path $InstallerPath)) {
        throw "Installer directory not found: $InstallerPath"
    }

    $items = [System.Collections.Generic.List[PSObject]]::new()

    $files = Get-ChildItem -Path $InstallerPath -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $items.Add([PSCustomObject]@{
            FullName  = $f.FullName
            Name      = $f.Name
            Extension = $f.Extension.ToLower()
            IsDir     = $false
            SizeBytes = $f.Length
        })
    }

    $dirs = Get-ChildItem -Path $InstallerPath -Directory -ErrorAction SilentlyContinue
    foreach ($d in $dirs) {
        $dirSize = (Get-ChildItem -Path $d.FullName -Recurse -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum
        if (-not $dirSize) { $dirSize = 0 }
        $items.Add([PSCustomObject]@{
            FullName  = $d.FullName
            Name      = $d.Name
            Extension = ''
            IsDir     = $true
            SizeBytes = $dirSize
        })
    }

    return $items
}

function Resolve-ItemStatus {
    <#
    .SYNOPSIS
        Classifies each item on disk as InUse, Orphaned, or Excluded.
    #>
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[PSObject]]$DiskItems,
        [hashtable]$RegisteredInfo,
        [System.Collections.Generic.List[hashtable]]$ExclusionRules
    )

    $guidPattern = '\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'

    $classified = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($item in $DiskItems) {
        $status = 'Orphaned'
        $detail = ''
        $guidsInName = @()

        # ── Pass 1: exact LocalPackage path match ────────────────
        if ($RegisteredInfo.KnownPaths.Contains($item.FullName)) {
            $status = 'InUse'
            $detail = 'Exact path match with registered LocalPackage'
        }

        # ── Pass 2: GUID match in file/folder name ───────────────
        if ($status -eq 'Orphaned') {
            $guidsInName = @([regex]::Matches($item.FullName, $guidPattern) |
                             ForEach-Object { $_.Value })

            foreach ($g in $guidsInName) {
                if ($RegisteredInfo.ProductCodes.Contains($g) -or
                    $RegisteredInfo.PatchCodes.Contains($g)) {
                    $status = 'InUse'
                    $detail = "GUID $g found in registered products/patches"
                    break
                }
            }
        }

        # ── Pass 3: exclusion filter check ───────────────────────
        $excludedBy = $null
        if ($status -eq 'Orphaned') {
            foreach ($g in $guidsInName) {
                $excludedBy = Test-Excluded -FilePath $item.FullName `
                                            -ProductCode $g `
                                            -PatchCode $g `
                                            -ProductName $null `
                                            -Rules $ExclusionRules
                if ($excludedBy) { break }
            }
            if (-not $excludedBy) {
                $excludedBy = Test-Excluded -FilePath $item.FullName `
                                            -ProductName $null `
                                            -ProductCode $null `
                                            -PatchCode $null `
                                            -Rules $ExclusionRules
            }
            if ($excludedBy) {
                $status = 'Excluded'
                $detail = "Matched exclusion rule: $excludedBy"
            }
        }

        # For InUse items, try to attach a friendly product name
        if ($status -eq 'InUse' -and -not $detail.StartsWith('Exact')) {
            foreach ($g in $guidsInName) {
                if ($RegisteredInfo.ProductNameMap.ContainsKey($g)) {
                    $detail += " ($($RegisteredInfo.ProductNameMap[$g]))"
                    break
                }
            }
        }

        $classified.Add([PSCustomObject]@{
            FullName  = $item.FullName
            Name      = $item.Name
            Extension = $item.Extension
            IsDir     = $item.IsDir
            SizeBytes = $item.SizeBytes
            Status    = $status
            Detail    = $detail
        })
    }

    return $classified
}

#endregion

#region ── Action handlers ────────────────────────────────────────────────────

function Show-Report {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[PSObject]]$Classified
    )

    $inUse    = $Classified | Where-Object { $_.Status -eq 'InUse' }
    $orphaned = $Classified | Where-Object { $_.Status -eq 'Orphaned' }
    $excluded = $Classified | Where-Object { $_.Status -eq 'Excluded' }

    $totalSizeMB    = [math]::Round(($Classified  | Measure-Object -Property SizeBytes -Sum).Sum / 1MB, 2)
    $inUseSizeMB    = [math]::Round(($inUse       | Measure-Object -Property SizeBytes -Sum).Sum / 1MB, 2)
    $orphanedSizeMB = [math]::Round(($orphaned    | Measure-Object -Property SizeBytes -Sum).Sum / 1MB, 2)
    $excludedSizeMB = [math]::Round(($excluded    | Measure-Object -Property SizeBytes -Sum).Sum / 1MB, 2)

    Write-Host ''
    Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor White
    Write-Host '         Windows Installer Cleanup — Summary Report        ' -ForegroundColor White
    Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor White
    Write-Host ''
    Write-Host "  Total items scanned : $($Classified.Count)" -ForegroundColor Gray
    Write-Host "  Total size on disk  : $totalSizeMB MB" -ForegroundColor Gray
    Write-Host ''
    Write-Host "  In Use   (keep)     : $($inUse.Count) items  ($inUseSizeMB MB)" -ForegroundColor Green
    Write-Host "  Excluded (skip)     : $($excluded.Count) items  ($excludedSizeMB MB)" -ForegroundColor Yellow
    Write-Host "  Orphaned (cleanup)  : $($orphaned.Count) items  ($orphanedSizeMB MB)" -ForegroundColor Red
    Write-Host ''

    if ($orphaned.Count -gt 0) {
        Write-Host '── Orphaned items ─────────────────────────────────────────' -ForegroundColor Red
        foreach ($o in ($orphaned | Sort-Object SizeBytes -Descending)) {
            $sizeMB = [math]::Round($o.SizeBytes / 1MB, 2)
            $tag    = if ($o.IsDir) { '[DIR]' } else { "[.$($o.Extension.TrimStart('.'))]" }
            Write-Host "   $tag $($o.FullName)  ($sizeMB MB)" -ForegroundColor Gray
        }
        Write-Host ''
    }

    if ($excluded.Count -gt 0) {
        Write-Host '── Excluded items ─────────────────────────────────────────' -ForegroundColor Yellow
        foreach ($e in ($excluded | Sort-Object SizeBytes -Descending)) {
            $sizeMB = [math]::Round($e.SizeBytes / 1MB, 2)
            Write-Host "   $($e.FullName)  ($sizeMB MB) — $($e.Detail)" -ForegroundColor DarkYellow
        }
        Write-Host ''
    }
}

function Invoke-MoveOrphans {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [System.Collections.Generic.List[PSObject]]$Orphaned,
        [string]$Destination
    )

    if (-not (Test-Path $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        Write-Host "  Created backup directory: $Destination" -ForegroundColor Cyan
    }

    foreach ($item in $Orphaned) {
        $destPath = Join-Path $Destination $item.Name
        if ($PSCmdlet.ShouldProcess($item.FullName, 'Move to backup')) {
            try {
                Move-Item -Path $item.FullName -Destination $destPath -Force
                Write-Log -Path $item.FullName -Type $(if ($item.IsDir) {'Directory'} else {'File'}) `
                          -Status 'Moved' -SizeBytes $item.SizeBytes -Detail "Moved to $destPath"
                Write-Host "   Moved: $($item.FullName)" -ForegroundColor Green
            }
            catch {
                Write-Log -Path $item.FullName -Type $(if ($item.IsDir) {'Directory'} else {'File'}) `
                          -Status 'MoveFailed' -SizeBytes $item.SizeBytes -Detail $_.Exception.Message
                Write-Warning "   Failed to move $($item.FullName): $_"
            }
        }
    }
}

function Invoke-DeleteOrphans {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [System.Collections.Generic.List[PSObject]]$Orphaned
    )

    foreach ($item in $Orphaned) {
        if ($PSCmdlet.ShouldProcess($item.FullName, 'Delete')) {
            try {
                Remove-Item -Path $item.FullName -Recurse -Force
                Write-Log -Path $item.FullName -Type $(if ($item.IsDir) {'Directory'} else {'File'}) `
                          -Status 'Deleted' -SizeBytes $item.SizeBytes
                Write-Host "   Deleted: $($item.FullName)" -ForegroundColor Green
            }
            catch {
                Write-Log -Path $item.FullName -Type $(if ($item.IsDir) {'Directory'} else {'File'}) `
                          -Status 'DeleteFailed' -SizeBytes $item.SizeBytes -Detail $_.Exception.Message
                Write-Warning "   Failed to delete $($item.FullName): $_"
            }
        }
    }
}

#endregion

#region ── Main execution ─────────────────────────────────────────────────────

Write-Host ''
Write-Host '╔═══════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║      Windows Installer Orphaned File Cleanup Utility     ║' -ForegroundColor Cyan
Write-Host '║      Replicates PatchCleaner behaviour via COM API       ║' -ForegroundColor Cyan
Write-Host '╚═══════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host ''

$exclusionRules = Build-ExclusionSet
Write-Host "  Loaded $($exclusionRules.Count) exclusion rule(s)." -ForegroundColor DarkGray

$registered = Get-RegisteredInstallerItems

$installerDir = Join-Path $env:windir 'Installer'
Write-Host "[3/4] Scanning $installerDir ..." -ForegroundColor Cyan
$diskItems = Get-InstallerDirectoryItems -InstallerPath $installerDir
Write-Host "   Found $($diskItems.Count) items on disk." -ForegroundColor Green

Write-Host '[4/4] Classifying items ...' -ForegroundColor Cyan
$classified = Resolve-ItemStatus -DiskItems $diskItems `
                                 -RegisteredInfo $registered `
                                 -ExclusionRules $exclusionRules

foreach ($c in $classified) {
    Write-Log -Path $c.FullName -Type $(if ($c.IsDir) {'Directory'} else {'File'}) `
              -Status $c.Status -SizeBytes $c.SizeBytes -Detail $c.Detail
}

Show-Report -Classified $classified

$orphaned = [System.Collections.Generic.List[PSObject]]($classified | Where-Object { $_.Status -eq 'Orphaned' })

if ($orphaned.Count -eq 0) {
    Write-Host '  No orphaned files detected. Nothing to clean up.' -ForegroundColor Green
}
elseif ($Action -eq 'ReportOnly') {
    Write-Host "  Action: ReportOnly — no files were modified." -ForegroundColor Yellow
    Write-Host "  Re-run with -Action Move or -Action Delete to remediate." -ForegroundColor Yellow
}
else {
    if (-not $Force) {
        $orphanedSizeMB = [math]::Round(($orphaned | Measure-Object -Property SizeBytes -Sum).Sum / 1MB, 2)
        Write-Host ''
        Write-Host "  ⚠  You are about to $($Action.ToLower()) $($orphaned.Count) orphaned items ($orphanedSizeMB MB)." -ForegroundColor Red
        $confirm = Read-Host '  Type YES to proceed'
        if ($confirm -ne 'YES') {
            Write-Host '  Aborted by user.' -ForegroundColor Yellow
            $Action = 'ReportOnly'
        }
    }

    switch ($Action) {
        'Move'   { Invoke-MoveOrphans -Orphaned $orphaned -Destination $BackupPath }
        'Delete' { Invoke-DeleteOrphans -Orphaned $orphaned }
    }
}

$script:logEntries | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "  Log written to: $LogPath" -ForegroundColor DarkGray
Write-Host '  Done.' -ForegroundColor Green
Write-Host ''

#endregion
