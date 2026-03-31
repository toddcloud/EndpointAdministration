[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Audit', 'Remediate')]
    [string]$Mode = 'Audit',

    [string[]]$ExcludePattern = @(),

    [switch]$IncludeMst,

    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallerRoot = 'C:\Windows\Installer'
$trackedExtensions = @('.msi', '.msp')
if ($IncludeMst) {
    $trackedExtensions += '.mst'
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-NormalizedPath {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PathValue
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $null
    }

    $trimmed = $PathValue.Trim().Trim('"')
    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed)
    try {
        return [System.IO.Path]::GetFullPath($expanded).ToLowerInvariant()
    }
    catch {
        return $null
    }
}

function Test-IsExcluded {
    param(
        [System.IO.FileInfo]$File,
        [string[]]$Patterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) {
        return $false
    }

    foreach ($pattern in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            continue
        }

        $wildcard = "*$pattern*"
        if ($File.FullName -like $wildcard -or $File.Name -like $wildcard) {
            return $true
        }
    }

    return $false
}

function Get-RegistryValueSafe {
    param(
        [string]$LiteralPath,
        [string]$Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $LiteralPath -ErrorAction Stop
    }
    catch {
        return $null
    }

    if ($null -eq $item) {
        return $null
    }

    $property = $item.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return [string]$property.Value
}

function Convert-FileListToPathArray {
    param(
        [AllowNull()]
        [object]$Files
    )

    if ($null -eq $Files) {
        return @()
    }

    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $Files) {
        if ($null -eq $file) {
            continue
        }

        $fullNameProperty = $file.PSObject.Properties['FullName']
        if ($null -ne $fullNameProperty -and -not [string]::IsNullOrWhiteSpace([string]$fullNameProperty.Value)) {
            $paths.Add([string]$fullNameProperty.Value)
            continue
        }

        $paths.Add([string]$file)
    }

    return @($paths)
}

$isWindowsOs = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if (-not $isWindowsOs) {
    throw 'This remediation script can only run on Windows.'
}

if (-not (Test-Path -LiteralPath $InstallerRoot)) {
    throw "Installer cache path was not found: $InstallerRoot"
}

if ($Mode -eq 'Remediate' -and -not (Test-IsAdministrator)) {
    throw 'Remediate mode requires an elevated PowerShell session (Run as Administrator).'
}

$normalizedInstallerRoot = Get-NormalizedPath -PathValue $InstallerRoot
if (-not $normalizedInstallerRoot) {
    throw "Unable to normalize installer path: $InstallerRoot"
}

$referenceMap = @{}
$referencedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Add-ReferencedPath {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PathValue,
        [string]$Source
    )

    $normalized = Get-NormalizedPath -PathValue $PathValue
    if (-not $normalized) {
        return
    }

    if (-not $normalized.StartsWith($normalizedInstallerRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    if ($referencedPaths.Add($normalized)) {
        $referenceMap[$normalized] = [System.Collections.Generic.List[string]]::new()
    }

    if ($Source) {
        $referenceMap[$normalized].Add($Source)
    }
}

function Add-LocalPackageFromChildren {
    param(
        [string]$RootPath,
        [string]$SourcePrefix
    )

    if (-not (Test-Path -LiteralPath $RootPath)) {
        return
    }

    $childKeys = Get-ChildItem -LiteralPath $RootPath -ErrorAction SilentlyContinue
    foreach ($child in $childKeys) {
        $localPackage = Get-RegistryValueSafe -LiteralPath $child.PSPath -Name 'LocalPackage'
        if ($localPackage) {
            Add-ReferencedPath -PathValue $localPackage -Source "$SourcePrefix\$($child.PSChildName)"
        }
    }
}

function Add-UserDataProducts {
    param(
        [string]$UserDataRoot
    )

    if (-not (Test-Path -LiteralPath $UserDataRoot)) {
        return
    }

    $sidKeys = Get-ChildItem -LiteralPath $UserDataRoot -ErrorAction SilentlyContinue
    foreach ($sidKey in $sidKeys) {
        $productsRoot = Join-Path -Path $sidKey.PSPath -ChildPath 'Products'
        if (Test-Path -LiteralPath $productsRoot) {
            $productKeys = Get-ChildItem -LiteralPath $productsRoot -ErrorAction SilentlyContinue
            foreach ($productKey in $productKeys) {
                $installPropertiesPath = Join-Path -Path $productKey.PSPath -ChildPath 'InstallProperties'
                if (-not (Test-Path -LiteralPath $installPropertiesPath)) {
                    continue
                }

                $localPackage = Get-RegistryValueSafe -LiteralPath $installPropertiesPath -Name 'LocalPackage'
                if ($localPackage) {
                    Add-ReferencedPath -PathValue $localPackage -Source "UserData\Products\$($sidKey.PSChildName)\$($productKey.PSChildName)"
                }
            }
        }

        $patchesRoot = Join-Path -Path $sidKey.PSPath -ChildPath 'Patches'
        if (Test-Path -LiteralPath $patchesRoot) {
            $patchKeys = Get-ChildItem -LiteralPath $patchesRoot -ErrorAction SilentlyContinue
            foreach ($patchKey in $patchKeys) {
                $localPackage = Get-RegistryValueSafe -LiteralPath $patchKey.PSPath -Name 'LocalPackage'
                if ($localPackage) {
                    Add-ReferencedPath -PathValue $localPackage -Source "UserData\Patches\$($sidKey.PSChildName)\$($patchKey.PSChildName)"
                }
            }
        }
    }
}

Add-UserDataProducts -UserDataRoot 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
Add-LocalPackageFromChildren -RootPath 'HKLM:\SOFTWARE\Classes\Installer\Products' -SourcePrefix 'Classes\Installer\Products'
Add-LocalPackageFromChildren -RootPath 'HKLM:\SOFTWARE\Classes\Installer\Patches' -SourcePrefix 'Classes\Installer\Patches'
Add-LocalPackageFromChildren -RootPath 'HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products' -SourcePrefix 'WOW6432Node\Classes\Installer\Products'
Add-LocalPackageFromChildren -RootPath 'HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Patches' -SourcePrefix 'WOW6432Node\Classes\Installer\Patches'

$installerFiles = Get-ChildItem -LiteralPath $InstallerRoot -File -ErrorAction Stop |
    Where-Object { $trackedExtensions -contains $_.Extension.ToLowerInvariant() } |
    Sort-Object -Property Name

$referencedFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$orphanedFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

foreach ($file in $installerFiles) {
    $normalizedFilePath = Get-NormalizedPath -PathValue $file.FullName
    if ($normalizedFilePath -and $referencedPaths.Contains($normalizedFilePath)) {
        $referencedFiles.Add($file)
        continue
    }

    $orphanedFiles.Add($file)
}

$excludedOrphaned = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$candidateForRemoval = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
foreach ($orphan in $orphanedFiles) {
    if (Test-IsExcluded -File $orphan -Patterns $ExcludePattern) {
        $excludedOrphaned.Add($orphan)
        continue
    }

    $candidateForRemoval.Add($orphan)
}

$deletedFiles = [System.Collections.Generic.List[string]]::new()
$deleteFailures = [System.Collections.Generic.List[pscustomobject]]::new()

if ($Mode -eq 'Remediate') {
    foreach ($candidate in $candidateForRemoval) {
        if (-not $PSCmdlet.ShouldProcess($candidate.FullName, 'Delete orphaned installer cache file')) {
            continue
        }

        try {
            Remove-Item -LiteralPath $candidate.FullName -Force -ErrorAction Stop
            $deletedFiles.Add($candidate.FullName)
        }
        catch {
            $deleteFailures.Add([pscustomobject]@{
                    Path  = $candidate.FullName
                    Error = $_.Exception.Message
                })
        }
    }
}

$classification = foreach ($file in $installerFiles) {
    $normalizedFilePath = Get-NormalizedPath -PathValue $file.FullName
    $isReferenced = $normalizedFilePath -and $referencedPaths.Contains($normalizedFilePath)
    $isExcluded = $false
    $state = 'Orphaned'

    if ($isReferenced) {
        $state = 'Referenced'
    }
    else {
        $isExcluded = Test-IsExcluded -File $file -Patterns $ExcludePattern
        if ($isExcluded) {
            $state = 'OrphanedExcluded'
        }
    }

    [pscustomobject]@{
        State      = $state
        FileName   = $file.Name
        FullPath   = $file.FullName
        SizeMB     = [Math]::Round(($file.Length / 1MB), 2)
        LastWrite  = $file.LastWriteTime
        References = if ($isReferenced -and $referenceMap.ContainsKey($normalizedFilePath)) {
            $referenceMap[$normalizedFilePath] -join '; '
        }
        else {
            $null
        }
    }
}

$report = [pscustomobject]@{
    ComputerName                 = $env:COMPUTERNAME
    GeneratedAtUtc               = (Get-Date).ToUniversalTime().ToString('o')
    Mode                         = $Mode
    InstallerRoot                = $InstallerRoot
    TrackedExtensions            = $trackedExtensions
    ExcludePattern               = $ExcludePattern
    ScannedFileCount             = $installerFiles.Count
    ReferencedFileCount          = $referencedFiles.Count
    OrphanedFileCount            = $orphanedFiles.Count
    ExcludedOrphanedFileCount    = $excludedOrphaned.Count
    CandidateForRemovalFileCount = $candidateForRemoval.Count
    DeletedFileCount             = $deletedFiles.Count
    DeleteFailureCount           = $deleteFailures.Count
    ReferencedFiles              = Convert-FileListToPathArray -Files $referencedFiles
    OrphanedFiles                = Convert-FileListToPathArray -Files $orphanedFiles
    ExcludedOrphanedFiles        = Convert-FileListToPathArray -Files $excludedOrphaned
    CandidateForRemovalFiles     = Convert-FileListToPathArray -Files $candidateForRemoval
    DeletedFiles                 = @($deletedFiles)
    DeleteFailureDetails         = @($deleteFailures)
    FileClassification           = @($classification)
}

if ($ReportPath) {
    $parent = Split-Path -Path $ReportPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }

    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

$summary = [pscustomobject]@{
    Mode                         = $Mode
    InstallerRoot                = $InstallerRoot
    ScannedFileCount             = $report.ScannedFileCount
    ReferencedFileCount          = $report.ReferencedFileCount
    CandidateForRemovalFileCount = $report.CandidateForRemovalFileCount
    ExcludedOrphanedFileCount    = $report.ExcludedOrphanedFileCount
    DeletedFileCount             = $report.DeletedFileCount
    DeleteFailureCount           = $report.DeleteFailureCount
}

Write-Host ''
Write-Host 'Installer cache cleanup summary:' -ForegroundColor Cyan
$summary | Format-List | Out-Host

Write-Output $report
