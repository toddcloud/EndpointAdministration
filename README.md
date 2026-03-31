# EndpointAdministration

## Invoke-InstallerPatchCleanup.ps1

PowerShell remediation script that detects and removes orphaned `.msi` and `.msp` files from `C:\Windows\Installer`. Replicates the core behavior of the [PatchCleaner](https://www.homedev.com.au/free/patchcleaner) utility.

### How It Works

1. **Queries the Windows Installer COM API** (`WindowsInstaller.Installer`) to enumerate every registered product and patch, resolving each to its `LocalPackage` path inside `C:\Windows\Installer`.
2. **Falls back to the registry** (`HKLM:\...\Installer\UserData`) to catch patches not surfaced through the COM enumeration.
3. **Scans the disk** for all `.msi` and `.msp` files in `C:\Windows\Installer`.
4. **Classifies every file** as In-Use (referenced by a current installation), Excluded (protected by a vendor/product filter), or Orphaned (safe to remove).
5. **Acts on orphaned files** according to the chosen mode: report, delete, or move.

### Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Must be run as **Administrator** (the script checks and exits if not elevated)

### Usage

```powershell
# Report only (default) — lists files and reclaimable space
.\Invoke-InstallerPatchCleanup.ps1

# Delete orphaned files (prompts for confirmation)
.\Invoke-InstallerPatchCleanup.ps1 -Mode Delete

# Delete without prompting
.\Invoke-InstallerPatchCleanup.ps1 -Mode Delete -Force

# Move orphaned files to a backup folder
.\Invoke-InstallerPatchCleanup.ps1 -Mode Move -BackupPath D:\InstallerBackup

# Custom exclusion filters
.\Invoke-InstallerPatchCleanup.ps1 -ExcludeVendors 'Adobe','Acrobat','Microsoft Office'
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `Report` | `Report`, `Delete`, or `Move` |
| `-BackupPath` | `C:\Windows\Installer\_Orphaned` | Destination for moved files |
| `-ExcludeVendors` | `@('Adobe', 'Acrobat')` | Vendor/product name substrings to protect |
| `-ExcludeProductCodes` | `@()` | Product GUIDs to protect unconditionally |
| `-Force` | `$false` | Skip confirmation prompt for Delete/Move |
| `-LogPath` | `$env:TEMP\InstallerPatchCleanup.log` | Log file location |

### Output

The script returns a `PSCustomObject` with summary statistics:

```
TotalFiles, TotalSize, InUseCount, InUseSize, ExcludedCount, ExcludedSize,
OrphanedCount, OrphanedSize, Processed, Failed, Mode
```

A detailed log is also written to `$env:TEMP\InstallerPatchCleanup.log` (configurable via `-LogPath`).

### Safety

- **Report mode is the default** — nothing is deleted or moved unless you explicitly choose Delete or Move.
- **Exclusion filters** protect files associated with specific vendors (Adobe/Acrobat by default).
- **Confirmation prompt** is shown before destructive operations unless `-Force` is used.
- **`-WhatIf` support** is built in via `SupportsShouldProcess`.
- **Move mode** provides a non-destructive alternative that lets you verify results before permanently deleting.
