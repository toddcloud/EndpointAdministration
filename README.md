# EndpointAdministration

## Invoke-InstallerCleanup.ps1 — Windows Installer Orphaned File Cleanup

A PowerShell remediation script that replicates the behaviour of [PatchCleaner](https://patchcleaner.com/) by identifying and removing orphaned `.msi` and `.msp` files from `C:\Windows\Installer`.

### How It Works

1. **Enumerates registered products** — Uses the `WindowsInstaller.Installer` COM API to collect every product code, patch code, and `LocalPackage` path known to Windows.
2. **Scans the Installer directory** — Lists all files and subdirectories under `C:\Windows\Installer`.
3. **Classifies each item** with two passes:
   - **Exact path match** — If the file path matches a registered `LocalPackage`, it is marked **In Use**.
   - **GUID match** — If the file/folder name contains a product or patch GUID that is still registered, it is marked **In Use**.
   - Items matching no registered entry are classified as **Orphaned**.
4. **Applies exclusion filters** — Known-sensitive products (e.g. Adobe Acrobat) are protected from removal even if they appear orphaned.
5. **Takes action** — Report only (default), move to a backup folder, or permanently delete.

### Requirements

| Requirement | Detail |
|---|---|
| OS | Windows 7 / Server 2008 R2 or later |
| Shell | Windows PowerShell 5.1+ or PowerShell 7+ on Windows |
| Privileges | **Must be run as Administrator** |
| Dependencies | None (uses built-in COM API) |

### Quick Start

```powershell
# Report only — scan and show what would be cleaned, touch nothing
.\Invoke-InstallerCleanup.ps1

# Move orphaned files to a backup directory
.\Invoke-InstallerCleanup.ps1 -Action Move -BackupPath D:\InstallerBackup

# Permanently delete orphaned files (will prompt for confirmation)
.\Invoke-InstallerCleanup.ps1 -Action Delete

# Delete without confirmation prompt
.\Invoke-InstallerCleanup.ps1 -Action Delete -Force
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Action` | `ReportOnly` \| `Move` \| `Delete` | `ReportOnly` | What to do with orphaned files. |
| `-BackupPath` | `string` | `C:\WindowsInstallerBackup` | Destination when Action is `Move`. |
| `-ExclusionFile` | `string` | — | Path to a JSON file with extra exclusion rules. |
| `-SkipDefaultExclusions` | `switch` | — | Disables built-in exclusions (Adobe, Office, etc.). |
| `-Force` | `switch` | — | Suppresses the confirmation prompt. |
| `-LogPath` | `string` | `.\InstallerCleanup_<timestamp>.csv` | Where to write the detailed CSV log. |

### Built-in Exclusion Filters

The following products are excluded by default to prevent issues with licence-sensitive installers:

- Adobe Acrobat / Reader (including `{AC7*}` patch GUIDs)
- Adobe Creative Cloud
- Microsoft Office / Microsoft 365
- Microsoft Visual C++ Redistributable
- Microsoft .NET Framework

To add your own, supply a JSON file via `-ExclusionFile`:

```json
[
  {
    "Name": "My Custom App",
    "ProductName": ["MyApp*"],
    "PathPattern": ["*\\MyApp*"]
  }
]
```

### Output

The script produces:

- **Console report** with item counts and reclaimable space.
- **CSV log** (`InstallerCleanup_<timestamp>.csv`) with per-file status, size, and classification detail.

### Safety Notes

- **Always run `ReportOnly` first** to review what will be affected.
- When using `-Action Move`, files are preserved in the backup folder and can be restored by copying them back.
- The script honours PowerShell's `-WhatIf` via `SupportsShouldProcess`.
