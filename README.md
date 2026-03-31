# EndpointAdministration

## Windows Installer orphaned cache remediation script

`Remove-OrphanedInstallerCache.ps1` is a PowerShell remediation script that mirrors the core Patch Cleaner approach for:

- Scanning only `C:\Windows\Installer`
- Classifying installer cache files as:
  - `Referenced` (still associated with installed products/patches)
  - `Orphaned` (no active association found)
  - `OrphanedExcluded` (orphaned but skipped by your exclusion filters)
- Optionally deleting only orphaned, non-excluded files in remediation mode

### What it scans

- Extensions: `.msi`, `.msp` (plus `.mst` when `-IncludeMst` is used)
- Windows Installer registry references under:
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData`
  - `HKLM:\SOFTWARE\Classes\Installer\Products`
  - `HKLM:\SOFTWARE\Classes\Installer\Patches`
  - `HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Products`
  - `HKLM:\SOFTWARE\WOW6432Node\Classes\Installer\Patches`

### Usage

Audit only (safe, no deletion):

```powershell
.\Remove-OrphanedInstallerCache.ps1 -Mode Audit -ReportPath C:\Temp\InstallerAudit.json
```

Audit with exclusion filters (example: Acrobat):

```powershell
.\Remove-OrphanedInstallerCache.ps1 -Mode Audit -ExcludePattern Acrobat,Adobe -ReportPath C:\Temp\InstallerAudit.json
```

Remediate orphaned files (requires elevated PowerShell):

```powershell
.\Remove-OrphanedInstallerCache.ps1 -Mode Remediate -ExcludePattern Acrobat,Adobe -ReportPath C:\Temp\InstallerRemediation.json -WhatIf
```

When ready to actually delete, remove `-WhatIf`:

```powershell
.\Remove-OrphanedInstallerCache.ps1 -Mode Remediate -ExcludePattern Acrobat,Adobe -ReportPath C:\Temp\InstallerRemediation.json
```

### Safety notes

- Start with `-Mode Audit` and review the report first.
- Use `-WhatIf` in remediation mode for a dry run.
- Keep vendor filters (for example `Acrobat`, `Adobe`) in `-ExcludePattern` until validated in your environment.
