# GPOBaselineForge — Project Instructions

## What This Is

GPOBaselineForge is a PowerShell module: Parse Microsoft security baselines and generate Intune custom compliance packages

## Architecture

- `GPOBaselineForge.psm1` — Root module (dot-sources Public/ and Private/)
- `Public/*.ps1` — Exported functions
- `Private/*.ps1` — Internal helper functions
- `data/` — Static data files (JSON, CSV)
- `scripts/` — Standalone utility scripts
- `tests/` — Pester tests

## Conventions

- PowerShell 7.0+ only (`pwsh`)
- `[CmdletBinding()]` and comment-based help on every function
- PascalCase params, camelCase locals
- `$script:` for module-scoped state, never `$global:`
- Explicit `Export-ModuleMember` in .psm1

## Running Tests

```powershell
Invoke-Pester ./tests/ -Output Detailed
```
