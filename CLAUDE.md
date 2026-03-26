# GPOBaselineForge — Project Instructions

## What This Is

GPOBaselineForge parses Microsoft security baseline GPO exports and generates Intune custom compliance packages (detection script + JSON rules). It closes the gap between Intune's configuration-only security baselines and compliance reporting.

## Architecture

Pipeline pattern with 4 stages, each independently usable:

```
Import-BaselineGPO → Set-BaselineSeverity → New-CompliancePackage → Publish-CompliancePolicy
     (Parse)              (Classify)              (Generate)              (Deploy)
```

- `GPOBaselineForge.psm1` — Root module (dot-sources Public/ and Private/)
- `Public/` — 6 exported cmdlets (pipeline stages + orchestrator + utility)
- `Private/` — Parsers (Read-PolicyRulesXml), generators (New-DetectionScript, New-ComplianceRulesJson), helpers
- `data/severity-map/` — Curated severity tier mappings per baseline version
- `data/category-map/` — Functional category mappings per baseline version
- `tests/` — Pester 5.x tests (Smoke, Unit, Integration)

## Key Concepts

- **BaselineForge.Setting** — Normalized PSCustomObject representing one security setting (registry, audit, privilege right, system access, or service config)
- **Severity tiers** — Critical, High, Medium, Low. Only Critical+High go into compliance by default
- **Categories** — Credential Protection, Network Security, Audit Logging, etc.
- **PolicyRules XML** — Primary data source. Microsoft's pre-extracted settings from all GPOs in one XML file

## Public Cmdlets

| Cmdlet | Purpose |
|--------|---------|
| `Import-BaselineGPO` | Parse baseline → `BaselineForge.Setting[]` |
| `Set-BaselineSeverity` | Apply severity + category from JSON maps |
| `New-CompliancePackage` | Generate detection script + rules JSON |
| `Publish-CompliancePolicy` | Deploy to Intune via Graph API |
| `Invoke-BaselineForge` | Full pipeline orchestrator |
| `Get-BaselineInventory` | Reporting/inspection utility |

## Conventions

- PowerShell 7.0+ only (`pwsh`)
- `[CmdletBinding()]` and comment-based help on every function
- PascalCase params, camelCase locals
- `$script:` for module-scoped state, never `$global:`
- PSScriptAnalyzer clean

## Running Tests

```powershell
Import-Module ./GPOBaselineForge.psd1 -Force
Invoke-Pester ./tests/ -Output Detailed
```

## Quick Start

```powershell
Import-Module ./GPOBaselineForge.psd1
Invoke-BaselineForge -BaselinePath '.\baseline' -OutputPath './output' -MinSeverity High -Name 'Win11-25H2'
```
