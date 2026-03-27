<#
.SYNOPSIS
    Generates all category-based compliance packages from the Win11 25H2 baseline.
.DESCRIPTION
    Imports the full baseline, classifies settings, then generates one compliance
    package per category. Validates each package with Test-CompliancePackage and
    produces a manifest.json summarizing all packages.
.PARAMETER BaselinePath
    Path to the Microsoft Security Baseline directory.
.PARAMETER OutputPath
    Root output directory. Packages are written to {OutputPath}/{CategoryName}/.
.PARAMETER BaselineName
    Name prefix for the baseline (e.g., 'Win11-25H2'). Defaults to 'Win11-25H2'.
.EXAMPLE
    .\Build-AllPackages.ps1 -BaselinePath 'C:\baselines\Win11-25H2' -OutputPath './output/release/Win11-25H2'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$BaselinePath,

    [Parameter()]
    [string]$OutputPath = './output/release/Win11-25H2',

    [Parameter()]
    [string]$BaselineName = 'Win11-25H2'
)

$ErrorActionPreference = 'Stop'

# Import module
$modulePath = Join-Path $PSScriptRoot '..' 'GPOBaselineForge.psd1'
Import-Module $modulePath -Force

# Parse and classify
Write-Host "Importing baseline from: $BaselinePath" -ForegroundColor Cyan
$settings = Import-BaselineGPO -Path $BaselinePath | Set-BaselineSeverity
Write-Host "Total settings: $($settings.Count)" -ForegroundColor Green

# Get unique categories (excluding 'General' which is the default/uncategorized)
$categories = $settings | Select-Object -ExpandProperty Category -Unique | Sort-Object
Write-Host "Categories found: $($categories.Count)" -ForegroundColor Green
Write-Host ($categories -join ', ')

# Generate one package per category
$manifest = @{
    baseline       = 'Windows 11 v25H2 Security Baseline'
    generatedDate  = (Get-Date -Format 'yyyy-MM-dd')
    generatedBy    = 'GPOBaselineForge'
    totalSettings  = $settings.Count
    packages       = @()
}

$totalTypeErrors = 0

foreach ($category in $categories) {
    $safeName = $category -replace '\s+&\s+', 'And' -replace '\s+', ''
    $packageName = "$BaselineName-$safeName"
    $packageOutput = Join-Path $OutputPath $safeName

    Write-Host "`nGenerating: $category ($safeName)" -ForegroundColor Yellow

    $pkg = $settings | New-CompliancePackage -OutputPath $packageOutput -Name $packageName -IncludeCategory $category

    # Validate with TypeCheck
    $typeResults = $pkg | Test-CompliancePackage -Mode TypeCheck
    $typeErrors = @($typeResults | Where-Object Status -eq 'TypeError')

    $status = if ($typeErrors.Count -eq 0) { 'PASS' } else { 'FAIL' }
    $statusColor = if ($typeErrors.Count -eq 0) { 'Green' } else { 'Red' }
    Write-Host "  Settings: $($pkg.TotalSettings) | Script: $($pkg.ScriptSizeKB) KB | TypeCheck: $status" -ForegroundColor $statusColor

    if ($typeErrors.Count -gt 0) {
        $totalTypeErrors += $typeErrors.Count
        foreach ($err in $typeErrors) {
            Write-Host "    TypeError: $($err.SettingName) — actual: $($err.ActualValue)" -ForegroundColor Red
        }
    }

    # Rename files to simple Detection.ps1 / Rules.json for the public repo
    $detectionDest = Join-Path $packageOutput 'Detection.ps1'
    $rulesDest = Join-Path $packageOutput 'Rules.json'

    if ($pkg.DetectionScriptPath -ne $detectionDest) {
        Move-Item -Path $pkg.DetectionScriptPath -Destination $detectionDest -Force
    }
    if ($pkg.RulesJsonPath -ne $rulesDest) {
        Move-Item -Path $pkg.RulesJsonPath -Destination $rulesDest -Force
    }

    $manifest.packages += @{
        category      = $category
        directory     = $safeName
        settingCount  = $pkg.TotalSettings
        scriptSizeKB  = $pkg.ScriptSizeKB
        rulesSizeKB   = $pkg.RulesSizeKB
        severity      = $pkg.SeverityBreakdown
        typeCheckPass = ($typeErrors.Count -eq 0)
    }
}

# Write manifest
$manifestPath = Join-Path $OutputPath 'manifest.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8
Write-Host "`nManifest written to: $manifestPath" -ForegroundColor Cyan

# Summary
Write-Host "`n=== Build Summary ===" -ForegroundColor Cyan
Write-Host "Packages generated: $($manifest.packages.Count)"
Write-Host "Total settings across all packages: $(($manifest.packages | Measure-Object -Property settingCount -Sum).Sum)"
Write-Host "TypeCheck errors: $totalTypeErrors"

if ($totalTypeErrors -gt 0) {
    Write-Host "`nBUILD FAILED — $totalTypeErrors TypeCheck errors detected" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "`nBUILD PASSED — all packages validated" -ForegroundColor Green
}
