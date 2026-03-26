<#
.SYNOPSIS
    GPOBaselineForge — Parse Microsoft security baselines and generate Intune custom compliance packages
.DESCRIPTION
    Provides cmdlets to interact with GPOBaselineForge data and functionality.
#>

$script:ModuleRoot = $PSScriptRoot

# Dot-source private functions first, then public
foreach ($file in (Get-ChildItem "$PSScriptRoot/Private/*.ps1" -ErrorAction SilentlyContinue)) {
    . $file.FullName
}
foreach ($file in (Get-ChildItem "$PSScriptRoot/Public/*.ps1" -ErrorAction SilentlyContinue)) {
    . $file.FullName
}
