function Invoke-BaselineForge {
    <#
    .SYNOPSIS
        Runs the full GPOBaselineForge pipeline in one command.
    .DESCRIPTION
        Orchestrates the complete baseline-to-compliance workflow:
        Import → Classify → Generate → optionally Publish.
    .PARAMETER BaselinePath
        Path to the Microsoft security baseline package directory.
    .PARAMETER OutputPath
        Directory for generated compliance artifacts.
    .PARAMETER Name
        Base name for output files.
    .PARAMETER MinSeverity
        Minimum severity tier to include in the compliance package.
    .PARAMETER IncludeCategory
        Only include settings from these categories.
    .PARAMETER ExcludeGPO
        Exclude settings from GPOs matching these names.
    .PARAMETER SeverityMapPath
        Path to a custom severity mapping JSON file.
    .PARAMETER CategoryMapPath
        Path to a custom category mapping JSON file.
    .PARAMETER Publish
        Deploy the generated package to Intune via Graph API.
    .PARAMETER WhatIf
        Show what would happen without making changes.
    .EXAMPLE
        Invoke-BaselineForge -BaselinePath '.\baseline' -OutputPath './output' -MinSeverity High
    .EXAMPLE
        Invoke-BaselineForge -BaselinePath '.\baseline' -IncludeCategory 'Credential Protection'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$BaselinePath,

        [Parameter()]
        [string]$OutputPath = './output',

        [Parameter()]
        [string]$Name = 'BaselineCompliance',

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$MinSeverity,

        [Parameter()]
        [string[]]$IncludeCategory,

        [Parameter()]
        [string[]]$ExcludeGPO,

        [Parameter()]
        [string]$SeverityMapPath,

        [Parameter()]
        [string]$CategoryMapPath,

        [Parameter()]
        [switch]$Publish
    )

    # Stage 1: Parse
    Write-Verbose '=== Stage 1: Parsing baseline ==='
    $importParams = @{ Path = $BaselinePath }
    if ($ExcludeGPO) { $importParams.ExcludeGPO = $ExcludeGPO }
    $settings = Import-BaselineGPO @importParams
    Write-Verbose "Parsed $($settings.Count) settings"

    # Stage 2: Classify
    Write-Verbose '=== Stage 2: Classifying settings ==='
    $classifyParams = @{}
    if ($SeverityMapPath) { $classifyParams.SeverityMapPath = $SeverityMapPath }
    if ($CategoryMapPath) { $classifyParams.CategoryMapPath = $CategoryMapPath }
    $classified = $settings | Set-BaselineSeverity @classifyParams
    Write-Verbose "Classified: $(($classified | Group-Object Severity | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', ')"

    # Stage 3: Generate
    Write-Verbose '=== Stage 3: Generating compliance package ==='
    $packageParams = @{
        OutputPath = $OutputPath
        Name       = $Name
    }
    if ($MinSeverity) { $packageParams.MinSeverity = $MinSeverity }
    if ($IncludeCategory) { $packageParams.IncludeCategory = $IncludeCategory }

    if ($PSCmdlet.ShouldProcess("$OutputPath/$Name", 'Generate compliance package')) {
        $package = $classified | New-CompliancePackage @packageParams
    }

    # Stage 4: Publish (optional)
    if ($Publish -and $package) {
        Write-Verbose '=== Stage 4: Publishing to Intune ==='
        if ($PSCmdlet.ShouldProcess('Intune', 'Publish compliance policy')) {
            $package | Add-Member -NotePropertyName Published -NotePropertyValue $false
            Publish-CompliancePolicy -DetectionScriptPath $package.DetectionScriptPath -RulesJsonPath $package.RulesJsonPath -PolicyName $Name
            $package.Published = $true
        }
    }

    return $package
}
