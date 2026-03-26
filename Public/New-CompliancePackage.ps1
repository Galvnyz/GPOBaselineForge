function New-CompliancePackage {
    <#
    .SYNOPSIS
        Generates an Intune custom compliance package from classified baseline settings.
    .DESCRIPTION
        Produces two files: a PowerShell detection script and a JSON rules file
        for Intune custom compliance. Supports filtering by severity and category.
    .PARAMETER Setting
        Array of BaselineForge.Setting objects (classified via Set-BaselineSeverity).
    .PARAMETER OutputPath
        Directory to write the output files. Created if it does not exist.
    .PARAMETER Name
        Base name for the output files. Defaults to 'BaselineCompliance'.
    .PARAMETER MinSeverity
        Minimum severity tier to include. Settings below this tier are excluded.
        Order: Critical > High > Medium > Low.
    .PARAMETER IncludeCategory
        Only include settings from these categories.
    .EXAMPLE
        $settings | New-CompliancePackage -OutputPath './output' -MinSeverity High
    .EXAMPLE
        $settings | New-CompliancePackage -OutputPath './output' -IncludeCategory 'Credential Protection','Audit Logging'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Setting,

        [Parameter()]
        [string]$OutputPath = './output',

        [Parameter()]
        [string]$Name = 'BaselineCompliance',

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$MinSeverity,

        [Parameter()]
        [string[]]$IncludeCategory
    )

    begin {
        $allSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        foreach ($s in $Setting) {
            $allSettings.Add($s)
        }
    }

    end {
        $filtered = $allSettings.ToArray()

        # Apply severity filter
        if ($MinSeverity) {
            $severityOrder = @{
                'Critical' = 4
                'High'     = 3
                'Medium'   = 2
                'Low'      = 1
            }
            $minLevel = $severityOrder[$MinSeverity]
            $filtered = $filtered | Where-Object {
                $severityOrder[$_.Severity] -ge $minLevel
            }
        }

        # Apply category filter
        if ($IncludeCategory) {
            $filtered = $filtered | Where-Object {
                $_.Category -in $IncludeCategory
            }
        }

        $filtered = @($filtered)

        if ($filtered.Count -eq 0) {
            Write-Warning 'No settings match the specified filters. No output generated.'
            return
        }

        # Ensure output directory exists
        if (-not (Test-Path $OutputPath)) {
            $null = New-Item -Path $OutputPath -ItemType Directory -Force
        }

        # Build baseline name from first setting's GPO name
        $baselineName = ($filtered | Select-Object -First 1).PolicyName
        if (-not $baselineName) { $baselineName = 'Microsoft Security Baseline' }

        # Generate detection script
        Write-Verbose "Generating detection script for $($filtered.Count) settings..."
        $scriptContent = New-DetectionScript -Setting $filtered -BaselineName $baselineName

        $scriptPath = Join-Path $OutputPath "$Name-Detection.ps1"
        Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8

        # Generate rules JSON
        Write-Verbose 'Generating compliance rules JSON...'
        $rulesContent = New-ComplianceRulesJson -Setting $filtered

        $rulesPath = Join-Path $OutputPath "$Name-Rules.json"
        Set-Content -Path $rulesPath -Value $rulesContent -Encoding UTF8

        # Validate the generated script is valid PowerShell
        try {
            $null = [scriptblock]::Create($scriptContent)
            $scriptValid = $true
        }
        catch {
            Write-Warning "Generated detection script has syntax errors: $_"
            $scriptValid = $false
        }

        # Return summary
        $summary = [PSCustomObject]@{
            PSTypeName         = 'BaselineForge.CompliancePackage'
            Name               = $Name
            DetectionScriptPath = (Resolve-Path $scriptPath).Path
            RulesJsonPath       = (Resolve-Path $rulesPath).Path
            TotalSettings      = $filtered.Count
            SeverityBreakdown  = ($filtered | Group-Object Severity | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', '
            CategoryBreakdown  = ($filtered | Group-Object Category | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', '
            ScriptSizeKB       = [math]::Round((Get-Item $scriptPath).Length / 1KB, 1)
            RulesSizeKB        = [math]::Round((Get-Item $rulesPath).Length / 1KB, 1)
            ScriptValid        = $scriptValid
            MinSeverity        = if ($MinSeverity) { $MinSeverity } else { 'All' }
        }

        Write-Verbose "Package generated: $($filtered.Count) settings, script $($summary.ScriptSizeKB)KB, rules $($summary.RulesSizeKB)KB"
        return $summary
    }
}
