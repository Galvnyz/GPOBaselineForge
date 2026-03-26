function Set-BaselineSeverity {
    <#
    .SYNOPSIS
        Applies severity and category classifications to baseline settings.
    .DESCRIPTION
        Reads severity and category mapping JSON files and applies them to
        BaselineForge.Setting objects using wildcard pattern matching.
        Settings are matched against rules in order; first match wins.
    .PARAMETER Setting
        Array of BaselineForge.Setting objects from Import-BaselineGPO.
    .PARAMETER SeverityMapPath
        Path to a severity mapping JSON file. Defaults to the built-in W11 25H2 map.
    .PARAMETER CategoryMapPath
        Path to a category mapping JSON file. Defaults to the built-in W11 25H2 map.
    .EXAMPLE
        Import-BaselineGPO -Path '.\baseline' | Set-BaselineSeverity
    .EXAMPLE
        $settings | Set-BaselineSeverity -SeverityMapPath './custom-severity.json'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Setting,

        [Parameter()]
        [string]$SeverityMapPath,

        [Parameter()]
        [string]$CategoryMapPath
    )

    begin {
        $moduleRoot = $script:ModuleRoot
        if (-not $moduleRoot) {
            $moduleRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        }

        # Load severity map
        if (-not $SeverityMapPath) {
            $SeverityMapPath = Join-Path $moduleRoot 'data/severity-map/win11-25h2.json'
        }
        $severityMap = Get-Content -Path $SeverityMapPath -Raw | ConvertFrom-Json
        $defaultSeverity = $severityMap.defaultSeverity

        # Load category map
        if (-not $CategoryMapPath) {
            $CategoryMapPath = Join-Path $moduleRoot 'data/category-map/win11-25h2.json'
        }
        $categoryMap = Get-Content -Path $CategoryMapPath -Raw | ConvertFrom-Json
        $defaultCategory = $categoryMap.defaultCategory

        $allSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        foreach ($s in $Setting) {
            $allSettings.Add($s)
        }
    }

    end {
        foreach ($s in $allSettings) {
            # Build match target based on setting type
            $matchTarget = switch ($s.SettingType) {
                'Registry'       { $s.RegistryKey + '\' + $s.ValueName }
                'AuditPolicy'    { $s.ValueName }
                'PrivilegeRight' { $s.ValueName }
                'SystemAccess'   { $s.ValueName }
                'ServiceConfig'  { $s.ValueName }
            }

            # Apply severity - first match wins
            $s.Severity = $defaultSeverity
            foreach ($rule in $severityMap.rules) {
                if ($rule.settingType -and $rule.settingType -ne $s.SettingType) { continue }
                if ($matchTarget -like $rule.pattern) {
                    $s.Severity = $rule.severity
                    break
                }
            }

            # Apply category - first match wins
            $s.Category = $defaultCategory
            foreach ($rule in $categoryMap.rules) {
                if ($rule.settingType -and $rule.settingType -ne $s.SettingType) { continue }
                if ($matchTarget -like $rule.pattern) {
                    $s.Category = $rule.category
                    break
                }
            }
        }

        return $allSettings.ToArray()
    }
}
