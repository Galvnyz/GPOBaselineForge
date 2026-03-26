function Import-BaselineGPO {
    <#
    .SYNOPSIS
        Parses a Microsoft security baseline package into normalized settings.
    .DESCRIPTION
        Reads a Microsoft Security Compliance Toolkit baseline package directory
        and extracts all security settings (registry, audit, privilege rights,
        system access, service config) as BaselineForge.Setting objects.

        The primary data source is the .PolicyRules XML file in the Documentation
        folder, which contains pre-extracted settings from all GPOs.
    .PARAMETER Path
        Path to the root directory of the security baseline package.
    .PARAMETER IncludeGPO
        Filter to include only settings from GPOs matching these names (supports wildcards).
    .PARAMETER ExcludeGPO
        Filter to exclude settings from GPOs matching these names (supports wildcards).
    .EXAMPLE
        Import-BaselineGPO -Path 'C:\Baselines\Windows 11 v25H2 Security Baseline'
    .EXAMPLE
        Import-BaselineGPO -Path '.\baseline' -ExcludeGPO '*Internet Explorer*'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$Path,

        [Parameter()]
        [string[]]$IncludeGPO,

        [Parameter()]
        [string[]]$ExcludeGPO
    )

    $resolvedPath = Resolve-Path -Path $Path

    # Find the PolicyRules XML file
    $policyRulesFile = Get-ChildItem -Path (Join-Path $resolvedPath 'Documentation') -Filter '*.PolicyRules' -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $policyRulesFile) {
        Write-Error "No .PolicyRules file found in '$resolvedPath\Documentation'. Ensure this is a valid Microsoft security baseline package."
        return
    }

    Write-Verbose "Parsing PolicyRules: $($policyRulesFile.FullName)"
    $settings = Read-PolicyRulesXml -Path $policyRulesFile.FullName

    Write-Verbose "Parsed $($settings.Count) settings from PolicyRules XML"

    # Deduplicate: registry settings from SecurityTemplate may overlap with ComputerConfig.
    # Keep PolicyRules source over SecurityTemplate when there's a collision.
    $seen = @{}
    $deduped = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($setting in $settings) {
        $dedupeKey = switch ($setting.SettingType) {
            'Registry'       { "REG:$($setting.RegistryKey)\$($setting.ValueName)" }
            'AuditPolicy'    { "AUD:$($setting.ValueName)" }
            'PrivilegeRight' { "PRV:$($setting.ValueName)" }
            'SystemAccess'   { "ACC:$($setting.ValueName)" }
            'ServiceConfig'  { "SVC:$($setting.ValueName)" }
        }

        if ($seen.ContainsKey($dedupeKey)) {
            # Prefer PolicyRules source over SecurityTemplate
            if ($setting.Source -eq 'PolicyRules' -and $seen[$dedupeKey].Source -eq 'SecurityTemplate') {
                $idx = $deduped.IndexOf($seen[$dedupeKey])
                if ($idx -ge 0) { $deduped[$idx] = $setting }
                $seen[$dedupeKey] = $setting
            }
            continue
        }

        $seen[$dedupeKey] = $setting
        $deduped.Add($setting)
    }

    Write-Verbose "After deduplication: $($deduped.Count) unique settings"

    # Apply GPO filters
    $filtered = $deduped

    if ($IncludeGPO) {
        $filtered = $filtered | Where-Object {
            $gpo = $_.SourceGPO
            $IncludeGPO | Where-Object { $gpo -like $_ } | Select-Object -First 1
        }
    }

    if ($ExcludeGPO) {
        $filtered = $filtered | Where-Object {
            $gpo = $_.SourceGPO
            -not ($ExcludeGPO | Where-Object { $gpo -like $_ } | Select-Object -First 1)
        }
    }

    $result = @($filtered)
    Write-Verbose "Returning $($result.Count) settings after GPO filtering"
    return $result
}
