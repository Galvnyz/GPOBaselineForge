function Read-PolicyRulesXml {
    <#
    .SYNOPSIS
        Parses a Microsoft Security Baseline PolicyRules XML file.
    .DESCRIPTION
        Reads ComputerConfig, UserConfig, SecurityTemplate, and AuditSubcategory
        elements from a .PolicyRules XML file and returns normalized
        BaselineForge.Setting objects.
    .PARAMETER Path
        Path to the .PolicyRules XML file.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $settings = [System.Collections.Generic.List[PSCustomObject]]::new()
    [xml]$xml = Get-Content -Path $Path -Raw

    # --- ComputerConfig and UserConfig (registry-based settings) ---
    foreach ($configType in @('ComputerConfig', 'UserConfig')) {
        $hive = if ($configType -eq 'ComputerConfig') { 'HKLM' } else { 'HKU' }
        $elements = $xml.PolicyRules.$configType
        if (-not $elements) { continue }

        foreach ($entry in $elements) {
            $regKey = "$hive\$($entry.Key)"
            $valueName = $entry.Value
            $id = New-SettingId -SettingType 'Registry' -Identifier "$($entry.Key)\$valueName"

            $expectedValue = switch ($entry.RegType) {
                'REG_DWORD'     { [int]$entry.RegData }
                'REG_QWORD'     { [long]$entry.RegData }
                'REG_SZ'        { [string]$entry.RegData }
                'REG_EXPAND_SZ' { [string]$entry.RegData }
                'REG_MULTI_SZ'  { [string]$entry.RegData }
                default         { $entry.RegData }
            }

            $setting = [PSCustomObject]@{
                PSTypeName    = 'BaselineForge.Setting'
                Id            = $id
                Source        = 'PolicyRules'
                SourceGPO     = $entry.PolicyName
                SettingType   = 'Registry'
                RegistryHive  = $hive
                RegistryKey   = $regKey
                ValueName     = $valueName
                DataType      = $entry.RegType
                ExpectedValue = $expectedValue
                Category      = ''
                Severity      = ''
                PolicyName    = $entry.PolicyName
                Description   = ''
            }
            $settings.Add($setting)
        }
    }

    # --- SecurityTemplate elements (GptTmpl.inf data) ---
    $secTemplates = $xml.PolicyRules.SecurityTemplate
    if ($secTemplates) {
        foreach ($entry in $secTemplates) {
            $section = $entry.Section
            $lineItem = $entry.LineItem
            $policyName = $entry.PolicyName

            switch ($section) {
                'Registry Values' {
                    # Format: MACHINE\Path\ValueName=Type,Data
                    if ($lineItem -match '^MACHINE\\(.+?)=(\d+),(.*)$') {
                        $fullPath = $Matches[1]
                        $typeCode = [int]$Matches[2]
                        $rawData = $Matches[3]

                        # Split path into key + value name
                        $lastSlash = $fullPath.LastIndexOf('\')
                        if ($lastSlash -gt 0) {
                            $regKeyPath = $fullPath.Substring(0, $lastSlash)
                            $valName = $fullPath.Substring($lastSlash + 1)
                        }
                        else {
                            $regKeyPath = $fullPath
                            $valName = ''
                        }

                        $dataType = switch ($typeCode) {
                            1 { 'REG_SZ' }
                            2 { 'REG_EXPAND_SZ' }
                            3 { 'REG_BINARY' }
                            4 { 'REG_DWORD' }
                            7 { 'REG_MULTI_SZ' }
                            default { "TYPE_$typeCode" }
                        }

                        $expectedVal = switch ($typeCode) {
                            4 { [int]$rawData }
                            1 { $rawData.Trim('"') }
                            default { $rawData }
                        }

                        $id = New-SettingId -SettingType 'Registry' -Identifier "$regKeyPath\$valName"

                        $setting = [PSCustomObject]@{
                            PSTypeName    = 'BaselineForge.Setting'
                            Id            = $id
                            Source        = 'SecurityTemplate'
                            SourceGPO     = $policyName
                            SettingType   = 'Registry'
                            RegistryHive  = 'HKLM'
                            RegistryKey   = "HKLM\$regKeyPath"
                            ValueName     = $valName
                            DataType      = $dataType
                            ExpectedValue = $expectedVal
                            Category      = ''
                            Severity      = ''
                            PolicyName    = $policyName
                            Description   = ''
                        }
                        $settings.Add($setting)
                    }
                }
                'Privilege Rights' {
                    # Format: PrivilegeName=*SID1,*SID2 or PrivilegeName=
                    if ($lineItem -match '^(\w+)=(.*)$') {
                        $privName = $Matches[1]
                        $sids = $Matches[2]
                        $id = New-SettingId -SettingType 'PrivilegeRight' -Identifier $privName

                        $setting = [PSCustomObject]@{
                            PSTypeName    = 'BaselineForge.Setting'
                            Id            = $id
                            Source        = 'SecurityTemplate'
                            SourceGPO     = $policyName
                            SettingType   = 'PrivilegeRight'
                            RegistryHive  = ''
                            RegistryKey   = ''
                            ValueName     = $privName
                            DataType      = 'SID_LIST'
                            ExpectedValue = $sids
                            Category      = ''
                            Severity      = ''
                            PolicyName    = $policyName
                            Description   = ''
                        }
                        $settings.Add($setting)
                    }
                }
                'System Access' {
                    # Format: PolicyKey=Value
                    if ($lineItem -match '^(\w+)=(.*)$') {
                        $policyKey = $Matches[1]
                        $rawValue = $Matches[2]
                        $id = New-SettingId -SettingType 'SystemAccess' -Identifier $policyKey

                        # Try to parse as integer
                        $parsedValue = if ($rawValue -match '^\d+$') { [int]$rawValue } else { $rawValue }

                        $setting = [PSCustomObject]@{
                            PSTypeName    = 'BaselineForge.Setting'
                            Id            = $id
                            Source        = 'SecurityTemplate'
                            SourceGPO     = $policyName
                            SettingType   = 'SystemAccess'
                            RegistryHive  = ''
                            RegistryKey   = ''
                            ValueName     = $policyKey
                            DataType      = 'POLICY_VALUE'
                            ExpectedValue = $parsedValue
                            Category      = ''
                            Severity      = ''
                            PolicyName    = $policyName
                            Description   = ''
                        }
                        $settings.Add($setting)
                    }
                }
                'Service General Setting' {
                    # Format: "ServiceName",StartupType,"ACL"
                    if ($lineItem -match '^"(\w+)",(\d+),') {
                        $svcName = $Matches[1]
                        $startupType = [int]$Matches[2]
                        $id = New-SettingId -SettingType 'ServiceConfig' -Identifier $svcName

                        $setting = [PSCustomObject]@{
                            PSTypeName    = 'BaselineForge.Setting'
                            Id            = $id
                            Source        = 'SecurityTemplate'
                            SourceGPO     = $policyName
                            SettingType   = 'ServiceConfig'
                            RegistryHive  = ''
                            RegistryKey   = ''
                            ValueName     = $svcName
                            DataType      = 'STARTUP_TYPE'
                            ExpectedValue = $startupType
                            Category      = ''
                            Severity      = ''
                            PolicyName    = $policyName
                            Description   = ''
                        }
                        $settings.Add($setting)
                    }
                }
            }
        }
    }

    # --- AuditSubcategory elements ---
    $auditEntries = $xml.PolicyRules.AuditSubcategory
    if ($auditEntries) {
        foreach ($entry in $auditEntries) {
            $settingValue = [int]$entry.Setting
            $auditFlags = switch ($settingValue) {
                0 { 'None' }
                1 { 'Success' }
                2 { 'Failure' }
                3 { 'SuccessAndFailure' }
                default { "Unknown_$settingValue" }
            }

            $id = New-SettingId -SettingType 'AuditPolicy' -Identifier $entry.Name

            $setting = [PSCustomObject]@{
                PSTypeName    = 'BaselineForge.Setting'
                Id            = $id
                Source        = 'PolicyRules'
                SourceGPO     = $entry.PolicyName
                SettingType   = 'AuditPolicy'
                RegistryHive  = ''
                RegistryKey   = ''
                ValueName     = $entry.Name
                DataType      = 'AUDIT_FLAGS'
                ExpectedValue = $settingValue
                Category      = ''
                Severity      = ''
                PolicyName    = $entry.PolicyName
                Description   = "Expected: $auditFlags (GUID: $($entry.GUID))"
            }
            $settings.Add($setting)
        }
    }

    return $settings.ToArray()
}
