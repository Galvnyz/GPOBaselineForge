function New-ComplianceRulesJson {
    <#
    .SYNOPSIS
        Generates an Intune custom compliance rules JSON file.
    .DESCRIPTION
        Creates the JSON rules file that Intune uses to evaluate detection script
        output. Each rule maps a SettingName to an expected value and operator.
    .PARAMETER Setting
        Array of classified BaselineForge.Setting objects.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Setting
    )

    $rules = foreach ($s in $Setting) {
        $operator = 'IsEquals'
        $dataType = 'String'
        $operand = [string]$s.ExpectedValue

        switch ($s.SettingType) {
            'Registry' {
                switch ($s.DataType) {
                    'REG_DWORD' {
                        $dataType = 'Int64'
                        $operand = [string][int]$s.ExpectedValue
                    }
                    'REG_QWORD' {
                        $dataType = 'Int64'
                        $operand = [string][long]$s.ExpectedValue
                    }
                    'REG_SZ' {
                        $dataType = 'String'
                        $operand = [string]$s.ExpectedValue
                    }
                    'REG_EXPAND_SZ' {
                        $dataType = 'String'
                        $operand = [string]$s.ExpectedValue
                    }
                    default {
                        $dataType = 'String'
                        $operand = [string]$s.ExpectedValue
                    }
                }
            }
            'AuditPolicy' {
                $dataType = 'Int64'
                $operand = [string][int]$s.ExpectedValue
                # Audit: require at least the expected flags (GreaterEquals allows SuccessAndFailure to satisfy Success)
                $operator = 'GreaterEquals'
            }
            'PrivilegeRight' {
                $dataType = 'String'
                $operand = [string]$s.ExpectedValue
            }
            'SystemAccess' {
                if ($s.ExpectedValue -is [int] -or $s.ExpectedValue -match '^\d+$') {
                    $dataType = 'Int64'
                    $operand = [string][int]$s.ExpectedValue
                }
                else {
                    $dataType = 'String'
                    $operand = [string]$s.ExpectedValue
                }
            }
            'ServiceConfig' {
                $dataType = 'Int64'
                $operand = [string][int]$s.ExpectedValue
            }
        }

        # Build remediation description
        $description = switch ($s.SettingType) {
            'Registry' { "Registry: $($s.RegistryKey)\$($s.ValueName) must be $($s.ExpectedValue). Severity: $($s.Severity). Category: $($s.Category)." }
            'AuditPolicy' { "Audit policy '$($s.ValueName)' must be enabled. $($s.Description). Severity: $($s.Severity)." }
            'PrivilegeRight' { "Privilege '$($s.ValueName)' must be assigned to: $($s.ExpectedValue). Severity: $($s.Severity)." }
            'SystemAccess' { "Security policy '$($s.ValueName)' must be $($s.ExpectedValue). Severity: $($s.Severity)." }
            'ServiceConfig' { "Service '$($s.ValueName)' startup type must be $($s.ExpectedValue). Severity: $($s.Severity)." }
        }

        # Build readable title
        $title = switch ($s.SettingType) {
            'Registry' { "$($s.ValueName) ($($s.Category))" }
            'AuditPolicy' { $s.ValueName }
            'PrivilegeRight' { $s.ValueName }
            'SystemAccess' { $s.ValueName }
            'ServiceConfig' { "Service: $($s.ValueName)" }
        }

        [ordered]@{
            SettingName        = $s.Id
            Operator           = $operator
            DataType           = $dataType
            Operand            = $operand
            MoreInfoUrl        = 'https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines'
            RemediationStrings = @(
                [ordered]@{
                    Language    = 'en_US'
                    Title       = $title
                    Description = $description
                }
            )
        }
    }

    $rulesDocument = [ordered]@{
        Rules = @($rules)
    }

    return ($rulesDocument | ConvertTo-Json -Depth 5)
}
