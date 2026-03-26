function New-SettingId {
    <#
    .SYNOPSIS
        Generates a deterministic, stable ID for a baseline setting.
    .DESCRIPTION
        Produces IDs like REG-Lsa-RunAsPPL, AUD-CredentialValidation,
        PRV-SeDebugPrivilege, ACC-MinimumPasswordLength, SVC-XboxGipSvc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Registry', 'AuditPolicy', 'PrivilegeRight', 'SystemAccess', 'ServiceConfig')]
        [string]$SettingType,

        [Parameter(Mandatory)]
        [string]$Identifier
    )

    $prefixMap = @{
        'Registry'       = 'REG'
        'AuditPolicy'    = 'AUD'
        'PrivilegeRight' = 'PRV'
        'SystemAccess'   = 'ACC'
        'ServiceConfig'  = 'SVC'
    }

    $prefix = $prefixMap[$SettingType]

    switch ($SettingType) {
        'Registry' {
            # Identifier is "Key\ValueName" — take last 3 path segments for uniqueness
            # (2 segments collides on Zones\0 vs Lockdown_Zones\0, Tcpip\Parameters vs Tcpip6\Parameters)
            $parts = $Identifier -split '\\'
            if ($parts.Count -ge 4) {
                $slug = "$($parts[-3])-$($parts[-2])-$($parts[-1])"
            }
            elseif ($parts.Count -ge 3) {
                $slug = "$($parts[-3])-$($parts[-2])-$($parts[-1])"
            }
            elseif ($parts.Count -eq 2) {
                $slug = "$($parts[-2])-$($parts[-1])"
            }
            else {
                $slug = $parts[-1]
            }
        }
        'AuditPolicy' {
            # Identifier is subcategory name — slugify
            $slug = ($Identifier -replace '\s+', '' -replace '[^A-Za-z0-9]', '')
        }
        'PrivilegeRight' {
            # Identifier is the privilege constant name
            $slug = $Identifier
        }
        'SystemAccess' {
            # Identifier is the policy key name
            $slug = $Identifier
        }
        'ServiceConfig' {
            # Identifier is the service name
            $slug = $Identifier
        }
    }

    return "$prefix-$slug"
}
