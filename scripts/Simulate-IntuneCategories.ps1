<#
.SYNOPSIS
    Simulates remapping settings to Intune portal categories for validation.
.DESCRIPTION
    Maps all baseline settings to their proposed Intune portal category and
    outputs a report for user review before modifying the actual category-map.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$BaselinePath = 'C:/git/SecFrame/Microsoft/Windows 11 v25H2 Security Baseline'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'GPOBaselineForge.psd1') -Force

$settings = Import-BaselineGPO -Path $BaselinePath | Set-BaselineSeverity

# --- Mapping function ---
# Priority: specific value-level overrides first, then path-based, then type-based defaults
function Get-IntuneCategory {
    param($Setting)

    $key = $Setting.RegistryKey
    $val = $Setting.ValueName
    $type = $Setting.SettingType

    # Non-registry types
    switch ($type) {
        'AuditPolicy'    { return 'Auditing' }
        'PrivilegeRight' { return 'User Rights' }
        'SystemAccess'   { return 'Device Lock' }
        'ServiceConfig'  { return 'System Services' }
    }

    # --- Value-level overrides (settings where path alone is ambiguous) ---

    # MS Security Guide: specific settings from Microsoft's custom ADMX
    # These appear under Admin Templates > MS Security Guide in the portal
    if ($key -match 'MrxSmb10')                                          { return 'Administrative Templates - MS Security Guide' }
    if ($key -match 'Session Manager\\kernel' -and $val -match 'DisableExceptionChainValidation') { return 'Administrative Templates - MS Security Guide' }
    if ($key -match 'Session Manager$' -and $val -match 'SafeDllSearchMode') { return 'Administrative Templates - MS Security Guide' }
    if ($key -match 'Control\\Lsa$' -and $val -match 'WDigest')         { return 'Administrative Templates - MS Security Guide' } # WDigest isn't a real value name, but just in case
    # SMB1 server setting under LanmanServer\Parameters
    if ($key -match 'Services\\LanmanServer\\Parameters' -and $val -match 'SMB1') { return 'Administrative Templates - MS Security Guide' }

    # MSS (Legacy): TCP/IP stack, NetBIOS parameters
    if ($key -match 'Services\\Tcpip\\Parameters')                      { return 'Administrative Templates - MSS (Legacy)' }
    if ($key -match 'Services\\Tcpip6\\Parameters')                     { return 'Administrative Templates - MSS (Legacy)' }
    if ($key -match 'Services\\Netbt\\Parameters')                      { return 'Administrative Templates - MSS (Legacy)' }

    # --- Top-level sections (dedicated portal accordions) ---

    if ($key -match 'DeviceGuard')                                      { return 'Device Guard' }
    if ($key -match 'Kernel DMA Protection')                            { return 'Dma Guard' }
    if ($key -match 'Control\\Lsa')                                     { return 'Local Security Authority' }
    if ($key -match 'Services\\Netlogon')                               { return 'Local Security Authority' }
    if ($key -match 'Services\\LDAP')                                   { return 'Local Security Authority' }
    if ($key -match 'WindowsFirewall')                                  { return 'Firewall' }
    if ($key -match 'LanmanWorkstation')                                { return 'Lanman Workstation' }
    if ($key -match 'Bowser')                                           { return 'Lanman Workstation' }
    if ($key -match 'Policies\\Microsoft\\Windows\\LanmanServer')       { return 'Lanman Server' }
    if ($key -match 'Services\\LanmanServer')                           { return 'Lanman Server' }
    if ($key -match 'Kerberos')                                         { return 'Kerberos' }
    if ($key -match 'KDC')                                              { return 'Kerberos' }
    if ($key -match 'Policies\\LAPS')                                   { return 'LAPS' }
    if ($key -match 'Sudo')                                             { return 'Sudo' }
    if ($key -match 'Windows Defender')                                 { return 'Defender' }
    if ($key -match 'EarlyLaunch')                                      { return 'Defender' }
    if ($key -match 'WTDS')                                             { return 'Smart Screen' }
    if ($key -match 'Internet Explorer')                                { return 'Browser' }
    if ($key -match 'Internet Settings')                                { return 'Browser' }
    if ($key -match 'Policies\\Ext')                                    { return 'Browser' }
    if ($key -match 'WindowsInkWorkspace')                              { return 'Windows Ink Workspace' }
    if ($key -match 'Biometrics')                                       { return 'Windows Hello For Business' }
    if ($key -match 'WcmSvc|wifinetworkmanager')                        { return 'Wi-Fi Settings' }

    # Local Policies Security Options: UAC and interactive logon settings
    if ($key -match 'Policies\\System$' -or $key -match 'Policies\\System\\Audit') { return 'Local Policies Security Options' }
    if ($key -match 'Winlogon')                                         { return 'Local Policies Security Options' }

    # --- Administrative Templates sub-categories ---

    # Control Panel
    if ($key -match 'Personalization')                                  { return 'Administrative Templates - Control Panel' }

    # Network
    if ($key -match 'DNSClient')                                        { return 'Administrative Templates - Network' }
    if ($key -match 'Network Connections')                              { return 'Administrative Templates - Network' }
    if ($key -match 'NetworkProvider')                                  { return 'Administrative Templates - Network' }
    if ($key -match 'Windows NT\\Rpc')                                  { return 'Administrative Templates - Network' }

    # Windows Components sub-categories
    if ($key -match 'FVE')                                              { return 'Administrative Templates - BitLocker Drive Encryption' }
    if ($key -match 'CredUI|CredentialsDelegation|CredSSP')             { return 'Administrative Templates - Credential Delegation' }
    if ($key -match 'EventLog')                                         { return 'Administrative Templates - Event Log Service' }
    if ($key -match 'Explorer')                                         { return 'Administrative Templates - File Explorer' }
    if ($key -match 'Terminal Services')                                { return 'Administrative Templates - Remote Desktop Services' }
    if ($key -match 'Installer')                                        { return 'Administrative Templates - Windows Installer' }
    if ($key -match 'PowerShell')                                       { return 'Administrative Templates - Windows PowerShell' }
    if ($key -match 'WinRM')                                            { return 'Administrative Templates - Windows Remote Management' }
    if ($key -match 'AxInstaller')                                      { return 'Administrative Templates - Windows Installer' }
    if ($key -match 'Printers|\\Print')                                 { return 'Administrative Templates - Printers' }

    # System sub-categories
    if ($key -match 'DeviceInstall')                                    { return 'Administrative Templates - Device Installation' }
    if ($key -match 'Power\\')                                          { return 'Administrative Templates - Power' }
    if ($key -match 'Windows\\System')                                  { return 'Administrative Templates - System' }

    # Privacy/Experience
    if ($key -match 'CloudContent')                                     { return 'Administrative Templates - Experience' }
    if ($key -match 'GameDVR')                                          { return 'Administrative Templates - Experience' }
    if ($key -match 'Windows Search')                                   { return 'Administrative Templates - Search' }
    if ($key -match 'PushNotifications|DataCollection|AppPrivacy')      { return 'Administrative Templates - Privacy' }

    # Catch-all
    return 'Administrative Templates - Other'
}

# --- Map all settings ---
$mapped = foreach ($s in $settings) {
    [PSCustomObject]@{
        Id             = $s.Id
        OldCategory    = $s.Category
        NewCategory    = Get-IntuneCategory -Setting $s
        SettingType    = $s.SettingType
        ValueName      = $s.ValueName
        RegistryKey    = $s.RegistryKey
        Severity       = $s.Severity
    }
}

# --- Report ---
Write-Host "`n=== INTUNE PORTAL CATEGORY MAPPING REPORT ===" -ForegroundColor Cyan
Write-Host "Total settings: $($mapped.Count)`n"

$groups = $mapped | Group-Object NewCategory | Sort-Object @{Expression={
    # Sort top-level first, then Admin Templates
    if ($_.Name -like 'Administrative Templates*') { "ZZ_$($_.Name)" } else { "AA_$($_.Name)" }
}}

Write-Host ("  {0,-55} {1,5}" -f "CATEGORY", "COUNT")
Write-Host ("  {0,-55} {1,5}" -f ("-" * 55), "-----")
$topLevelTotal = 0
$adminTotal = 0
foreach ($g in $groups) {
    $prefix = if ($g.Name -like 'Administrative Templates*') { '    ' } else { '' }
    if ($g.Name -eq ($groups | Where-Object { $_.Name -like 'Administrative Templates*' } | Select-Object -First 1).Name -and $adminTotal -eq 0) {
        Write-Host "`n  Administrative Templates (sub-categories):" -ForegroundColor Yellow
    }
    if ($g.Name -notlike 'Administrative Templates*') { $topLevelTotal += $g.Count } else { $adminTotal += $g.Count }
    Write-Host ("  {0}{1,-55} {2,5}" -f $prefix, $g.Name, $g.Count)
}

Write-Host "`n  Top-level sections: $topLevelTotal settings across $(($groups | Where-Object { $_.Name -notlike 'Administrative Templates*' }).Count) packages"
Write-Host "  Admin Templates:    $adminTotal settings across $(($groups | Where-Object { $_.Name -like 'Administrative Templates*' }).Count) sub-packages"
Write-Host "  Total packages:     $(($groups).Count)"

# Show any that fell to "Other"
$other = $mapped | Where-Object NewCategory -eq 'Administrative Templates - Other'
if ($other.Count -gt 0) {
    Write-Host "`n=== UNMAPPED (Administrative Templates - Other) ===" -ForegroundColor Red
    foreach ($o in $other) {
        Write-Host "  $($o.Id): $($o.RegistryKey)\$($o.ValueName)"
    }
}

# Show detail per category
Write-Host "`n=== DETAILED BREAKDOWN ===" -ForegroundColor Yellow
foreach ($g in $groups) {
    Write-Host "`n  $($g.Name) ($($g.Count) settings):" -ForegroundColor Cyan
    foreach ($s in ($g.Group | Sort-Object Id)) {
        $display = if ($s.SettingType -eq 'Registry') {
            $shortKey = if ($s.RegistryKey.Length -gt 50) { "..." + $s.RegistryKey.Substring($s.RegistryKey.Length - 47) } else { $s.RegistryKey }
            "$shortKey\$($s.ValueName)"
        } else {
            "$($s.SettingType): $($s.ValueName)"
        }
        Write-Host ("    {0,-30} {1,-8} {2}" -f $s.Id.Substring(0, [Math]::Min(30, $s.Id.Length)), $s.Severity, $display)
    }
}
