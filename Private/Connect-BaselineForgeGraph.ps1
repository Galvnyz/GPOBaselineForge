function Connect-BaselineForgeGraph {
    <#
    .SYNOPSIS
        Ensures a Microsoft Graph connection with required scopes.
    .DESCRIPTION
        Verifies an existing Graph connection has the required scope for Intune
        compliance operations. If not connected, initiates an interactive login.
    #>
    [CmdletBinding()]
    param()

    $requiredScope = 'DeviceManagementConfiguration.ReadWrite.All'

    # Check if Microsoft.Graph.Authentication is available
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        Write-Error 'Microsoft.Graph.Authentication module is required. Install with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        return $false
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $context = Get-MgContext
    if (-not $context) {
        Write-Verbose 'No active Graph session. Connecting...'
        Connect-MgGraph -Scopes $requiredScope -ErrorAction Stop
        $context = Get-MgContext
    }

    if ($requiredScope -notin $context.Scopes) {
        Write-Warning "Current Graph session missing scope '$requiredScope'. Reconnecting..."
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Connect-MgGraph -Scopes $requiredScope -ErrorAction Stop
        $context = Get-MgContext
    }

    Write-Verbose "Connected to Graph as $($context.Account) with TenantId $($context.TenantId)"
    return $true
}
