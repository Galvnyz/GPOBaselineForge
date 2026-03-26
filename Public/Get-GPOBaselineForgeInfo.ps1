function Get-GPOBaselineForgeInfo {
    <#
    .SYNOPSIS
        Returns module information for GPOBaselineForge.
    .DESCRIPTION
        Provides version, author, and description metadata about the module.
        Use this as a starting point — replace with your actual public functions.
    .OUTPUTS
        PSCustomObject — module metadata.
    .EXAMPLE
        Get-GPOBaselineForgeInfo
    #>
    [CmdletBinding()]
    param()

    $manifest = Import-PowerShellDataFile -Path (Join-Path $script:ModuleRoot 'GPOBaselineForge.psd1')

    [PSCustomObject]@{
        Name        = 'GPOBaselineForge'
        Version     = $manifest.ModuleVersion
        Author      = $manifest.Author
        Description = $manifest.Description
    }
}
