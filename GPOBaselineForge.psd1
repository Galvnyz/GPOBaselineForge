@{
    RootModule        = 'GPOBaselineForge.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '8dfc6ac4-d8da-46e9-9637-25eef5420af1'
    Author            = 'Galvnyz'
    CompanyName       = 'Galvnyz'
    Copyright         = '(c) 2026 Galvnyz. All rights reserved.'
    Description       = 'Parse Microsoft security baselines and generate Intune custom compliance packages'
    PowerShellVersion = '7.0'

    FunctionsToExport = @(
        'Import-BaselineGPO'
        'Set-BaselineSeverity'
        'New-CompliancePackage'
        'Publish-CompliancePolicy'
        'Invoke-BaselineForge'
        'Get-BaselineInventory'
        'Test-CompliancePackage'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('gpobaselineforge', 'security', 'compliance')
            ProjectUri = 'https://github.com/Galvnyz/GPOBaselineForge'
        }
    }
}
