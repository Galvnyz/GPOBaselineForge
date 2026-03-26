Describe 'GPOBaselineForge Module' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' '..' 'GPOBaselineForge.psd1'
    }

    It 'Has a valid module manifest' {
        { Test-ModuleManifest -Path $modulePath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Imports without errors' {
        { Import-Module $modulePath -Force -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Exports Import-BaselineGPO' {
        Import-Module $modulePath -Force
        (Get-Module 'GPOBaselineForge').ExportedFunctions.Keys | Should -Contain 'Import-BaselineGPO'
    }

    It 'Exports Set-BaselineSeverity' {
        (Get-Module 'GPOBaselineForge').ExportedFunctions.Keys | Should -Contain 'Set-BaselineSeverity'
    }

    It 'Exports New-CompliancePackage' {
        (Get-Module 'GPOBaselineForge').ExportedFunctions.Keys | Should -Contain 'New-CompliancePackage'
    }

    It 'Exports Publish-CompliancePolicy' {
        (Get-Module 'GPOBaselineForge').ExportedFunctions.Keys | Should -Contain 'Publish-CompliancePolicy'
    }

    It 'Exports Invoke-BaselineForge' {
        (Get-Module 'GPOBaselineForge').ExportedFunctions.Keys | Should -Contain 'Invoke-BaselineForge'
    }

    It 'Exports Get-BaselineInventory' {
        (Get-Module 'GPOBaselineForge').ExportedFunctions.Keys | Should -Contain 'Get-BaselineInventory'
    }

    AfterAll {
        Remove-Module 'GPOBaselineForge' -ErrorAction SilentlyContinue
    }
}
