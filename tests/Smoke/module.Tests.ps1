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

    It 'Exports expected functions' {
        Import-Module $modulePath -Force
        $exportedFunctions = (Get-Module 'GPOBaselineForge').ExportedFunctions.Keys
        $exportedFunctions | Should -Contain 'Get-GPOBaselineForgeInfo'
    }

    AfterAll {
        Remove-Module 'GPOBaselineForge' -ErrorAction SilentlyContinue
    }
}
