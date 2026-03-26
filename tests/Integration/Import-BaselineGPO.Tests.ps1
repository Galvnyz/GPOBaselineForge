Describe 'Import-BaselineGPO Integration' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' '..' 'GPOBaselineForge.psd1'
        Import-Module $modulePath -Force

        $baselinePath = 'C:/git/SecFrame/Microsoft/Windows 11 v25H2 Security Baseline'
        $skipReason = if (-not (Test-Path $baselinePath)) { 'Baseline not available at expected path' } else { $null }
    }

    It 'Parses the W11 25H2 baseline with expected setting count' -Skip:($null -ne $skipReason) {
        $settings = Import-BaselineGPO -Path $baselinePath
        $settings.Count | Should -BeGreaterThan 350
        $settings.Count | Should -BeLessThan 500
    }

    It 'Produces no duplicate IDs' -Skip:($null -ne $skipReason) {
        $settings = Import-BaselineGPO -Path $baselinePath
        $ids = $settings | Select-Object -ExpandProperty Id
        $ids.Count | Should -Be ($ids | Sort-Object -Unique).Count
    }

    It 'Contains expected setting types' -Skip:($null -ne $skipReason) {
        $settings = Import-BaselineGPO -Path $baselinePath
        $types = $settings | Select-Object -ExpandProperty SettingType -Unique
        $types | Should -Contain 'Registry'
        $types | Should -Contain 'AuditPolicy'
        $types | Should -Contain 'PrivilegeRight'
        $types | Should -Contain 'SystemAccess'
        $types | Should -Contain 'ServiceConfig'
    }

    It 'Contains known critical settings' -Skip:($null -ne $skipReason) {
        $settings = Import-BaselineGPO -Path $baselinePath
        $ids = $settings | Select-Object -ExpandProperty Id
        $ids | Should -Contain 'REG-Control-Lsa-RunAsPPL'
        $ids | Should -Contain 'AUD-AuditCredentialValidation'
        $ids | Should -Contain 'PRV-SeSecurityPrivilege'
    }

    It 'Filters by ExcludeGPO' -Skip:($null -ne $skipReason) {
        $all = Import-BaselineGPO -Path $baselinePath
        $filtered = Import-BaselineGPO -Path $baselinePath -ExcludeGPO '*Internet Explorer*'
        $filtered.Count | Should -BeLessThan $all.Count
        $filtered | Where-Object { $_.SourceGPO -like '*Internet Explorer*' } | Should -BeNullOrEmpty
    }

    AfterAll {
        Remove-Module 'GPOBaselineForge' -ErrorAction SilentlyContinue
    }
}
