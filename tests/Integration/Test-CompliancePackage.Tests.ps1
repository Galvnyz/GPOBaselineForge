Describe 'Test-CompliancePackage Integration' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' '..' 'GPOBaselineForge.psd1'
        Import-Module $modulePath -Force

        $baselinePath = 'C:/git/SecFrame/Microsoft/Windows 11 v25H2 Security Baseline'
        $skipReason = if (-not (Test-Path $baselinePath)) { 'Baseline not available at expected path' } else { $null }

        $outputPath = Join-Path $PSScriptRoot '..' '..' 'tests' '_testoutput'
    }

    Context 'TypeCheck mode' {
        It 'Returns results for every rule in the package' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'TypeCheckTest' -IncludeCategory 'Local Security Authority'

            $results = $pkg | Test-CompliancePackage -Mode TypeCheck

            $results.Count | Should -Be $pkg.TotalSettings
        }

        It 'Produces zero TypeError results for generated packages' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'TypeCheckTest2' -IncludeCategory 'Local Security Authority'

            $results = $pkg | Test-CompliancePackage -Mode TypeCheck

            $typeErrors = $results | Where-Object Status -eq 'TypeError'
            $typeErrors | Should -BeNullOrEmpty
        }

        It 'Returns objects with expected properties' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'TypeCheckTest3' -IncludeCategory 'Local Security Authority'

            $results = $pkg | Test-CompliancePackage -Mode TypeCheck
            $first = $results | Select-Object -First 1

            $first.PSObject.Properties.Name | Should -Contain 'SettingName'
            $first.PSObject.Properties.Name | Should -Contain 'Status'
            $first.PSObject.Properties.Name | Should -Contain 'ActualValue'
            $first.PSObject.Properties.Name | Should -Contain 'ExpectedValue'
            $first.PSObject.Properties.Name | Should -Contain 'DataType'
            $first.PSObject.Properties.Name | Should -Contain 'Operator'
        }
    }

    Context 'FullEval mode' {
        It 'Returns Compliant, NotCompliant, or TypeError for each setting' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'FullEvalTest' -IncludeCategory 'Local Security Authority'

            $results = $pkg | Test-CompliancePackage -Mode FullEval

            $results.Count | Should -Be $pkg.TotalSettings
            $validStatuses = @('Compliant', 'NotCompliant', 'TypeError')
            $results | ForEach-Object {
                $_.Status | Should -BeIn $validStatuses
            }
        }

        It 'Accepts explicit paths instead of pipeline' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'ExplicitPathTest' -IncludeCategory 'Local Security Authority'

            $results = Test-CompliancePackage -DetectionScriptPath $pkg.DetectionScriptPath -RulesJsonPath $pkg.RulesJsonPath -Mode FullEval

            $results.Count | Should -Be $pkg.TotalSettings
        }
    }

    AfterAll {
        $testOutput = Join-Path $PSScriptRoot '..' '..' 'tests' '_testoutput'
        if (Test-Path $testOutput) {
            Remove-Item -Path $testOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Module 'GPOBaselineForge' -ErrorAction SilentlyContinue
    }
}
