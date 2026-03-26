Describe 'New-CompliancePackage Integration' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' '..' 'GPOBaselineForge.psd1'
        Import-Module $modulePath -Force

        $baselinePath = 'C:/git/SecFrame/Microsoft/Windows 11 v25H2 Security Baseline'
        $skipReason = if (-not (Test-Path $baselinePath)) { 'Baseline not available at expected path' } else { $null }

        $outputPath = Join-Path $PSScriptRoot '..' '..' 'tests' '_testoutput'
    }

    It 'Generates valid compliance package from full pipeline' -Skip:($null -ne $skipReason) {
        $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
        $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'IntegrationTest' -MinSeverity High

        $pkg.TotalSettings | Should -BeGreaterThan 100
        $pkg.ScriptValid | Should -BeTrue
        $pkg.DetectionScriptPath | Should -Exist
        $pkg.RulesJsonPath | Should -Exist
    }

    It 'Detection script is valid PowerShell' -Skip:($null -ne $skipReason) {
        $scriptPath = Join-Path $outputPath 'IntegrationTest-Detection.ps1'
        if (Test-Path $scriptPath) {
            $content = Get-Content -Path $scriptPath -Raw
            { [scriptblock]::Create($content) } | Should -Not -Throw
        }
    }

    It 'Rules JSON is valid JSON with expected structure' -Skip:($null -ne $skipReason) {
        $rulesPath = Join-Path $outputPath 'IntegrationTest-Rules.json'
        if (Test-Path $rulesPath) {
            $content = Get-Content -Path $rulesPath -Raw
            $parsed = $content | ConvertFrom-Json
            $parsed.Rules | Should -Not -BeNullOrEmpty
            $parsed.Rules[0].SettingName | Should -Not -BeNullOrEmpty
            $parsed.Rules[0].Operator | Should -Not -BeNullOrEmpty
            $parsed.Rules[0].DataType | Should -Not -BeNullOrEmpty
        }
    }

    It 'Detection script size is under 100KB Intune limit' -Skip:($null -ne $skipReason) {
        $scriptPath = Join-Path $outputPath 'IntegrationTest-Detection.ps1'
        if (Test-Path $scriptPath) {
            (Get-Item $scriptPath).Length | Should -BeLessThan 102400
        }
    }

    It 'Category filter produces smaller package' -Skip:($null -ne $skipReason) {
        $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
        $full = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'FullTest'
        $credOnly = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'CredTest' -IncludeCategory 'Credential Protection'

        $credOnly.TotalSettings | Should -BeLessThan $full.TotalSettings
    }

    AfterAll {
        # Clean up test output
        $testOutput = Join-Path $PSScriptRoot '..' '..' 'tests' '_testoutput'
        if (Test-Path $testOutput) {
            Remove-Item -Path $testOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Module 'GPOBaselineForge' -ErrorAction SilentlyContinue
    }
}
