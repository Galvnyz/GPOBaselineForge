# Test-CompliancePackage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `Test-CompliancePackage` cmdlet that runs detection scripts locally and validates output against rules JSON, simulating Intune compliance evaluation.

**Architecture:** Single public cmdlet in `Public/Test-CompliancePackage.ps1`, accepting pipeline input from `New-CompliancePackage` or explicit file paths. Two modes: TypeCheck (datatype validation) and FullEval (full rule evaluation). Returns PSCustomObjects per setting.

**Tech Stack:** PowerShell 7.0+, Pester 5.x

---

### Task 1: Write the Pester test file

**Files:**
- Create: `tests/Integration/Test-CompliancePackage.Tests.ps1`

- [ ] **Step 1: Create the test file with all test cases**

```powershell
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
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'TypeCheckTest' -IncludeCategory 'Credential Protection'

            $results = $pkg | Test-CompliancePackage -Mode TypeCheck

            $results.Count | Should -Be $pkg.TotalSettings
        }

        It 'Produces zero TypeError results for generated packages' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'TypeCheckTest2' -IncludeCategory 'Credential Protection'

            $results = $pkg | Test-CompliancePackage -Mode TypeCheck

            $typeErrors = $results | Where-Object Status -eq 'TypeError'
            $typeErrors | Should -BeNullOrEmpty
        }

        It 'Returns objects with expected properties' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'TypeCheckTest3' -IncludeCategory 'Credential Protection'

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
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'FullEvalTest' -IncludeCategory 'Credential Protection'

            $results = $pkg | Test-CompliancePackage -Mode FullEval

            $results.Count | Should -Be $pkg.TotalSettings
            $validStatuses = @('Compliant', 'NotCompliant', 'TypeError')
            $results | ForEach-Object {
                $_.Status | Should -BeIn $validStatuses
            }
        }

        It 'Accepts explicit paths instead of pipeline' -Skip:($null -ne $skipReason) {
            $settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
            $pkg = $settings | New-CompliancePackage -OutputPath $outputPath -Name 'ExplicitPathTest' -IncludeCategory 'Credential Protection'

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
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `pwsh -NoProfile -Command "Import-Module ./GPOBaselineForge.psd1 -Force; Invoke-Pester ./tests/Integration/Test-CompliancePackage.Tests.ps1 -Output Detailed"`

Expected: All tests FAIL because `Test-CompliancePackage` does not exist yet.

- [ ] **Step 3: Commit**

```bash
git add tests/Integration/Test-CompliancePackage.Tests.ps1
git commit -m "test: add failing tests for Test-CompliancePackage cmdlet"
```

---

### Task 2: Implement Test-CompliancePackage cmdlet

**Files:**
- Create: `Public/Test-CompliancePackage.ps1`

- [ ] **Step 1: Create the cmdlet file**

```powershell
function Test-CompliancePackage {
    <#
    .SYNOPSIS
        Validates a compliance package by running the detection script locally.
    .DESCRIPTION
        Runs the detection script, parses the output, and validates each setting
        against the rules JSON. Supports TypeCheck (datatype validation only) and
        FullEval (full operator/operand comparison) modes.
    .PARAMETER DetectionScriptPath
        Path to the detection script (.ps1).
    .PARAMETER RulesJsonPath
        Path to the compliance rules JSON file.
    .PARAMETER Mode
        TypeCheck validates datatypes only. FullEval also evaluates operator comparisons.
    .EXAMPLE
        $pkg | Test-CompliancePackage -Mode FullEval
    .EXAMPLE
        Test-CompliancePackage -DetectionScriptPath './Detection.ps1' -RulesJsonPath './Rules.json'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$DetectionScriptPath,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$RulesJsonPath,

        [Parameter()]
        [ValidateSet('TypeCheck', 'FullEval')]
        [string]$Mode = 'TypeCheck'
    )

    process {
        if (-not $DetectionScriptPath -or -not $RulesJsonPath) {
            throw 'Both DetectionScriptPath and RulesJsonPath are required. Provide them explicitly or pipe a CompliancePackage object.'
        }

        # Run the detection script and capture JSON output
        Write-Verbose "Running detection script: $DetectionScriptPath"
        $scriptOutput = & $DetectionScriptPath 2>$null
        $detectionResults = $scriptOutput | ConvertFrom-Json -AsHashtable

        # Parse the rules JSON
        $rulesDoc = Get-Content -Path $RulesJsonPath -Raw | ConvertFrom-Json

        foreach ($rule in $rulesDoc.Rules) {
            $settingName = $rule.SettingName
            $expectedDataType = $rule.DataType
            $operator = $rule.Operator
            $operand = $rule.Operand

            # Check if setting exists in detection output
            if (-not $detectionResults.ContainsKey($settingName)) {
                [PSCustomObject]@{
                    SettingName   = $settingName
                    Status        = 'TypeError'
                    ActualValue   = $null
                    ExpectedValue = $operand
                    DataType      = $expectedDataType
                    Operator      = $operator
                }
                continue
            }

            $actualValue = $detectionResults[$settingName]

            # Type validation
            $typePassed = $true
            switch ($expectedDataType) {
                'Int64' {
                    try {
                        $actualValue = [long]$actualValue
                    }
                    catch {
                        $typePassed = $false
                    }
                }
                'String' {
                    $actualValue = [string]$actualValue
                }
            }

            if (-not $typePassed) {
                [PSCustomObject]@{
                    SettingName   = $settingName
                    Status        = 'TypeError'
                    ActualValue   = $detectionResults[$settingName]
                    ExpectedValue = $operand
                    DataType      = $expectedDataType
                    Operator      = $operator
                }
                continue
            }

            # TypeCheck mode: type passed, we're done
            if ($Mode -eq 'TypeCheck') {
                [PSCustomObject]@{
                    SettingName   = $settingName
                    Status        = 'Pass'
                    ActualValue   = $actualValue
                    ExpectedValue = $operand
                    DataType      = $expectedDataType
                    Operator      = $operator
                }
                continue
            }

            # FullEval mode: evaluate operator comparison
            $castOperand = switch ($expectedDataType) {
                'Int64'  { [long]$operand }
                'String' { [string]$operand }
            }

            $compliant = switch ($operator) {
                'IsEquals'      { $actualValue -eq $castOperand }
                'GreaterEquals' { $actualValue -ge $castOperand }
                default         { $actualValue -eq $castOperand }
            }

            [PSCustomObject]@{
                SettingName   = $settingName
                Status        = if ($compliant) { 'Compliant' } else { 'NotCompliant' }
                ActualValue   = $actualValue
                ExpectedValue = $operand
                DataType      = $expectedDataType
                Operator      = $operator
            }
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `pwsh -NoProfile -Command "Import-Module ./GPOBaselineForge.psd1 -Force; Invoke-Pester ./tests/Integration/Test-CompliancePackage.Tests.ps1 -Output Detailed"`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add Public/Test-CompliancePackage.ps1
git commit -m "feat: add Test-CompliancePackage cmdlet with TypeCheck and FullEval modes"
```

---

### Task 3: Register in module manifest

**Files:**
- Modify: `GPOBaselineForge.psd1:11-18` (FunctionsToExport array)

- [ ] **Step 1: Add Test-CompliancePackage to FunctionsToExport**

In `GPOBaselineForge.psd1`, add `'Test-CompliancePackage'` to the `FunctionsToExport` array:

```powershell
    FunctionsToExport = @(
        'Import-BaselineGPO'
        'Set-BaselineSeverity'
        'New-CompliancePackage'
        'Publish-CompliancePolicy'
        'Invoke-BaselineForge'
        'Get-BaselineInventory'
        'Test-CompliancePackage'
    )
```

- [ ] **Step 2: Run full test suite to verify nothing broke**

Run: `pwsh -NoProfile -Command "Import-Module ./GPOBaselineForge.psd1 -Force; Invoke-Pester ./tests/ -Output Detailed"`

Expected: All tests PASS (original 18 + new tests).

- [ ] **Step 3: Commit**

```bash
git add GPOBaselineForge.psd1
git commit -m "chore: export Test-CompliancePackage in module manifest"
```

---

### Task 4: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md` (Public Cmdlets table)

- [ ] **Step 1: Add Test-CompliancePackage to the cmdlets table**

Add this row to the Public Cmdlets table in `CLAUDE.md`:

```
| `Test-CompliancePackage` | Local compliance package validator |
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add Test-CompliancePackage to public cmdlets table"
```

---

### Verification

After all tasks complete:

```powershell
Import-Module ./GPOBaselineForge.psd1 -Force

# Generate a package
$baselinePath = 'C:/git/SecFrame/Microsoft/Windows 11 v25H2 Security Baseline'
$settings = Import-BaselineGPO -Path $baselinePath | Set-BaselineSeverity
$pkg = $settings | New-CompliancePackage -OutputPath './output/deploy' -Name 'Win11-25H2-CredProtection' -IncludeCategory 'Credential Protection'

# TypeCheck — should show zero TypeError
$pkg | Test-CompliancePackage -Mode TypeCheck | Format-Table

# FullEval — should show Compliant/NotCompliant per setting
$pkg | Test-CompliancePackage -Mode FullEval | Format-Table

# Filter to just failures
$pkg | Test-CompliancePackage -Mode FullEval | Where-Object Status -ne 'Compliant' | Format-Table
```
