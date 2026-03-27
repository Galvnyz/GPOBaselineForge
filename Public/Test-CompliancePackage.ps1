function Test-CompliancePackage {
    <#
    .SYNOPSIS
        Validates a compliance package by running the detection script locally.
    .DESCRIPTION
        Runs the detection script, parses the output, and validates each setting
        against the rules JSON. Supports TypeCheck (datatype validation only) and
        FullEval (full operator/operand comparison) modes.

        This is a local development/testing tool. The detection script is executed
        directly — only run scripts you trust.
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
        if (-not $scriptOutput) {
            throw "Detection script produced no output. Ensure the script at '$DetectionScriptPath' runs correctly."
        }
        try {
            $detectionResults = $scriptOutput | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        }
        catch {
            throw "Detection script output is not valid JSON: $_"
        }

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
                default {
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
                default  { [string]$operand }
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
