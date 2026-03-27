# Test-CompliancePackage Design Spec

## Problem

Intune custom compliance policies are slow to report (hours). When a compliance package has bugs — like datatype mismatches between the detection script output and rules JSON — the feedback loop is painfully long. We need a local validator that catches these issues before uploading to Intune.

## Solution

A `Test-CompliancePackage` public cmdlet that runs the detection script locally, parses the rules JSON, and validates each setting — reporting the same states Intune would (Compliant, NotCompliant, TypeError) without the deployment delay.

## Parameters

| Parameter | Type | Source | Required |
|-----------|------|--------|----------|
| `DetectionScriptPath` | `string` | Explicit or from pipeline object `.DetectionScriptPath` | Yes (either explicit or pipeline) |
| `RulesJsonPath` | `string` | Explicit or from pipeline object `.RulesJsonPath` | Yes (either explicit or pipeline) |
| `Mode` | `string` (ValidateSet) | `TypeCheck` (default), `FullEval` | No |

Pipeline input: Accepts the `CompliancePackage` object returned by `New-CompliancePackage` (has `DetectionScriptPath` and `RulesJsonPath` properties).

## Modes

### TypeCheck (default)

Validates that each value in the detection script output can be cast to the DataType declared in the corresponding rule. This catches Intune error 65010 (invalid datatype).

- For `Int64` rules: checks that the value is numeric (castable to `[long]`)
- For `String` rules: always passes (everything is representable as a string)
- Returns `Pass` or `TypeError` per setting

### FullEval

Performs TypeCheck first, then evaluates the operator comparison against the operand — simulating what Intune does.

- `IsEquals`: `actualValue -eq operand`
- `GreaterEquals`: `actualValue -ge operand`
- Returns `Compliant`, `NotCompliant`, or `TypeError` per setting

## Output

One PSCustomObject per setting:

```
SettingName   : REG-Control-Lsa-RunAsPPL
Status        : NotCompliant
ActualValue   : -1
ExpectedValue : 1
DataType      : Int64
Operator      : IsEquals
```

### Status values by mode

| Mode | Possible Status values |
|------|----------------------|
| TypeCheck | `Pass`, `TypeError` |
| FullEval | `Compliant`, `NotCompliant`, `TypeError` |

## Execution Flow

1. Validate that both files exist
2. Execute the detection script via `& $DetectionScriptPath` in a script block, capture output
3. Parse stdout as JSON into a hashtable
4. Parse the rules JSON file
5. For each rule:
   a. Look up `SettingName` in the detection output
   b. If missing from output: `TypeError` (setting not reported by detection script)
   c. Attempt to cast the value to the rule's `DataType`
   d. If cast fails: `TypeError`
   e. If Mode is `TypeCheck`: `Pass`
   f. If Mode is `FullEval`: evaluate `Operator` against `Operand`, return `Compliant` or `NotCompliant`

## File Location

`Public/Test-CompliancePackage.ps1` — exported cmdlet, added to module manifest.

## Usage Examples

```powershell
# Pipeline from New-CompliancePackage
$pkg | Test-CompliancePackage

# Full evaluation with filtering
$pkg | Test-CompliancePackage -Mode FullEval | Where-Object Status -ne 'Compliant'

# Standalone with explicit paths
Test-CompliancePackage -DetectionScriptPath './output/deploy/Detection.ps1' `
                       -RulesJsonPath './output/deploy/Rules.json' -Mode FullEval

# Quick type-safety check (default mode)
Test-CompliancePackage -DetectionScriptPath './output/deploy/Detection.ps1' `
                       -RulesJsonPath './output/deploy/Rules.json'
```

## Testing

Pester integration test that:
1. Generates a compliance package from the real baseline
2. Runs `Test-CompliancePackage -Mode TypeCheck` — asserts zero `TypeError` results
3. Runs `Test-CompliancePackage -Mode FullEval` — asserts output contains expected status values and all properties are present
