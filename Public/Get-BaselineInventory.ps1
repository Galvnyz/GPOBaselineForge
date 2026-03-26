function Get-BaselineInventory {
    <#
    .SYNOPSIS
        Displays a summary report of parsed and classified baseline settings.
    .DESCRIPTION
        Groups and formats baseline settings by SettingType, Severity, Category,
        or SourceGPO. Useful for inspecting what's in a baseline before generating
        compliance packages.
    .PARAMETER Setting
        Array of BaselineForge.Setting objects.
    .PARAMETER GroupBy
        Property to group the summary by. Default: Severity.
    .PARAMETER Format
        Output format. Default: Table.
    .PARAMETER Detail
        Show individual settings instead of just counts.
    .EXAMPLE
        Import-BaselineGPO -Path '.\baseline' | Set-BaselineSeverity | Get-BaselineInventory
    .EXAMPLE
        $settings | Get-BaselineInventory -GroupBy Category -Detail
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Setting,

        [Parameter()]
        [ValidateSet('Severity', 'Category', 'SettingType', 'SourceGPO')]
        [string]$GroupBy = 'Severity',

        [Parameter()]
        [ValidateSet('Table', 'List', 'Csv', 'Markdown')]
        [string]$Format = 'Table',

        [Parameter()]
        [switch]$Detail
    )

    begin {
        $allSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        foreach ($s in $Setting) {
            $allSettings.Add($s)
        }
    }

    end {
        if ($Detail) {
            $output = $allSettings | Sort-Object $GroupBy, Id |
                Select-Object Id, SettingType, Severity, Category, ValueName, ExpectedValue
        }
        else {
            $output = $allSettings | Group-Object $GroupBy | Sort-Object Count -Descending |
                Select-Object @{N='Group';E={$_.Name}}, Count,
                    @{N='Types';E={($_.Group | Group-Object SettingType | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ' '}}
        }

        switch ($Format) {
            'Table'    { $output | Format-Table -AutoSize }
            'List'     { $output | Format-List }
            'Csv'      { $output | ConvertTo-Csv -NoTypeInformation }
            'Markdown' {
                if ($Detail) {
                    '| Id | Type | Severity | Category | Setting | Expected |'
                    '|---|---|---|---|---|---|'
                    foreach ($row in $output) {
                        "| $($row.Id) | $($row.SettingType) | $($row.Severity) | $($row.Category) | $($row.ValueName) | $($row.ExpectedValue) |"
                    }
                }
                else {
                    "| $GroupBy | Count | Types |"
                    '|---|---|---|'
                    foreach ($row in $output) {
                        "| $($row.Group) | $($row.Count) | $($row.Types) |"
                    }
                }
            }
        }
    }
}
