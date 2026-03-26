function Read-ManifestXml {
    <#
    .SYNOPSIS
        Parses a GPO backup manifest.xml to extract GPO name-to-GUID mappings.
    .DESCRIPTION
        Returns a hashtable mapping backup instance GUIDs to GPO display names.
    .PARAMETER Path
        Path to the GPOs/manifest.xml file.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    [xml]$xml = Get-Content -Path $Path -Raw
    $ns = @{ mfst = 'http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest' }

    $map = @{}
    foreach ($inst in $xml.Backups.BackupInst) {
        $backupId = $inst.ID.'#cdata-section'
        $displayName = $inst.GPODisplayName.'#cdata-section'
        if ($backupId -and $displayName) {
            $map[$backupId] = $displayName
        }
    }

    return $map
}
