@{
    Severity = @('Error', 'Warning')

    Rules = @{
        PSAvoidUsingCmdletAliases              = @{ Enable = $true }
        PSAvoidUsingPositionalParameters       = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments    = @{ Enable = $true }
        PSAvoidUsingInvokeExpression            = @{ Enable = $true }
        PSAvoidUsingPlainTextForPassword        = @{ Enable = $true }
        PSAvoidUsingConvertToSecureStringWithPlainText = @{ Enable = $true }
        PSUseProcessBlockForPipelineCommand     = @{ Enable = $true }
    }

    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
        'PSUseBOMForUnicodeEncodedFile'
        'PSReviewUnusedParameter'
        'PSUseSingularNouns'
    )
}
