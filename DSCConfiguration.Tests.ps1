<#
    PSSA = PS Script Analyzer
    Only the first and last tests here will pass/fail correctly at the moment. The other 3 tests
    will currently always pass, but print warnings based on the problems they find.
    These automatic passes are here to give contributors time to fix the PSSA
    problems before we turn on these tests. These 'automatic passes' should be removed
    along with the first test (which is replaced by the following 3) around Jan-Feb
    2017.
#>
Describe 'Common Tests - PS Script Analyzer' -Tag Lint {

    $requiredPssaRuleNames = @(
        'PSAvoidDefaultValueForMandatoryParameter',
        'PSAvoidDefaultValueSwitchParameter',
        'PSAvoidInvokingEmptyMembers',
        'PSAvoidNullOrEmptyHelpMessageAttribute',
        'PSAvoidUsingCmdletAliases',
        'PSAvoidUsingComputerNameHardcoded',
        'PSAvoidUsingDeprecatedManifestFields',
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidUsingInvokeExpression',
        'PSAvoidUsingPositionalParameters',
        'PSAvoidShouldContinueWithoutForce',
        'PSAvoidUsingWMICmdlet',
        'PSAvoidUsingWriteHost',
        'PSDSCReturnCorrectTypesForDSCFunctions',
        'PSDSCUseIdenticalMandatoryParametersForDSC',
        'PSDSCUseIdenticalParametersForDSC',
        'PSMissingModuleManifestField',
        'PSPossibleIncorrectComparisonWithNull',
        'PSProvideCommentHelp',
        'PSReservedCmdletChar',
        'PSReservedParams',
        'PSUseApprovedVerbs',
        'PSUseCmdletCorrectly',
        'PSUseOutputTypeCorrectly'
    )

    $flaggedPssaRuleNames = @(
        'PSAvoidGlobalVars',
        'PSAvoidUsingUsernameAndPasswordParams',
        'PSShouldProcess',
        'PSUseDeclaredVarsMoreThanAssigments',
        'PSUsePSCredentialType'
    )

    $ignorePssaRuleNames = @(
        # The following exclusions are required for build platform compatibility
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSDSCDscExamplesPresent',
        'PSDSCDscTestsPresent',
        'PSUseBOMForUnicodeEncodedFile',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns',
        'PSUseToExportFieldsInManifest',
        'PSUseUTF8EncodingForHelpFile'
    )

    $ScriptFiles = Get-ChildItem -Path $env:BuildFolder -Filter '*.ps1' -File

    foreach ($ScriptFile in $ScriptFiles)
    {
        $invokeScriptAnalyzerParameters = @{
            Path = $ScriptFile.FullName
            ErrorAction = 'SilentlyContinue'
            Recurse = $true
        }

        Context $ScriptFile.Name {
            It 'Should pass all error-level PS Script Analyzer rules' {
                $errorPssaRulesOutput = Invoke-ScriptAnalyzer @invokeScriptAnalyzerParameters -ExcludeRule $ignorePssaRuleNames -Severity 'Error'

                if ($null -ne $errorPssaRulesOutput) {
                    Write-Warning -Message 'Error-level PSSA rule(s) did not pass.'
                    Write-Warning -Message 'The following PSScriptAnalyzer errors need to be fixed:'

                    foreach ($errorPssaRuleOutput in $errorPssaRulesOutput)
                    {
                        Write-Warning -Message "$($errorPssaRuleOutput.ScriptName) (Line $($errorPssaRuleOutput.Line)): $($errorPssaRuleOutput.Message)"
                    }

                    Write-Warning -Message  'For instructions on how to run PSScriptAnalyzer on your own machine, please go to https://github.com/powershell/PSScriptAnalyzer'
                }

                $errorPssaRulesOutput | Should Be $null
            }

            It 'Should pass all required PS Script Analyzer rules' {
                $requiredPssaRulesOutput = Invoke-ScriptAnalyzer @invokeScriptAnalyzerParameters -IncludeRule $requiredPssaRuleNames

                if ($null -ne $requiredPssaRulesOutput) {
                    Write-Warning -Message 'Required PSSA rule(s) did not pass.'
                    Write-Warning -Message 'The following PSScriptAnalyzer errors need to be fixed:'

                    foreach ($requiredPssaRuleOutput in $requiredPssaRulesOutput)
                    {
                        Write-Warning -Message "$($requiredPssaRuleOutput.ScriptName) (Line $($requiredPssaRuleOutput.Line)): $($requiredPssaRuleOutput.Message)"
                    }

                    Write-Warning -Message  'For instructions on how to run PSScriptAnalyzer on your own machine, please go to https://github.com/powershell/PSScriptAnalyzer'
                }

                <#
                    Automatically passing this test since it may break several modules at the moment.
                    Automatic pass to be removed Jan-Feb 2017.
                #>
                $requiredPssaRulesOutput = $null
                $requiredPssaRulesOutput | Should Be $null
            }

            It 'Should pass all flagged PS Script Analyzer rules' {
                $flaggedPssaRulesOutput = Invoke-ScriptAnalyzer @invokeScriptAnalyzerParameters -IncludeRule $flaggedPssaRuleNames

                if ($null -ne $flaggedPssaRulesOutput) {
                    Write-Warning -Message 'Flagged PSSA rule(s) did not pass.'
                    Write-Warning -Message 'The following PSScriptAnalyzer errors need to be fixed or approved to be suppressed:'

                    foreach ($flaggedPssaRuleOutput in $flaggedPssaRulesOutput)
                    {
                        Write-Warning -Message "$($flaggedPssaRuleOutput.ScriptName) (Line $($flaggedPssaRuleOutput.Line)): $($flaggedPssaRuleOutput.Message)"
                    }

                    Write-Warning -Message  'For instructions on how to run PSScriptAnalyzer on your own machine, please go to https://github.com/powershell/PSScriptAnalyzer'
                }

                <#
                    Automatically passing this test since it may break several modules at the moment.
                    Automatic pass to be removed Jan-Feb 2017.
                #>
                $flaggedPssaRulesOutput = $null
                $flaggedPssaRulesOutput | Should Be $null
            }

            It 'Should not suppress any required PS Script Analyzer rules' {
                $requiredRuleIsSuppressed = $false

                $suppressedRuleNames = Get-SuppressedPSSARuleNameList -FilePath $ScriptFile.FullName

                foreach ($suppressedRuleName in $suppressedRuleNames)
                {
                    $suppressedRuleNameNoQuotes = $suppressedRuleName.Replace("'", '')

                    if ($requiredPssaRuleNames -icontains $suppressedRuleNameNoQuotes)
                    {
                        Write-Warning -Message "The file $($ScriptFile.Name) contains a suppression of the required PS Script Analyser rule $suppressedRuleNameNoQuotes. Please remove the rule suppression."
                        $requiredRuleIsSuppressed = $true
                    }
                }

                $requiredRuleIsSuppressed | Should Be $false
            }
        }
    }
}

<#
#>
Describe 'Common Tests - File Parsing' -Tag Lint {
    $ScriptFiles = Get-ChildItem -Path $env:BuildFolder -Filter '*.ps1' -File

    foreach ($ScriptFile in $ScriptFiles)
    {
        Context $ScriptFile.Name {   
            It 'Should not contain parse errors' {
                $containsParseErrors = $false

                $parseErrors = Get-FileParseErrors -FilePath $ScriptFile.FullName

                if ($null -ne $parseErrors)
                {
                    Write-Warning -Message "There are parse errors in $($ScriptFile.FullName):"
                    Write-Warning -Message ($parseErrors | Format-List | Out-String)

                    $containsParseErrors = $true
                }

                $containsParseErrors | Should Be $false
            }
        }
    }
}

<#
#>
Describe 'Common Tests - File Formatting' -Tag Lint {
    $textFiles = Get-TextFilesList -FilePath $env:BuildFolder
    
    Context 'All discovered ext files' {
        It "Should not contain any files with Unicode file encoding" {
            $containsUnicodeFile = $false

            foreach ($textFile in $textFiles)
            {
                if (Test-FileInUnicode $textFile) {
                    if($textFile.Extension -ieq '.mof')
                    {
                        Write-Warning -Message "File $($textFile.FullName) should be converted to ASCII. Use fixer function 'Get-UnicodeFilesList `$pwd | ConvertTo-ASCII'."
                    }
                    else
                    {
                        Write-Warning -Message "File $($textFile.FullName) should be converted to UTF-8. Use fixer function 'Get-UnicodeFilesList `$pwd | ConvertTo-UTF8'."
                    }

                    $containsUnicodeFile = $true
                }
            }

            $containsUnicodeFile | Should Be $false
        }

        It 'Should not contain any files with tab characters' {
            $containsFileWithTab = $false

            foreach ($textFile in $textFiles)
            {
                $fileName = $textFile.FullName
                $fileContent = Get-Content -Path $fileName -Raw

                $tabCharacterMatches = $fileContent | Select-String "`t"

                if ($null -ne $tabCharacterMatches)
                {
                    Write-Warning -Message "Found tab character(s) in $fileName. Use fixer function 'Get-TextFilesList `$pwd | ConvertTo-SpaceIndentation'."
                    $containsFileWithTab = $true
                }
            }

            $containsFileWithTab | Should Be $false
        }

        It 'Should not contain empty files' {
            $containsEmptyFile = $false

            foreach ($textFile in $textFiles)
            {
                $fileContent = Get-Content -Path $textFile.FullName -Raw

                if([String]::IsNullOrWhiteSpace($fileContent))
                {
                    Write-Warning -Message "File $($textFile.FullName) is empty. Please remove this file."
                    $containsEmptyFile = $true
                }
            }

            $containsEmptyFile | Should Be $false
        }

        It 'Should not contain files without a newline at the end' {
            $containsFileWithoutNewLine = $false

            foreach ($textFile in $textFiles)
            {
                $fileContent = Get-Content -Path $textFile.FullName -Raw

                if(-not [String]::IsNullOrWhiteSpace($fileContent) -and $fileContent[-1] -ne "`n")
                {
                    if (-not $containsFileWithoutNewLine)
                    {
                        Write-Warning -Message 'Each file must end with a new line.'
                    }

                    Write-Warning -Message "$($textFile.FullName) does not end with a new line. Use fixer function 'Add-NewLine'"
                    
                    $containsFileWithoutNewLine = $true
                }
            }

                    
            $containsFileWithoutNewLine | Should Be $false
        }
    }
}

<#
#>
Describe 'Common Tests - Configuration Module Requirements' -Tag Unit {
    $Files = Get-ChildItem -Path $env:BuildFolder
    $ScriptFileInfo = Test-ScriptFileInfo -Path "$env:BuildFolder\$env:ProjectName.ps1"

    Context "$env:ProjectName scriptfileinfo properties" {
        It 'Contains a script file that aligns to the project name' {
            $Files.Name.Contains("$env:ProjectName.ps1") | Should Be True
        }
        It 'Contains a readme' {
            $Files.Name.Contains("README.md") | Should Be True
        }
        It 'Should have a GUID in the scriptfileinfo' {
            $ScriptFileInfo.GUID | Should Match '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
        }
        It 'Should list requirements in the scriptfileinfo' {
            $ScriptFileInfo.RequiredModules | Should Not Be Null
        }
        It 'Should list a version in the scriptfileinfo' {
            $ScriptFileInfo.Version | Should BeGreaterThan 0.0.0
        }
        It 'Should list an author in the scriptfileinfo' {
            $ScriptFileInfo.Author | Should Not Be Null
        }
        It 'Should provide a description in the scriptfileinfo' {
            $ScriptFileInfo.Description | Should Not Be Null
        }
        It 'Should include tags in the scriptfileinfo' {
            $ScriptFileInfo.Tags | Should Not Be Null
        }
        It 'Should include a project URI in the scriptfileinfo' {
            $ScriptFileInfo.ProjectURI | Should Not Be Null
        }
        It 'Should include a license URI in the scriptfileinfo' {
            $ScriptFileInfo.LicenseURI | Should Not Be Null
        }
        It 'Should include release notes in the scriptfileinfo' {
            $ScriptFileInfo.ReleaseNotes | Should Not Be Null
        }
    }
    <#
    Context "$env:ProjectName required modules" {
        ForEach ($RequiredModule in $ScriptFileInfo.RequiredModules.split(',')) {
            if ($RequiredModule.GetType().Name -eq 'Hashtable') {
                It "$($RequiredModule.ModuleName) version $($RequiredModule.ModuleVersion) should be found in the PowerShell public gallery" {
                    {Find-Module -Name $RequiredModule.ModuleName -RequiredVersion $RequiredModule.ModuleVersion} | Should Not Be Null
                }
                It "$($RequiredModule.ModuleName) version $($RequiredModule.ModuleVersion) should install locally without error" {
                    {Install-Module -Name $RequiredModule.ModuleName -RequiredVersion $RequiredModule.ModuleVersion -Force} | Should Not Throw
                } 
            }
            else {
                It "$RequiredModule should be found in the PowerShell public gallery" {
                    {Find-Module -Name $RequiredModule} | Should Not Be Null
                }
                It "$RequiredModule should install locally without error" {
                    {Install-Module -Name $RequiredModule -Force} | Should Not Throw
                }
            }
        }
    }
    #>
    Context "$env:ProjectName configuration script" {
        It "$env:BuildFolder\$env:ProjectName.ps1 should execute as a script without error" {
            {. $env:BuildFolder\$env:ProjectName.ps1} | Should Not Throw
        }
        It "$env:ProjectName should provide configurations" {
            # this could produce a false positive if the build machine has other known
            # configurations loaded, but scripts are not identified as source
            . $env:BuildFolder\$env:ProjectName.ps1
            $Configurations = Get-Command -Type Configuration | Where-Object {$_.Source -eq ''} | ForEach-Object {$_.Name}
            $Configurations.count | Should BeGreaterThan 0
        }
        if (!(Test-Path $env:TEMP\mof)) {
            New-Item -Path $env:TEMP\mof -ItemType Directory
        }
        ForEach ($Configuration in $Configurations) {
            It "$Configuration should compile without error" {
                {& $Configuration -Out $env:TEMP\mof\$Configuration} | Should Not Throw
            }
            It "$Configuration should produce a mof file" {
                if (Test-Path $env:TEMP\mof\$Configuration) {
                    $Mof = Get-ChildItem -Path "$env:TEMP\mof\$Configuration\*.mof"
                 }
                 $Mof | Should Not Be Null
            }
        }
    }
}

<#
#>
Describe 'Common Tests - Azure Automation DSC' -Tag AADSCIntegration {

    $ResourceGroup = "ContosoDev-Test$env:BuildID"
    $AutomationAccount = "AzureDSC$env:BuildID"

    $ScriptFileInfo = Test-ScriptFileInfo -Path "$env:BuildFolder\$env:ProjectName.ps1"
    
    $RequiredModules = $ScriptFileInfo.RequiredModules | ForEach-Object {$_.Name}

    . $env:BuildFolder\$env:ProjectName.ps1
    
    $ConfigurationCommands = Get-Command -Type Configuration | `
                             Where-Object {$_.Name -eq $env:ProjectName} | `
                             ForEach-Object {$_.Name}

    # Get AADSC Modules
    $AADSCModules = Get-AzureRmAutomationModule -ResourceGroupName $ResourceGroup `
                    -AutomationAccountName $AutomationAccount
    $AADSCModuleNames = $AADSCModules | ForEach-Object {$_.Name}

    # Get AADSC Configurations
    $AADSCConfigurations = Get-AzureRmAutomationDscConfiguration -ResourceGroupName `
                           $ResourceGroup -AutomationAccountName $AutomationAccount
    $AADSCConfigurationNames = $AADSCConfigurations | ForEach-Object {$_.Name}

    Context "Modules" {
        ForEach ($RequiredModule in $RequiredModules) {
            It "$RequiredModule should be present in AzureDSC" {
                $AADSCModuleNames.Contains($RequiredModule) | Should Be True
            }
        }
    }
    Context "Configurations" {
        ForEach ($ConfigurationCommand in $ConfigurationCommands) {
            It "$ConfigurationCommand should be present in AADSC" {
                $AADSCConfigurationNames.Contains("$ConfigurationCommand") | Should Be True
            }
            It "$ConfigurationCommand status should be Complete in AADSC" {
                $AADSCConfigurations | Where-Object {$_.Name -eq $ConfigurationCommand} | ForEach-Object {$_.State} | Should Be "Published"
            }
        }
    }
}

<#
#>
Describe 'Common Tests - Azure VM' -Tag AzureVMIntegration {

    $ResourceGroup = "ContosoDev-Test$env:BuildID"
    $AutomationAccount = "AzureDSC$env:BuildID"

    . $env:BuildFolder\$env:ProjectName.ps1
    $ConfigurationCommands = Get-Command -Type Configuration | Where-Object {$_.Source -eq ''} | ForEach-Object {$_.Name}

    $OSVersion = (Test-ScriptFileInfo $env:BuildFolder\$env:ProjectName.ps1).PrivateData

    $Nodes = Get-AzureRMAutomationDSCNode -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount
    $NodeNames = $Nodes | ForEach-Object {$_.Name}

    Context "AADSC Nodes" {
        foreach ($Node in $Nodes) {
            It "Node $($Node.Name) is compliant with $($Node.NodeConfigurationName)" {
                $Node.Status | Should Be 'Compliant'
            }
        }
    }
}    
