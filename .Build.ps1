<#
    Invoke-Build script for DSC Configuration validation

    This script should be ubiquitious such that it can be run on a local workstation or within
    any build service and achieve the same outcome.

    Goals:
        - Verify the configuration module and Configuration meet basic requirements using Pester
          and PSScriptAnalyzer.
        - Deploy the Configuration and any required modules to Azure Automation using AzureRM
        - Verify the Configuration compile successfully in Azure Automation using Pester
        - Deploy Azure VM instance(s) and apply configuration using AzureRM
        - Verify the server is configured as expected

    Test results should be clearly understood using reporting platforms that support NUnit XML.

    The process to validate any configuration should only require the author to clone this repo
    in to their project folder and execute 'Invoke-Build' from a PowerShell session, providing
    input parameters for Azure authentication, etc.
#>

<#
#>
function Write-Task {
    param(
        [string]$Name
    )
    Write-Output `n
    Write-Build -Color Cyan -Text "########## $Name ##########"
}

Enter-BuildTask {
    $BuildRoot = $env:BuildFolder
    Write-task $task.Name
}

Exit-BuildTask {
    # PLACEHOLDER
}

<#
.Synopsis: Baseline the environment
#>
Enter-Build {
    Write-Output "The build folder is $env:BuildFolder"
    
    # Optimize timing for AzureRM module to install
    Write-Output "Installing latest AzureRM module as background job"
    $ARM = Start-Job -ScriptBlock {
        Install-Module "AzureRm.Resources", "AzureRM.Automation", "AzureAutomationAuthoringToolkit" -Scope CurrentUser -Force
    }

    # Load helper module from test repo
    Import-Module -Name $env:BuildFolder\DscConfiguration.Tests\TestHelper.psm1 -Force
    
    # Fix module path if duplicates exist (TestHelper)
    Invoke-UniquePSModulePath

    # Create random password
    $script:Password = new-randompassword -length 24 -UseSpecialCharacters | `
    ConvertTo-SecureString -AsPlainText -Force
}

<#
.Synopsis: Load the Configuration script
#>
Add-BuildTask LoadConfigurationScript {
    # Prep and import Configuration
    $script:Configuration = Invoke-ConfigurationPrep -Verbose

    Write-Output "Loaded Configuration:`n$($script:Configuration | `
        ForEach-Object -Process `
        {$_.Name})"
    Write-Output "Supported operating systems:`n$($script:Configuration | `
        ForEach-Object -Process `
        {$_.OSVersions})"

    # This was moved from another build task used when configurations were stored in modules
    # and ideally should be a new seperate build task
    $script:Modules = Get-RequiredGalleryModules $($script:Configuration | `
                      ForEach-Object -Process {$_.RequiredModules}) -Verbose

    Write-Output "Required Modules:`n$($script:Modules | `
        ForEach-Object -Process {$_.Name})"
    
}

<#
.Synopsis: Run Lint and Unit Tests
#>
Add-BuildTask LintUnitTests {
    $testResultsFile = "$env:BuildFolder\LintUnitTestsResults.xml"
    $Pester = Invoke-Pester -Tag Lint, Unit -OutputFormat NUnitXml -OutputFile `
        $testResultsFile -PassThru
    
    (New-Object 'System.Net.WebClient').UploadFile("$env:TestResultsUploadURI", `
    (Resolve-Path $testResultsFile))

    Push-AppveyorArtifact -Path (Resolve-Path $testResultsFile)

    if ($Pester.FailedCount -gt 0) {
        throw "Pester returned errors after tests`n$Pester"
    }
}

<#
.Synopsis: Perform Azure Login
#>
Add-BuildTask AzureLogin {
    Write-Output "Waiting for AzureRM module to finish installing"
    $ARM = Wait-Job -Job $ARM
    
    # Login to Azure using information from params
    Invoke-AzureSPNLogin
}

<#
.Synopsis: Create Resource Group
#>
Add-BuildTask ResourceGroupAndAutomationAccount {
    # Create Azure Resource Group and Automation account (TestHelper)
    Write-Output "Creating assets for build $env:BuildID."
    New-ResourceGroupandAutomationAccount -Password $script:Password
}

<#
.Synopsis: Deploys modules to Azure Automation
#>
Add-BuildTask AzureAutomationAssets {
    Write-Output "Starting background task to load assets to Azure Automation"
    Write-Output "Loading Modules: $($script:Modules | ForEach-Object -Process {$_.Name})"
    Write-Output "Loading Configuration: $($script:Configuration | ForEach-Object -Process `
    {$_.Name})"
    $Script:AzureAutomationJob = Start-Job -ScriptBlock {
        param (
            $Modules,
            $Configuration
        )
        Import-Module -Name $env:BuildFolder\DscConfiguration.Tests\TestHelper.psm1 -Force
        Invoke-AzureSPNLogin

        # Import the modules discovered as requirements to Azure Automation (TestHelper)
        foreach ($ImportModule in $Modules) {
            Import-ModuleToAzureAutomation -Module $ImportModule -Verbose
        }    
        # Allow module activities to extract before importing configuration (TestHelper)
        foreach ($WaitForModule in $Modules) {
            Wait-ModuleExtraction -Module $WaitForModule
        }

        # Import and compile the Configuration using Azure Automation (TestHelper)
        Import-ConfigurationToAzureAutomation -Configuration $Configuration

        # Wait for Configuration to compile
        Wait-ConfigurationCompilation -Configuration $Configuration
    } -ArgumentList @($script:Modules, $script:Configuration)
}

<#
.Synopsis: Deploys Azure VM and bootstraps to Azure Automation DSC
#>
Add-BuildTask AzureVM {
    $Script:VMDeployments = @()
    Write-Output 'Deploying all test virtual machines in parallel'
    
    ForEach ($OSVersion in $Script:Configuration.OSVersions) {
    
        If ($null -eq $OSVersion) {
            Write-Output "No OS version was provided for deployment of $($Script:Configuration.Name)"
        }
        Write-Output "Initiating background deployment of $OSVersion and bootstrapping configuration $($Script:Configuration.Name)"
    
        $JobName = "$($Script:Configuration.Name).$($OSVersion.replace('-',''))"
    Write-Host "Starting job $JobName"
        $Script:VMDeployment = Start-Job -ScriptBlock {
            param
            (
                [string]$Configuration,
                [string]$OSVersion,
                [securestring]$Password
            )
            #>
            Import-Module -Name $env:BuildFolder\DscConfiguration.Tests\TestHelper.psm1 -Force
        
            Invoke-AzureSPNLogin
        
            New-AzureTestVM -Configuration $Configuration -OSVersion $OSVersion `
            -Password $Password

        } -ArgumentList @($Script:Configuration.Name, $OSVersion, $script:Password) -Name $JobName
        $Script:VMDeployments += $Script:VMDeployment

        # pause for provisioning to avoid conflicts (this is a case where slower is faster)
        Start-Sleep 15
    }
}

<#
.Synopsis: Integration tests to verify that modules and Configuration loaded to Azure Automation DSC successfully
#>
Add-BuildTask IntegrationTestAzureAutomationDSC {
    Write-Host "Waiting for Azure Automation module extraction and configuration compile jobs actions to finish"
    $AzureAutomationJobWait = Wait-Job $Script:AzureAutomationJob
    Receive-Job $Script:AzureAutomationJob

    Write-Host 'Running tests tagged AADSCIntegration'
    $testResultsFile = "$env:BuildFolder\AADSCIntegrationTestsResults.xml"
    $Pester = Invoke-Pester -Tag AADSCIntegration -OutputFormat NUnitXml `
        -OutputFile $testResultsFile -PassThru

    Write-Host 'Uploading test results to Appveyor'
    (New-Object 'System.Net.WebClient').UploadFile("$env:TestResultsUploadURI", `
    (Resolve-Path $testResultsFile))

    Write-Host 'Uploading build artifacts to Appveyor'
    Push-AppveyorArtifact -Path (Resolve-Path $testResultsFile)

    if ($Pester.FailedCount -gt 0) {
        throw "Pester returned errors after tests`n$Pester"
    }
}

<#
.Synopsis: Integration tests to verify that DSC configuration successfuly applied in virtual machines
#>
Add-BuildTask IntegrationTestAzureVMs {
    Write-Host "Waiting for all nodes to finish deployment"
    ForEach ($VMDeploymentJob in $Script:VMDeployments) {
        $Wait = Wait-Job -Job $VMDeploymentJob
        
        Write-Output `n
        Write-Output "########## Output from $($VMDeploymentJob.Name) ##########"
        Receive-Job -Job $VMDeploymentJob
    }

    # Also waiting for all nodes to upload their first status reports to Azure Automation
    Write-Host "Waiting for all nodes to report status to Azure Automation"
    Wait-NodeCompliance

    $testResultsFile = "$env:BuildFolder\VMIntegrationTestsResults.xml"

    $Pester = Invoke-Pester -Tag AzureVMIntegration -OutputFormat NUnitXml `
        -OutputFile $testResultsFile -PassThru

    (New-Object 'System.Net.WebClient').UploadFile("$env:TestResultsUploadURI", `
    (Resolve-Path $testResultsFile))

    Push-AppveyorArtifact -Path (Resolve-Path $testResultsFile)

    if ($Pester.FailedCount -gt 0) {
        throw "Pester returned errors after tests`n$Pester"
    }
}

<#
.Synopsis: remove all assets deployed to Azure and any local temporary changes (should be none)
#>
Exit-Build {
    if (!$env:DiagnoseRG) {
        Remove-AzureTestResources
    }
}

<#
.Synopsis: default build tasks
#>
Add-BuildTask . LoadConfigurationScript, LintUnitTests, AzureLogin, `
ResourceGroupAndAutomationAccount, AzureAutomationAssets, `
IntegrationTestAzureAutomationDSC, AzureVM, IntegrationTestAzureVMs
