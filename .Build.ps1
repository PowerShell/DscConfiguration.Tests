<#
    Invoke-Build script for DSC Configuration validation

    This script should be ubiquitious such that it can be run on a local workstation or within
    any build service and achieve the same outcome.

    Goals:
        - Verify the configuration module and configurations meet basic requirements using Pester
          and PSScriptAnalyzer.
        - Deploy the configurations and any required modules to Azure Automation using AzureRM
        - Verify the configurations compile successfully in Azure Automation using Pester
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
        Install-Module "AzureRm.Resources", "AzureRM.Automation" -force
    }
    # Load modules from test repo
    Import-Module -Name $env:BuildFolder\DscConfiguration.Tests\TestHelper.psm1 -Force
    
    # Install supporting environment modules from PSGallery
    $EnvironmentModules = @(
        'Pester',
        'PSScriptAnalyzer'
    )
    $Nuget = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.205 -Force
    Write-Output "Installing modules to support the build environment:`n$EnvironmentModules"
    Install-Module -Name $EnvironmentModules -Repository PSGallery -Force
    
    # Fix module path if duplicates exist (TestHelper)
    Invoke-UniquePSModulePath
}

<#
.Synopsis: Load the required resources
#>
Add-BuildTask LoadResourceModules {
    # Discover required modules from Configuration manifest (TestHelper)
    $script:Modules = Get-RequiredGalleryModules -ManifestData (Import-PowerShellDataFile `
    -Path "$env:BuildFolder\$env:ProjectName\$env:ProjectName.psd1") -Install
    Write-Output "Loaded modules:`n$($script:Modules | ForEach-Object -Process {$_.Name})"
}

<#
.Synopsis: Load the Configuration modules
#>
Add-BuildTask LoadConfigurationScript {
    # Prep and import Configurations
    $ProjectModuleName = $env:ProjectName+'Module'
    Set-Location "$env:BuildFolder\$ProjectModuleName\"
    Import-ModuleFromSource -Name $$ProjectModuleName
    $script:Configurations = Invoke-ConfigurationPrep -Module $$ProjectModuleName -Path `
        "$env:TEMP\$env:ProjectID"
    Write-Output "Loaded configurations:`n$($script:Configurations | ForEach-Object -Process {$_.Name})"
}

<#
.Synopsis: Run Lint and Unit Tests
#>
Add-BuildTask LintUnitTests {
    $testResultsFile = "$env:BuildFolder\LintUnitTestsResults.xml"

    $Pester = Invoke-Pester -Tag Lint, Unit -OutputFormat NUnitXml -OutputFile $testResultsFile -PassThru
    
    (New-Object 'System.Net.WebClient').UploadFile("$env:TestResultsUploadURI", `
    (Resolve-Path $testResultsFile))
    $host.SetShouldExit($Pester.FailedCount)
}

<#
.Synopsis: Perform Azure Login
#>
Add-BuildTask AzureLogin {
    Write-Output "Waiting for AzureRM module to finish installing"
    $ARM = Wait-Job -Job $ARM
    # Login to Azure using information from params
    Invoke-AzureSPNLogin -ApplicationID $env:ApplicationID -ApplicationPassword `
    $env:ApplicationPassword -TenantID $env:TenantID -SubscriptionID $env:SubscriptionID
}

<#
.Synopsis: Create Resource Group
#>
Add-BuildTask ResourceGroupAndAutomationAccount {
    # Create Azure Resource Group and Automation account (TestHelper)
    New-ResourceGroupandAutomationAccount
}

<#
.Synopsis: Deploys modules to Azure Automation
#>
Add-BuildTask AzureAutomationAssets {
    Write-Output "Starting background task to load assets to Azure Automation"
    $Script:AzureAutomationJob = Start-Job -ScriptBlock {
        param (
            $Modules,
            $Configurations
        )
        Import-Module -Name $env:BuildFolder\DscConfiguration.Tests\TestHelper.psm1 -Force
        Invoke-AzureSPNLogin -ApplicationID $env:ApplicationID -ApplicationPassword `
        $env:ApplicationPassword -TenantID $env:TenantID -SubscriptionID $env:SubscriptionID

        # Import the modules discovered as requirements to Azure Automation (TestHelper)
        foreach ($ImportModule in $Modules) {
            Import-ModuleToAzureAutomation -Module $ImportModule
        }    
        # Allow module activities to extract before importing configuration (TestHelper)
        foreach ($WaitForModule in $Modules) {
            Wait-ModuleExtraction -Module $WaitForModule
        }

        # Import and compile the Configurations using Azure Automation (TestHelper)
        foreach ($ImportConfiguration in $Configurations) {
            Import-ConfigurationToAzureAutomation -Configuration $ImportConfiguration
        }
        # Wait for Configurations to compile
        foreach ($WaitForConfiguration in $Configurations) {
            Wait-ConfigurationCompilation -Configuration $WaitForConfiguration
        }
    } -ArgumentList @($Script:Modules, $Script:Configurations)
}

<#
.Synopsis: Deploys Azure VM and bootstraps to Azure Automation DSC
#>
Add-BuildTask AzureVM {
    $Script:VMDeployments = @()
    Write-Output 'Deploying all test virtual machines in parallel'
    
    ForEach ($Configuration in $script:Configurations) {
        ForEach ($WindowsOSVersion in $Configuration.WindowsOSVersion) {
        
            If ($null -eq $WindowsOSVersion) {throw "No OS version was provided for deployment of $($Configuration.Name)"}
            Write-Output "Initiating background deployment of $WindowsOSVersion and bootstrapping configuration $($Configuration.Name)"
        
            $JobName = "$($Configuration.Name).$($WindowsOSVersion.replace('-',''))"
        
            $Script:VMDeployment = Start-Job -ScriptBlock {
                param
                (
                    [string]$env:BuildID,
                    [string]$Configuration,
                    [string]$WindowsOSVersion
                )
                Import-Module -Name $env:BuildFolder\DscConfiguration.Tests\TestHelper.psm1 -Force
            
                Invoke-AzureSPNLogin -ApplicationID $env:ApplicationID -ApplicationPassword `
            $env:ApplicationPassword -TenantID $env:TenantID -SubscriptionID $env:SubscriptionID
            
                New-AzureTestVM -BuildID $env:BuildID -Configuration $Configuration -WindowsOSVersion `
            $WindowsOSVersion

            } -ArgumentList @($env:BuildID, $Configuration.Name, $WindowsOSVersion) -Name $JobName
            $Script:VMDeployments += $Script:VMDeployment
            # pause for provisioning to avoid conflicts (this is a case where slower is faster)
            Start-Sleep 15
        }
    }
}

<#
.Synopsis: Integration tests to verify that modules and configurations loaded to Azure Automation DSC successfully
#>
Add-BuildTask IntegrationTestAzureAutomationDSC {
    Write-Host "Waiting for Azure Automation module extraction and configuration compile jobs actions to finish"
    $AzureAutomationJobWait = Wait-Job $Script:AzureAutomationJob
    Receive-Job $Script:AzureAutomationJob

    $testResultsFile = "$env:BuildFolder\AADSCIntegrationTestsResults.xml"

    $Pester = Invoke-Pester -Tag AADSCIntegration -OutputFormat NUnitXml `
    -OutputFile $testResultsFile -PassThru
    
    (New-Object 'System.Net.WebClient').UploadFile("$env:TestResultsUploadURI", `
    (Resolve-Path $testResultsFile))

    $host.SetShouldExit($Pester.FailedCount)
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

    $host.SetShouldExit($Pester.FailedCount)
}

<#
.Synopsis: remove all assets deployed to Azure and any local temporary changes (should be none)
#>
Exit-Build {
    Remove-AzureTestResources
}

<#
.Synopsis: default build tasks
#>
Add-BuildTask . LoadResourceModules, LoadConfigurationScript, LintUnitTests, AzureLogin, `
ResourceGroupAndAutomationAccount, AzureAutomationAssets, AzureVM, `
IntegrationTestAzureAutomationDSC, IntegrationTestAzureVMs
