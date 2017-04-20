<#
    .SYNOPSIS

#>
function Invoke-UniquePSModulePath 
{
    [CmdletBinding()]
    param
    () 
    try 
    {
        Write-Output 'Verifying there are no duplicates in PSModulePath'
        # Correct duplicates in environment psmodulepath
        foreach($path in $env:psmodulepath.split(';').ToUpper().ToLower()) {
            [array]$correctDirFormat += "$path\;"
        }
        $correctDirFormat = $correctDirFormat.replace("\\","\") | Where-Object {$_ -ne '\;'} `
        | Select-Object -Unique
        foreach ($path in $correctDirFormat.split(';')) {
            [string]$fixPath += "$path;"
        }
        $env:psmodulepath = $fixpath.replace(';;',';')
    }
    catch [System.Exception]
    {
        throw "An error occured while correcting the psmodulepath`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS

#>
function Get-RequiredGalleryModules
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ManifestData,
        [switch]$Install
    )
    try {
        # Load module data and create array of objects containing prerequisite details for use 
        # later in Azure Automation
        $ModulesInformation = @()
        foreach($RequiredModule in $ManifestData.RequiredModules[0])
        {
            # Placeholder object to store module names and locations
            $ModuleReference = New-Object -TypeName PSObject
            
            # If no version is given, get the latest version
            if ($RequiredModule.gettype().Name -eq 'String')
            {
                if ($galleryReference = Invoke-RestMethod -Method Get `
                -Uri "https://www.powershellgallery.com/api/v2/FindPackagesById()?id='$RequiredModule'" `
                -ErrorAction Continue)
                {
                    Write-Verbose "Identified module $RequiredModule in the PowerShell Gallery"
                    $ModuleReference | Add-Member -MemberType NoteProperty -Name 'Name' `
                    -Value $RequiredModule
                    $ModuleReference | Add-Member -MemberType NoteProperty -Name 'URI' `
                    -Value ($galleryReference | Where-Object {$_.Properties.IsLatestVersion.'#text' `
                    -eq $true}).content.src
                    $ModulesInformation += $ModuleReference
                }
                else {
                    throw "The module $RequiredModule was not found in the gallery"
                }
                if ($Install -eq $true)
                {
                    Write-Verbose "Installing module: $RequiredModule"
                    Install-Module -Name $RequiredModule -force
                }
            }

            # If a version is given, get it specifically
            if ($RequiredModule.gettype().Name -eq 'Hashtable')
            {
                if ($galleryReference = Invoke-RestMethod -Method Get `
                -Uri "https://www.powershellgallery.com/api/v2/FindPackagesById()?id='$($RequiredModule.ModuleName)'" `
                -ErrorAction Continue)
                {
                    Write-Verbose "Identified module $($RequiredModule.ModuleName) in the PowerShell Gallery"
                    $ModuleReference | Add-Member -MemberType NoteProperty -Name 'Name' `
                    -Value $RequiredModule.ModuleName
                    $ModuleReference | Add-Member -MemberType NoteProperty -Name 'URI' `
                    -Value ($galleryReference | Where-Object {$_.Properties.Version `
                    -eq $RequiredModule.ModuleVersion}).content.src
                    $ModulesInformation += $ModuleReference
                }
                else {
                    throw "The module $($RequiredModule.ModuleName) was not found in the gallery"
                }
                if ($Install -eq $true)
                {
                    Write-Verbose "Installing module: $($RequiredModule.ModuleName) version $($RequiredModule.ModuleVersion)"
                    Install-Module -Name $RequiredModule.ModuleName `
                    -RequiredVersion $RequiredModule.ModuleVersion -force
                }
            }
        }
        return $ModulesInformation    
    }
    catch [System.Exception] 
    {
        throw "An error occured while getting modules from PowerShellGallery.com`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS

#>
function Invoke-ConfigurationPrep
{
    [CmdletBinding()]     
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$Module,
        [string]$Path = "$env:TEMP\DSCConfigurationScripts"
    )
    try 
    {
        # Discover OS versions, or default to Server 2016 Datacenter Edition
        $WindowsOSVersion = if ($ModuleData = `
        (Get-Module -Name $Module).PrivateData.PSData.WindowsOSVersion) {$ModuleData}
        else {'2016-Datacenter'}

        # Get list of configurations loaded from module
        . $env:BuildFolder\$env:ProjectName.ps1
        $Configurations = Get-Command -Type Configuration
        $Configurations | Add-Member -MemberType NoteProperty -Name Location -Value $null
        $Configurations | Add-Member -MemberType NoteProperty -Name WindowsOSVersion `
        -Value $WindowsOSVersion


        # Create working folder
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    
        # Create a unique script for each configuration, with a name that matches the configuration
        # this is a safeguard in case multiple configurations are given in a file
        foreach ($Configuration in $Configurations) {
            if ($Config = (Get-Command $Configuration).ScriptBlock) {
                $Configuration.Location = "$Path\$Configuration.ps1"
                # write a new configuration using the scriptblock loaded from the file
                "Configuration $Configuration`n{" | Out-File $Configuration.Location
                $Config | Out-File $Configuration.Location -Append
                "}`n" | Out-File $Configuration.Location -Append
            }
        }
        Write-Verbose "Prepared configurations:`n$($Configurations | ForEach-Object `
        -Process {$_.Name})"
        return $Configurations
    }
    catch [System.Exception] 
    {
        throw "An error occured while preparing configurations for import`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS

#>
function Import-ModuleFromSource
{
    [CmdletBinding()]     
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    try 
    {
        if ($ModuleDir = New-Item -Type Directory `
        -Path $env:ProgramFiles\WindowsPowerShell\Modules\$Name -force) {
            Copy-Item -Path .\$Name.psd1 -Destination $ModuleDir -force
            if (Test-Path .\$Name.psm1) {
                Copy-Item -Path .\$Name.psm1 -Destination $ModuleDir -force
            }
            Import-Module -Name $Name
        }
    }
    catch [System.Exception] 
    {
        throw "An error occured while importing module $Name`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS

#>
function Invoke-AzureSPNLogin
{
    [CmdletBinding()]
    param
    (
        [string]$SubscriptionID = $env:SubscriptionID,
        [string]$ApplicationID = $env:ApplicationID,
        [string]$ApplicationPassword = $env:ApplicationPassword,
        [string]$TenantID = $env:TenantID
    )
    try 
    {
        Write-Output "Logging in to Azure"
        
        # Build platform (AppVeyor) does not offer solution for passing secure strings
        $Credential = New-Object -typename System.Management.Automation.PSCredential -argumentlist $ApplicationID, $(convertto-securestring -String $ApplicationPassword -AsPlainText -Force)
    
        # Suppress request to share usage information
        $Path = "$Home\AppData\Roaming\Windows Azure Powershell\"
        if (!(Test-Path -Path $Path)) {
            $AzPSProfile = New-Item -Path $Path -ItemType Directory
        }
        $AzProfileContent = Set-Content -Value '{"enableAzureDataCollection":true}' -Path (Join-Path $Path 'AzureDataCollectionProfile.json') 

        # Handle login
        $AddAccount = Add-AzureRmAccount -ServicePrincipal -SubscriptionID $SubscriptionID -TenantID $TenantID -Credential $Credential -ErrorAction SilentlyContinue

        # Validate login
        $LoginSuccessful = Get-AzureRmSubscription -SubscriptionID $SubscriptionID -TenantID $TenantID
        if ($Null -eq $LoginSuccessful) {
            throw 'Login to Azure was unsuccessful!'
        }
    }
    catch [System.Exception] {
        write-output "An error occured while logging in to Azure`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS

#>
function New-ResourceGroupandAutomationAccount
{
    [CmdletBinding()]
    param
    (
        [string]$SubscriptionID = $env:SubscriptionID,
        [string]$TenantID = $env:TenantID,
        [string]$Location = 'EastUS2',
        [string]$ResourceGroupName = 'TestAutomation'+$env:BuildID,
        [string]$AutomationAccountName = 'AADSC'+$env:BuildID
    )
    try 
    {
        # Make sure subscription is selected
        $Subscription = Select-AzureRMSubscription -SubscriptionID $SubscriptionID `
        -TenantID $TenantID

        # Create Resource Group
        $ResourceGroup = New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location `
        -Force
        Write-Output "Provisioning of Resource Group $ResourceGroupName returned $($ResourceGroup.ProvisioningState)"
        # Validate provisioning of resource group
        $ResourceGroupExists = Get-AzureRmResourceGroup -Name $ResourceGroupName
        If ($Null -eq $ResourceGroupExists) {
            throw "Resource group $ResourceGroupName could not be validated"
        }

        # Create Azure Automation account
        $AutomationAccount = New-AzureRMAutomationAccount -ResourceGroupName $ResourceGroupName `
        -Name $AutomationAccountName -Location $Location -Plan Basic
        Write-Output "Provisioning of Automation Account $AutomationAccountName returned $($AutomationAccount.State)"
        # Validate provisioning of resource group
        $AutomationAccountExists = Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName `
        -Name $AutomationAccountName
        If ($Null -eq $AutomationAccountExists) {
            throw "Automation account $AutomationAccountName could not be validated"
        }
    }
    catch [System.Exception] {
        throw "An error occured while creating or validating Azure resources`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS

#>
function Import-ModuleToAzureAutomation
{
    [CmdletBinding()]     
    param
    (
        [Parameter(Mandatory=$true)]
        [array]$Module,
        [string]$ResourceGroupName = 'TestAutomation'+$env:BuildID,
        [string]$AutomationAccountName = 'AADSC'+$env:BuildID
    )
    try
    {
        Write-Output "Importing module $($Module.Name) to Azure Automation"
        # Import module from custom object
        $ImportedModule = New-AzureRMAutomationModule -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName -Name $Module.Name -ContentLink $Module.URI

        # Validate module was imported
        $ImportedModuleExists = Get-AzureRmAutomationModule -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName -Name $Module.Name
        if ($Null -eq $ImportedModuleExists) {
            throw "The module $($Module.Name) could not be validated"
        }
    }
    catch [System.Exception] {
        throw "An error occured while importing the module $($Module.Name) to Azure Automation`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS

#>
function Wait-ModuleExtraction
{
    [CmdletBinding()]     
    param
    (
        [Parameter(Mandatory=$true)]
        [array]$Module,
        [string]$ResourceGroupName = 'TestAutomation'+$env:BuildID,
        [string]$AutomationAccountName = 'AADSC'+$env:BuildID
    )
    try
    {
        # The resource modules must finish the "Creating" stage before the configuration will compile successfully
        while ((Get-AzureRMAutomationModule -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName -Name $Module.Name).ProvisioningState `
        -ne 'Succeeded') {
                Start-Sleep -Seconds 15
        }
    }
    catch [System.Exception] 
    {
        throw "An error occured while waiting for module $($Module.Name) activities to extract in Azure Automation`n$($_.exception.message)"        
    }
}    

<#
    .SYNOPSIS

#>
function Import-ConfigurationToAzureAutomation
{
    [CmdletBinding()]     
    param
    (
        [Parameter(Mandatory=$true)]
        [psobject]$Configuration,
        [string]$ResourceGroupName = 'TestAutomation'+$env:BuildID,
        [string]$AutomationAccountName = 'AADSC'+$env:BuildID
    )
    try 
    {
        Write-Output "Importing configuration $($Configuration.Name) to Azure Automation"
        # Import Configuration to Azure Automation DSC
        $ConfigurationImport = Import-AzureRmAutomationDscConfiguration `
        -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -SourcePath $Configuration.Location -Published -Force

        # Validate configuration was imported
        $ConfigurationImportExists = Get-AzureRmAutomationDscConfiguration `
        -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -Name $Configuration.Name
        if ($Null -eq $ConfigurationImportExists) {
            throw "The configuration $($Configuration.Name) could not be validated"
        }

        # Load configdata if it exists
        if (Test-Path "$env:BuildFolder\ConfigurationData\$($Configuration.Name).ConfigData.psd1") {
            $ConfigurationData = Import-PowerShellDataFile `
                "$env:BuildFolder\ConfigurationData\$($Configuration.Name).ConfigData.psd1"
        }

        # Splate params to compile in Azure Automation DSC
        $CompileParams = @{
        ResourceGroupName     = $ResourceGroupName
        AutomationAccountName = $AutomationAccountName
        ConfigurationName     = $Configuration.Name
        ConfigurationData     = $ConfigurationData
    }
        $Compile = Start-AzureRmAutomationDscCompilationJob @CompileParams
    }
    catch [System.Exception] 
    {
        throw "An error occured while importing the configuration $($Configuration.Name) using Azure Automation`n$($_.exception.message)"        
    }
}

<#
    .SYNOPSIS

#>
function Wait-ConfigurationCompilation
{
    [CmdletBinding()]     
    param
    (
        [Parameter(Mandatory=$true)]
        [psobject]$Configuration,
        [string]$ResourceGroupName = 'TestAutomation'+$env:BuildID,
        [string]$AutomationAccountName = 'AADSC'+$env:BuildID
    )
    try 
    {
        while (@('Completed','Suspended') -notcontains (Get-AzureRmAutomationDscCompilationJob -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName -Name $Configuration.Name).Status) {
            Start-Sleep -Seconds 15
        }   
    }
    catch [System.Exception] 
    {
        throw "An error occured while waiting for configuration $($Configuration.Name) to compile in Azure Automation`n$($_.exception.message)"        
    }
}

<#
    This work was originally published in the PowerShell xJEA module.
    https://github.com/PowerShell/xJea/blob/dev/DSCResources/Library/JeaAccount.psm1
    .Synopsis
    Creates a random password.
    .DESCRIPTION
    Creates a random password by generating a array of characters and passing it to Get-Random
    .EXAMPLE
    PS> New-RandomPassword
    g0dIDojsRGcV
    .EXAMPLE
    PS> New-RandomPassword -Length 3
    dyN
    .EXAMPLE
    PS> New-RandomPassword -Length 30 -UseSpecialCharacters
    r5Lhs1K9n*joZl$u^NDO&TkWvPCf2c
#>
function New-RandomPassword
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        # Length of the password
        [Parameter(Mandatory=$False, Position=0)]
        [ValidateRange(12, 127)]
        $Length=12,

        # Includes the characters !@#$%^&*-+ in the password
        [switch]$UseSpecialCharacters
    )

    [char[]]$allowedCharacters = ([Char]'a'..[char]'z') + ([char]'A'..[char]'Z') + `
    ([byte][char]'0'..[byte][char]'9')
    if ($UseSpecialCharacters)
    {
        foreach ($c in '!','@','#','$','%','^','&','*','-','+')
        {
            $allowedCharacters += [char]$c
        }
    }

    $characters = 1..$Length | ForEach-Object {
        $characterIndex = Get-Random -Minimum 0 -Maximum $allowedCharacters.Count
        $allowedCharacters[$characterIndex]
    }

    return (-join $characters)
}

<#
    .SYNOPSIS

#>
function New-AzureTestVM
{
    [CmdletBinding()]     
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$Configuration,
        [Parameter(Mandatory=$true)]        
        [string]$WindowsOSVersion
    )
    try 
    {
        # Retrieve Azure Automation DSC registration information
        $Account = Get-AzureRMAutomationAccount -ResourceGroupName "TestAutomation$env:BuildID" `
        -Name "AADSC$env:BuildID"
        $RegistrationInfo = $Account | Get-AzureRmAutomationRegistrationInfo
        $registrationUrl = $RegistrationInfo.Endpoint
        $registrationKey = $RegistrationInfo.PrimaryKey | ConvertTo-SecureString -AsPlainText `
        -Force

        # Random password for local administrative account
        $adminPassword = new-randompassword -length 24 -UseSpecialCharacters | `
        ConvertTo-SecureString -AsPlainText -Force

        # DNS name based on random chars followed by first 10 of configuration name
        $dnsLabelPrefix = "test$(Get-Random -Minimum 1000 -Maximum 9999)"

        # VM Name based on configuration name and OS name
        $vmName = "$Configuration.$($WindowsOSVersion.replace('-',''))"

        # Build hashtable of deployment parameters
        $DeploymentParameters = @{
            Name = $vmName
            ResourceGroupName = "TestAutomation$env:BuildID"
            TemplateFile = "$env:BuildFolder\DSCConfiguration.Tests\AzureDeploy.json"
            TemplateParameterFile = "$env:BuildFolder\DSCConfiguration.Tests\AzureDeploy.parameters.json"
            dnsLabelPrefix = $dnsLabelPrefix
            vmName = $vmName
            storageAccountName = "sa$($WindowsOSVersion.replace('-','').ToLower())"
            nicName = "nic$Configuration$env:BuildID$($WindowsOSVersion.replace('-','').ToLower())"
            publicIPAddressName = "pip$Configuration$env:BuildID$($WindowsOSVersion.replace('-','').ToLower())"
            virtualNetworkName = "net$Configuration$env:BuildID$($WindowsOSVersion.replace('-','').ToLower())"
            nsgName = "nsg$Configuration$env:BuildID$($WindowsOSVersion.replace('-','').ToLower())"
            WindowsOSVersion = $WindowsOSVersion
            adminPassword = $adminPassword
            registrationUrl = $registrationUrl
            registrationKey = $registrationKey
            nodeConfigurationName = "$Configuration.localhost"
        }

        # Deploy ARM template
        $AzureVm = New-AzureRMResourceGroupDeployment @DeploymentParameters

        # Get deployment details
        $Status = Get-AzureRMResourceGroupDeployment -ResourceGroupName "TestAutomation$env:BuildID" `
        -Name $vmName

        # Write output to build log
        if ($Status.ProvisioningState -eq 'Succeeded') {
            Write-Output "Virtual machine DNS address: $($Status.Outputs.Values.Value)"
        }
        else {
            Write-Output $AzureVm
            $Error = Get-AzureRMResourceGroupDeploymentOperation -ResourceGroupName "TestAutomation$env:BuildID" `
            -Name $vmName
            $Message = $Error.Properties | Where-Object {$_.ProvisioningState -eq 'Failed'} | `
            ForEach-Object {$_.StatusMessage} | ForEach-Object {$_.Error} | `
            ForEach-Object {$_.Details} | ForEach-Object {$_.Message}
            Write-Error $Message
        }
    }
        catch [System.Exception] 
        {
        throw "An error occured during the Azure deployment.`n$($_.exception.message)"        
    }
}

<#
    .SYNOPSIS

#>
function Wait-NodeCompliance
{
    [CmdletBinding()]     
    param
    (
        [string]$ResourceGroupName = 'TestAutomation'+$env:BuildID,
        [string]$AutomationAccountName = 'AADSC'+$env:BuildID
    )
    try 
    {
        $Nodes = Get-AzureRMAutomationDSCNode -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName

        foreach ($Node in $Nodes) {
            while (@($null, 'InProgress', 'Pending') -contains (Get-AzureRMAutomationDSCNodeReport -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName -NodeID $Node.ID).Status) {
                Start-Sleep -Seconds 15
            }
        }
    }
    catch [System.Exception] 
    {
        throw "An error occured while waiting nodes to report compliance status in Azure Automation`n$($_.exception.message)"        
    }
}

<#
    .SYNOPSIS

#>
function Remove-AzureTestResources
{
    [CmdletBinding()]
    param
    (
        [string]$ResourceGroupName = 'TestAutomation'+$env:BuildID
    )
    try {
        $Remove = Remove-AzureRmResourceGroup -Name $ResourceGroupName -Force
    }
    catch [System.Exception] {
        throw "An error occured while removing the Resource Group $ResourceGroupName`n$($_.exception.message)"
    }
}

<#
    .SYNOPSIS
        Tests if a file is encoded in Unicode.

    .PARAMETER FileInfo
    The file to test.
#>
function Test-FileInUnicode
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [System.IO.FileInfo]
        $FileInfo
    )

    $filePath = $FileInfo.FullName
    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
    $zeroBytes = @( $fileBytes -eq 0 )

    return ($zeroBytes.Length -ne 0)
}

<#
    .SYNOPSIS
        Retrieves the parse errors for the given file.

    .PARAMETER FilePath
    The path to the file to get parse errors for.
#>
function Get-FileParseErrors
{
    [OutputType([System.Management.Automation.Language.ParseError[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]
        $FilePath
    )

    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref] $null, `
    [ref] $parseErrors)

    return $parseErrors
}

<#
    .SYNOPSIS
        Retrieves all text files under the given root file path.

    .PARAMETER Root
        The root file path under which to retrieve all text files.

    .NOTES
    Retrieves all files with the '.gitignore', '.gitattributes', '.ps1', '.psm1', '.psd1',
    '.json', '.xml', '.cmd', or '.mof' file extensions.
#>
function Get-TextFilesList
{
    [OutputType([System.IO.FileInfo[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath
    )

    $textFileExtensions = @('.gitignore', '.gitattributes', '.ps1', '.psm1', '.psd1', '.json', `
    '.xml', '.cmd', '.mof')

    return Get-ChildItem -Path $FilePath -File -Recurse | Where-Object { $textFileExtensions `
    -contains $_.Extension }
}

<#
    .SYNOPSIS
        Retrieves the list of suppressed PSSA rules in the file at the given path.

    .PARAMETER FilePath
    The path to the file to retrieve the suppressed rules of.
#>
function Get-SuppressedPSSARuleNameList
{
    [OutputType([String[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath
    )

    $suppressedPSSARuleNames = [String[]]@()

    $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$null, `
    [ref]$null)

    # Overall file attrbutes
    $attributeAsts = $fileAst.FindAll({$args[0] `
    -is [System.Management.Automation.Language.AttributeAst]}, $true)

    foreach ($attributeAst in $attributeAsts)
    {
        if ([System.Diagnostics.CodeAnalysis.SuppressMessageAttribute].FullName.ToLower().Contains($attributeAst.TypeName.FullName.ToLower()))
        {
            $suppressedPSSARuleNames += $attributeAst.PositionalArguments.Extent.Text
        }
    }

    return $suppressedPSSARuleNames
}
