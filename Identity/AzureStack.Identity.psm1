# Copyright (c) Microsoft Corporation. All rights reserved.
# See LICENSE.txt in the project root for license information.

<#
.Synopsis
    Get the Guid of the directory tenant
.DESCRIPTION
    This function fetches the OpenID configuration metadata from the identity system and parses the Directory TenantID out of it. 
    Azure Stack AD FS is configured to be a single tenanted identity system with a TenantID.
.EXAMPLE
    Get-AzsDirectoryTenantIdentifier -authority https://login.windows.net/microsoft.onmicrosoft.com
.EXAMPLE
    Get-AzsDirectoryTenantIdentifier -authority https://adfs.local.azurestack.external/adfs
#>

function Get-AzsDirectoryTenantidentifier {
    [CmdletBinding()]
    Param
    (
        # The Authority of the identity system, e.g. "https://login.windows.net/microsoft.onmicrosoft.com"
        [Parameter(Mandatory = $true,
            Position = 0)]
        $Authority
    )

    return $(Invoke-RestMethod $("{0}/.well-known/openid-configuration" -f $authority.TrimEnd('/'))).issuer.TrimEnd('/').Split('/')[-1]
}

<#
   .Synopsis
      This function is used to create a Service Principal on the AD Graph in an AD FS topology
   .DESCRIPTION
      The command creates a certificate in the cert store of the local user and uses that certificate to create a Service Principal in the Azure Stack Stamp Active Directory.
   .EXAMPLE
      $servicePrincipal = New-AzsAdGraphServicePrincipal -DisplayName "myapp12" -AdminCredential $(Get-Credential) -Verbose
#>

function New-AzsAdGraphServicePrincipal {
    [CmdletBinding()]
    Param
    (
        # Display Name of the Service Principal
        [ValidatePattern("[a-zA-Z0-9-]{3,}")]
        [Parameter(Mandatory = $true,
            Position = 0)]
        $DisplayName,

        # PEP Machine name        
        [string]
        $ERCSMachineName = "Azs-ERCS01",

        # Domain Administrator Credential to create Service Principal
        [Parameter(Mandatory = $true,
            Position = 2)]
        [System.Management.Automation.PSCredential]
        $AdminCredential
    )
    $ApplicationGroupName = $DisplayName
    $computerName = $ERCSMachineName
    $cloudAdminCredential = $AdminCredential
    $domainAdminSession = New-PSSession -ComputerName $computerName  -Credential $cloudAdminCredential -configurationname privilegedendpoint  -Verbose
    $GraphClientCertificate = New-SelfSignedCertificate -CertStoreLocation "cert:\CurrentUser\My" -Subject "CN=$ApplicationGroupName" -KeySpec KeyExchange
    $graphRedirectUri = "https://localhost/".ToLowerInvariant()
    $ApplicationName = $ApplicationGroupName
    $application = Invoke-Command -Session $domainAdminSession -Verbose -ErrorAction Stop  `
        -ScriptBlock { New-GraphApplication -Name $using:ApplicationName  -ClientRedirectUris $using:graphRedirectUri -ClientCertificates $using:GraphClientCertificate }
    
    return $application
}

# Exposed Functions

<#
.Synopsis
Repairs the advertised application registrations within Azure Stack for use with the "Register-AzsWithMyDirectoryTenant" cmdlet.
.DESCRIPTION
Running this cmdlet will repairs the advertised application registrations within Azure Stack for use with the "Register-AzsWithMyDirectoryTenant" cmdlet.
.EXAMPLE
$adminARMEndpoint = "https://adminmanagement.local.azurestack.external"
$azureStackDirectoryTenant = "<homeDirectoryTenant>.onmicrosoft.com"
$guestDirectoryTenantToBeOnboarded = "<guestDirectoryTenant>.onmicrosoft.com"

Repair-AzsApplicationRegistrations -AdminResourceManagerEndpoint $adminARMEndpoint -DirectoryTenantName $azureStackDirectoryTenant
#>

function Repair-AzsApplicationRegistrations {
    [CmdletBinding()]
    param
    (
        # The endpoint of the Azure Stack Resource Manager service.
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateScript( {$_.Scheme -eq [System.Uri]::UriSchemeHttps})]
        [uri] $AdminResourceManagerEndpoint,

        # The name of the home Directory Tenant in which the Azure Stack Administrator subscription resides.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $DirectoryTenantName,

        # The location of your Azure Stack deployment.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Location,

        # Optional: A credential used to authenticate with Azure Stack. Must support a non-interactive authentication flow. If not provided, the script will prompt for user credentials.
        [Parameter()]
        [ValidateNotNull()]
        [pscredential] $AutomationCredential = $null,

        # Indicates whether the script should only test if the application registration permissions are as-expected, without changing them. Run this command with "-Test:$false" to have it correct the changes it reports from running it without this modifier.
        [Parameter()]
        [switch] $Test = $true
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    if (-not $Test) {
        Write-Warning -WarningAction Inquire -Message "This script makes changes to the advertised application permissions within Azure Stack. This is a temporary workaround to address certain circumstances which can result in modifications to these resources within Azure Stack. Only run this script if you have been directed to do so or have an understanding of the modifications this script addresses. Are you sure you want to proceed?"
    }
    else {
        Write-Warning "This script has been executed with the default parameter '-Test:`$true' which will only report if any changes are detected to application registrations which can arise in certain circumstances when running an Azure Stack update. After reviewing the changes it reports, run the script again with the parameter '-Test:`$false' to apply the changes."
    }

    # Install-Module AzureRm
    Import-Module 'AzureRm.Profile' -Verbose:$false 4> $null
    Import-Module "$PSScriptRoot\GraphAPI\GraphAPI.psm1" -Verbose:$false 4> $null

    function Invoke-Main {
        # Initialize the Azure PowerShell module to communicate with the Azure Resource Manager in the public cloud corresponding to the Azure Stack Graph Service. Will prompt user for credentials.
        Write-Host "Authenticating user..."
        $azureStackEnvironment = Initialize-AzureRmEnvironment 'AzureStackAdmin'
        $refreshToken = Initialize-AzureRmUserAccount $azureStackEnvironment

        # Initialize the Graph PowerShell module to communicate with the correct graph service
        $graphEnvironment = Resolve-GraphEnvironment $azureStackEnvironment
        Initialize-GraphEnvironment -Environment $graphEnvironment -DirectoryTenantId $DirectoryTenantName -RefreshToken $refreshToken

        # Call Azure Stack Resource Manager to retrieve the list of registered applications which need to be initialized in the onboarding directory tenant
        Write-Host "Acquiring an access token to communicate with Resource Manager..."
        $armAccessToken = Get-ArmAccessToken $azureStackEnvironment

        Write-Host "Looking-up the current registered identity applications..."
        $subscription = Get-AzureRmSubscription -SubscriptionName "Default Provider Subscription" -TenantId $azureStackEnvironment.AdTenant
        $applicationRegistrationParams = @{
            Method  = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
            Headers = @{ Authorization = "Bearer $armAccessToken" }
            Uri     = "$($AdminResourceManagerEndpoint.ToString().TrimEnd('/'))/subscriptions/$($subscription.SubscriptionId)/resourceGroups/$("system.$Location")/providers/microsoft.subscriptions.providers/applicationRegistrations?api-version=2015-11-01"
        }
        $applicationRegistrations = Invoke-RestMethod @applicationRegistrationParams | Select -ExpandProperty value

        Write-Host "Processing '$($applicationRegistrations.Count)' application registrations... (this may take a few minutes)"
        $expectedRegistrations = Get-ExpectedApplicationRegistrationData $graphEnvironment $applicationRegistrations
        $appIds = Get-AppIds $applicationRegistrations
        Write-Verbose "Application IDs: $(ConvertTo-Json $appIds)" -Verbose
        function Get-AppName($appId) { if ($name = $appIds.GetEnumerator() | Where Value -eq $appId | Select -First 1 -ExpandProperty Name) {$name} else {$appId} }
        $anyChanges = $false
        foreach ($applicationRegistration in $applicationRegistrations) {
            if (-not ($expectedRegistration = $expectedRegistrations[$applicationRegistration.name])) {
                $anyChanges = $true
                $message = "Unexpected application registration '$($applicationRegistration.name)' found! [$(-not $Test)] Deleting this application registration..."
                Write-Warning $message
                Write-Verbose $message -Verbose
                if (-not $Test) {
                    $params = @{
                        Method  = [Microsoft.PowerShell.Commands.WebRequestMethod]::Delete
                        Headers = @{ Authorization = "Bearer $armAccessToken" }
                        Uri     = "$($AdminResourceManagerEndpoint.ToString().TrimEnd('/'))$($applicationRegistration.id)?api-version=2015-11-01"
                    }
                    $response = Invoke-RestMethod @params -Verbose -ErrorAction Stop
                }
                continue
            }

            $changes = $false
            $expectedAppRoleAssignments = $expectedRegistration.appRoleAssignments | Sort resource, client, roleId
            $actualAppRoleAssignments = $applicationRegistration.Properties.appRoleAssignments | Sort resource, client, roleId
            foreach ($expectedAppRoleAssignment in $expectedAppRoleAssignments) {
                if (-not ($actualAppRoleAssignment = $actualAppRoleAssignments | Where { ($_.resource -eq $expectedAppRoleAssignment.resource) -and ($_.client -eq $expectedAppRoleAssignment.client) -and ($_.roleId -eq $expectedAppRoleAssignment.roleId) })) {
                    $changes = $true
                    $message = "Adding missing permission to application '$($applicationRegistration.name)' [$(-not $Test)]: $($expectedAppRoleAssignment | Select @{n='resource';e={Get-AppName $_.resource}},@{n='client';e={Get-AppName $_.client}},@{n='roleId';e={$_.roleId}} | ConvertTo-Json -Compress)"
                    Write-Warning $message
                    Write-Verbose $message -Verbose
                }
            }
            foreach ($actualAppRoleAssignment in $actualAppRoleAssignments) {
                if (-not ($expectedAppRoleAssignment = $expectedAppRoleAssignments | Where { ($_.resource -eq $actualAppRoleAssignment.resource) -and ($_.client -eq $actualAppRoleAssignment.client) -and ($_.roleId -eq $actualAppRoleAssignment.roleId) })) {
                    $changes = $true
                    $message = "Removing extra permission from application '$($applicationRegistration.name)' [$(-not $Test)]: $($actualAppRoleAssignment | Select @{n='resource';e={Get-AppName $_.resource}},@{n='client';e={Get-AppName $_.client}},@{n='roleId';e={$_.roleId}} | ConvertTo-Json -Compress)"
                    Write-Warning $message
                    Write-Verbose $message -Verbose
                }
            }

            $expectedOAuth2PermissionGrants = $expectedRegistration.oAuth2PermissionGrants | Sort resource, client, scope
            $actualOAuth2PermissionGrants = $applicationRegistration.Properties.oAuth2PermissionGrants | Sort resource, client, scope
            foreach ($expectedOAuth2PermissionGrant in $expectedOAuth2PermissionGrants) {
                if (-not ($actualOAuth2PermissionGrant = $actualOAuth2PermissionGrants | Where { ($_.resource -eq $expectedOAuth2PermissionGrant.resource) -and ($_.client -eq $expectedOAuth2PermissionGrant.client) -and ($_.scope -eq $expectedOAuth2PermissionGrant.scope) })) {
                    $changes = $true
                    $message = "Adding missing permission to application '$($applicationRegistration.name)' [$(-not $Test)]: $($expectedOAuth2PermissionGrant | Select @{n='resource';e={Get-AppName $_.resource}},@{n='client';e={Get-AppName $_.client}},@{n='scope';e={$_.scope}} | ConvertTo-Json -Compress)"
                    Write-Warning $message
                    Write-Verbose $message -Verbose
                }
            }
            foreach ($actualOAuth2PermissionGrant in $actualOAuth2PermissionGrants) {
                if (-not ($expectedOAuth2PermissionGrant = $expectedOAuth2PermissionGrants | Where { ($_.resource -eq $actualOAuth2PermissionGrant.resource) -and ($_.client -eq $actualOAuth2PermissionGrant.client) -and ($_.scope -eq $actualOAuth2PermissionGrant.scope) })) {
                    $changes = $true
                    $message = "Removing extra permission from application '$($applicationRegistration.name)' [$(-not $Test)]: $($actualOAuth2PermissionGrant | Select @{n='resource';e={Get-AppName $_.resource}},@{n='client';e={Get-AppName $_.client}},@{n='scope';e={$_.scope}} | ConvertTo-Json -Compress)"
                    Write-Warning $message
                    Write-Verbose $message -Verbose
                }
            }

            if (-not $changes) {
                Write-Verbose "No changes required for application registration '$($applicationRegistration.name)'" -Verbose
            }
            elseif (-not $Test) {
                Write-Verbose "Updating application registration '$($applicationRegistration.name)'..." -Verbose
                $applicationRegistration.Properties.appRoleAssignments = $expectedRegistration.appRoleAssignments
                $applicationRegistration.Properties.oAuth2PermissionGrants = $expectedRegistration.oAuth2PermissionGrants
                if ($expectedRegistration.tags) { $applicationRegistration.Properties.tags = $expectedRegistration.tags }
                $params = @{
                    Method      = [Microsoft.PowerShell.Commands.WebRequestMethod]::Put
                    Headers     = @{ Authorization = "Bearer $armAccessToken" }
                    Uri         = "$($AdminResourceManagerEndpoint.ToString().TrimEnd('/'))$($applicationRegistration.id)?api-version=2015-11-01"
                    ContentType = 'application/json'
                    Body        = ConvertTo-Json $applicationRegistration -Depth 4 -Compress
                }
                $response = Invoke-RestMethod @params -Verbose -ErrorAction Stop
            }

            if ($changes) { $anyChanges = $true }
        }

        if (-not $anyChanges) {
            Write-Host "No required changes detected! The application registration resources are as expected!"
        }
        elseif ($Test) {
            Write-Warning "Changes to application registrations detected! After reviewing, please run this command again with the parameter '-Test:`$false' to apply the changes. Note that some reported changes might be expected if you are not on the latest version of Azure Stack."
        }
        else {
            Write-Host "All application registrations have been restored to their expected state!"
        }
    }

    function Initialize-AzureRmEnvironment([string]$environmentName) {
        $endpoints = Invoke-RestMethod -Method Get -Uri "$($AdminResourceManagerEndpoint.ToString().TrimEnd('/'))/metadata/endpoints?api-version=2015-01-01" -Verbose
        Write-Verbose -Message "Endpoints: $(ConvertTo-Json $endpoints)" -Verbose

        # resolve the directory tenant ID from the name
        $directoryTenantId = (New-Object uri(Invoke-RestMethod "$($endpoints.authentication.loginEndpoint.TrimEnd('/'))/$DirectoryTenantName/.well-known/openid-configuration").token_endpoint).AbsolutePath.Split('/')[1]

        $azureEnvironmentParams = @{
            Name                                     = $environmentName
            ActiveDirectoryEndpoint                  = $endpoints.authentication.loginEndpoint.TrimEnd('/') + "/"
            ActiveDirectoryServiceEndpointResourceId = $endpoints.authentication.audiences[0]
            AdTenant                                 = $directoryTenantId
            ResourceManagerEndpoint                  = $AdminResourceManagerEndpoint
            GalleryEndpoint                          = $endpoints.galleryEndpoint
            GraphEndpoint                            = $endpoints.graphEndpoint
            GraphAudience                            = $endpoints.graphEndpoint
        }

        $azureEnvironment = Add-AzureRmEnvironment @azureEnvironmentParams -ErrorAction Ignore
        $azureEnvironment = Get-AzureRmEnvironment -Name $environmentName -ErrorAction Stop

        return $azureEnvironment
    }

    function Initialize-AzureRmUserAccount([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureStackEnvironment) {
        $params = @{
            EnvironmentName = $azureStackEnvironment.Name
            TenantId        = $azureStackEnvironment.AdTenant
        }

        if ($AutomationCredential) {
            $params += @{ Credential = $AutomationCredential }
        }

        # Prompts the user for interactive login flow if automation credential is not specified
        $azureStackAccount = Add-AzureRmAccount @params

        # Retrieve the refresh token
        $tokens = @()
        $tokens += try { [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared.ReadItems()        } catch {}
        $tokens += try { [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems() } catch {}
        $refreshToken = $tokens |
            Where Resource -EQ $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId |
            Where IsMultipleResourceRefreshToken -EQ $true |
            Where DisplayableId -EQ $azureStackAccount.Context.Account.Id |
            Sort ExpiresOn |
            Select -Last 1 -ExpandProperty RefreshToken |
            ConvertTo-SecureString -AsPlainText -Force

        # Workaround due to regression in AzurePowerShell profile module which fails to populate the response object of "Add-AzureRmAccount" cmdlet
        if (-not $refreshToken) {
            if ($tokens.Count -eq 1) {
                Write-Warning "Failed to find target refresh token from Azure PowerShell Cache; attempting to reuse the single cached auth context..."
                $refreshToken = $tokens[0].RefreshToken | ConvertTo-SecureString -AsPlainText -Force
            }
            else {
                throw "Unable to find refresh token from Azure PowerShell Cache. Please try the command again in a fresh PowerShell instance after running 'Clear-AzureRmContext -Scope CurrentUser -Force -Verbose'."
            }
        }

        return $refreshToken
    }

    function Resolve-GraphEnvironment([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment) {
        $graphEnvironment = switch ($azureEnvironment.ActiveDirectoryAuthority) {
            'https://login.microsoftonline.com/' { 'AzureCloud'        }
            'https://login.chinacloudapi.cn/' { 'AzureChinaCloud'   }
            'https://login-us.microsoftonline.com/' { 'AzureUSGovernment' }
            'https://login.microsoftonline.de/' { 'AzureGermanCloud'  }

            Default { throw "Unsupported graph resource identifier: $_" }
        }

        return $graphEnvironment
    }

    function Get-ArmAccessToken([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureStackEnvironment) {
        $armAccessToken = $null
        $attempts = 0
        $maxAttempts = 12
        $delayInSeconds = 5
        do {
            try {
                $attempts++
                $armAccessToken = (Get-GraphToken -Resource $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId -UseEnvironmentData -ErrorAction Stop).access_token
            }
            catch {
                if ($attempts -ge $maxAttempts) {
                    throw
                }
                Write-Verbose "Error attempting to acquire ARM access token: $_`r`n$($_.Exception)" -Verbose
                Write-Verbose "Delaying for $delayInSeconds seconds before trying again... (attempt $attempts/$maxAttempts)" -Verbose
                Start-Sleep -Seconds $delayInSeconds
            }
        }
        while (-not $armAccessToken)

        return $armAccessToken
    }

    function Get-AppIds($applicationRegistrations) {
        $appIds = @{
            AzureCLI         = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
            Graph            = '00000002-0000-0000-c000-000000000000'
            PowerShell       = '1950a258-227b-4e31-a9cf-717495945fc2'
            VisualStudio     = '872cd9fa-d31f-45e0-9eab-6e460a02d1f1'
            VisualStudioCode = 'aebc6443-996d-45c2-90f0-388ff96faa56'
        }
        $applicationRegistrations | ForEach { $appIds[$_.name] = $_.Properties.appId }
        return $appIds
    }

    function Get-ExpectedApplicationRegistrationData($graphEnvironment, $applicationRegistrations) {
        $appIds = Get-AppIds $applicationRegistrations
        return @{
            AdminHubs              = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminHubs']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @()
            }
            AdminMonitoring        = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            AdminPolicy            = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminPolicy']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @()
            }
            AdminPortal            = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminPortal']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminPortal']
                        scope    = 'User.Read'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminPortal']
                        scope    = 'Directory.Read.All'
                    },
                    @{
                        resource = $appIds['AdminRbac']
                        client   = $appIds['AdminPortal']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVaultInternal']
                        client   = $appIds['AdminPortal']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['AdminPortal']
                        scope    = 'user_impersonation'
                    }
                )
            }
            AdminRbac              = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminRbac']
                        scope    = 'User.Read'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminRbac']
                        scope    = 'Directory.Read.All'
                    },
                    @{
                        resource = $appIds['AdminRbac']
                        client   = $appIds['PowerShell']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['AdminRbac']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminRbac']
                        client   = $appIds['AdminPortal']
                        scope    = 'user_impersonation'
                    }
                )
            }
            AdminResourceManager   = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminResourceManager']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminResourceManager']
                        scope    = 'Directory.Read.All'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminResourceManager']
                        scope    = 'Directory.AccessAsUser.All'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminResourceManager']
                        scope    = 'User.Read'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminResourceManager']
                        scope    = 'User.ReadBasic.All'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['AdminResourceManager']
                        scope    = 'User.Read.All'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['PowerShell']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['VisualStudio']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['AzureCLI']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['VisualStudioCode']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['AdminPortal']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['AdminResourceManager']
                        client   = $appIds['AdminRbac']
                        scope    = 'user_impersonation'
                    }
                )
                tags                   = @('MicrosoftAzureStack')
            }
            AzureMonitorOboService = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            AzureMonitorOnboardRP  = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            AzureStackBridge       = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            CRP                    = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            Deployment             = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Deployment']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Deployment']
                        roleId   = if ($graphEnvironment -eq 'AzureChinaCloud') { 'b55274d3-3582-44e3-83ae-ed7873d1111d' } else { '824c81eb-e3f8-4ee6-8f6d-de7f50d565b7' }
                    }
                )
                oAuth2PermissionGrants = @()
            }
            DeploymentProvider     = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['DeploymentProvider']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['DeploymentProvider']
                        roleId   = if ($graphEnvironment -eq 'AzureChinaCloud') { 'b55274d3-3582-44e3-83ae-ed7873d1111d' } else { '824c81eb-e3f8-4ee6-8f6d-de7f50d565b7' }
                    }
                )
                oAuth2PermissionGrants = @()
            }
            DiskRP                 = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            FRPProviders           = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            Hubs                   = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Hubs']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @()
            }
            IBC                    = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            KeyVault               = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['KeyVault']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['KeyVault']
                        client   = $appIds['Portal']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVault']
                        client   = $appIds['PowerShell']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVault']
                        client   = $appIds['VisualStudio']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVault']
                        client   = $appIds['VisualStudioCode']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVault']
                        client   = $appIds['AzureCLI']
                        scope    = 'user_impersonation'
                    }
                )
            }
            KeyVaultInternal       = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['KeyVaultInternal']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['KeyVaultInternal']
                        client   = $appIds['AdminPortal']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVaultInternal']
                        client   = $appIds['PowerShell']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVaultInternal']
                        client   = $appIds['VisualStudio']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVaultInternal']
                        client   = $appIds['VisualStudioCode']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVaultInternal']
                        client   = $appIds['AzureCLI']
                        scope    = 'user_impersonation'
                    }
                )
            }
            Monitoring             = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @()
            }
            Policy                 = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Policy']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @()
            }
            Portal                 = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Portal']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Portal']
                        scope    = 'User.Read'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Portal']
                        scope    = 'Directory.Read.All'
                    },
                    @{
                        resource = $appIds['Rbac']
                        client   = $appIds['Portal']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['KeyVault']
                        client   = $appIds['Portal']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['Portal']
                        scope    = 'user_impersonation'
                    }
                )
            }
            Rbac                   = @{
                appRoleAssignments     = @()
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Rbac']
                        scope    = 'User.Read'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['Rbac']
                        scope    = 'Directory.Read.All'
                    },
                    @{
                        resource = $appIds['Rbac']
                        client   = $appIds['PowerShell']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['Rbac']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['Rbac']
                        client   = $appIds['Portal']
                        scope    = 'user_impersonation'
                    }
                )
            }
            ResourceManager        = @{
                appRoleAssignments     = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['ResourceManager']
                        roleId   = '5778995a-e1bf-45b8-affa-663a9f3f4d04'
                    }
                )
                oAuth2PermissionGrants = @(
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['ResourceManager']
                        scope    = 'Directory.Read.All'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['ResourceManager']
                        scope    = 'Directory.AccessAsUser.All'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['ResourceManager']
                        scope    = 'User.Read'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['ResourceManager']
                        scope    = 'User.ReadBasic.All'
                    },
                    @{
                        resource = $appIds['Graph']
                        client   = $appIds['ResourceManager']
                        scope    = 'User.Read.All'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['PowerShell']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['VisualStudio']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['AzureCLI']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['VisualStudioCode']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['Rbac']
                        scope    = 'user_impersonation'
                    },
                    @{
                        resource = $appIds['ResourceManager']
                        client   = $appIds['Portal']
                        scope    = 'user_impersonation'
                    }
                )
                tags                   = @('MicrosoftAzureStack')
            }
        }
    }

    $logFile = Join-Path -Path $PSScriptRoot -ChildPath "Repair.$DirectoryTenantName.$(Get-Date -Format MM-dd_HH-mm-ss_ms).log"
    Write-Verbose "Logging additional information to log file '$logFile'" -Verbose

    $logStartMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Beginning invocation of '$($MyInvocation.InvocationName)' with parameters: $(ConvertTo-Json $PSBoundParameters -Depth 4)"
    $logStartMessage >> $logFile

    try {
        # Redirect verbose output to a log file
        Invoke-Main 4>> $logFile

        $logEndMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script completed successfully."
        $logEndMessage >> $logFile
    }
    catch {
        $logErrorMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script terminated with error: $_`r`n$($_.Exception)"
        $logErrorMessage >> $logFile
        Write-Warning "An error has occurred; more information may be found in the log file '$logFile'" -WarningAction Continue
        throw
    }
}

<#
.Synopsis
Adds a Guest Directory Tenant to Azure Stack.
.DESCRIPTION
Running this cmdlet will add the specified directory tenant to the Azure Stack whitelist.    
.EXAMPLE
$adminARMEndpoint = "https://adminmanagement.local.azurestack.external"
$azureStackDirectoryTenant = "<homeDirectoryTenant>.onmicrosoft.com"
$guestDirectoryTenantToBeOnboarded = "<guestDirectoryTenant>.onmicrosoft.com"

Register-AzsGuestDirectoryTenant -AdminResourceManagerEndpoint $adminARMEndpoint -DirectoryTenantName $azureStackDirectoryTenant -GuestDirectoryTenantName $guestDirectoryTenantToBeOnboarded
#>

function Register-AzsGuestDirectoryTenant {
    [CmdletBinding()]
    param
    (
        # The endpoint of the Azure Stack Resource Manager service.
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateScript( {$_.Scheme -eq [System.Uri]::UriSchemeHttps})]
        [uri] $AdminResourceManagerEndpoint,

        # The name of the home Directory Tenant in which the Azure Stack Administrator subscription resides.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $DirectoryTenantName,

        # The names of the guest Directory Tenants which are to be onboarded.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]] $GuestDirectoryTenantName,

        # The location of your Azure Stack deployment.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Location,

        # The identifier of the Administrator Subscription. If not specified, the script will attempt to use the set default subscription.
        [ValidateNotNull()]
        [string] $SubscriptionId = $null,

        # The display name of the Administrator Subscription. If not specified, the script will attempt to use the set default subscription.
        [ValidateNotNull()]
        [string] $SubscriptionName = $null,

        # The name of the resource group in which the directory tenant registration resource should be created (resource group must already exist).
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $null,

        # Optional: A credential used to authenticate with Azure Stack. Must support a non-interactive authentication flow. If not provided, the script will prompt for user credentials.
        [Parameter()]
        [ValidateNotNull()]
        [pscredential] $AutomationCredential = $null
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    # Install-Module AzureRm -RequiredVersion '1.2.11'
    Import-Module 'AzureRm.Profile' -Verbose:$false 4> $null

    function Invoke-Main {
        # Initialize the Azure PowerShell module to communicate with Azure Stack. Will prompt user for credentials.
        $azureEnvironment = Initialize-AzureRmEnvironment 'AzureStackAdmin'
        $azureAccount = Initialize-AzureRmUserAccount $azureEnvironment

        foreach ($directoryTenantName in $GuestDirectoryTenantName) {
            # Resolve the guest directory tenant ID from the name
            $directoryTenantId = (New-Object uri(Invoke-RestMethod "$($azureEnvironment.ActiveDirectoryAuthority.TrimEnd('/'))/$directoryTenantName/.well-known/openid-configuration").token_endpoint).AbsolutePath.Split('/')[1]

            # Add (or update) the new directory tenant to the Azure Stack deployment
            $params = @{
                ApiVersion        = '2015-11-01'
                ResourceType      = "Microsoft.Subscriptions.Admin/directoryTenants"
                ResourceGroupName = $ResourceGroupName
                ResourceName      = $directoryTenantName
                Location          = $Location
                Properties        = @{ tenantId = $directoryTenantId }
            }
            
            # Check if resource group exists, create it if it doesn't
            $rg = Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue
            if ($rg -eq $null) {
                New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue | Out-Null
            }
            
            $directoryTenant = New-AzureRmResource @params -Force -Verbose -ErrorAction Stop
            Write-Verbose -Message "Directory Tenant onboarded: $(ConvertTo-Json $directoryTenant)" -Verbose
        }
    }

    function Initialize-AzureRmEnvironment([string]$environmentName) {
        $endpoints = Invoke-RestMethod -Method Get -Uri "$($AdminResourceManagerEndpoint.ToString().TrimEnd('/'))/metadata/endpoints?api-version=2015-01-01" -Verbose
        Write-Verbose -Message "Endpoints: $(ConvertTo-Json $endpoints)" -Verbose

        # resolve the directory tenant ID from the name
        $directoryTenantId = (New-Object uri(Invoke-RestMethod "$($endpoints.authentication.loginEndpoint.TrimEnd('/'))/$DirectoryTenantName/.well-known/openid-configuration").token_endpoint).AbsolutePath.Split('/')[1]

        $azureEnvironmentParams = @{
            Name                                     = $environmentName
            ActiveDirectoryEndpoint                  = $endpoints.authentication.loginEndpoint.TrimEnd('/') + "/"
            ActiveDirectoryServiceEndpointResourceId = $endpoints.authentication.audiences[0]
            AdTenant                                 = $directoryTenantId
            ResourceManagerEndpoint                  = $AdminResourceManagerEndpoint
            GalleryEndpoint                          = $endpoints.galleryEndpoint
            GraphEndpoint                            = $endpoints.graphEndpoint
            GraphAudience                            = $endpoints.graphEndpoint
        }

        $azureEnvironment = Add-AzureRmEnvironment @azureEnvironmentParams -ErrorAction Ignore
        $azureEnvironment = Get-AzureRmEnvironment -Name $environmentName -ErrorAction Stop

        return $azureEnvironment
    }

    function Initialize-AzureRmUserAccount([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment) {
        $params = @{
            EnvironmentName = $azureEnvironment.Name
            TenantId        = $azureEnvironment.AdTenant
        }

        if ($AutomationCredential) {
            $params += @{ Credential = $AutomationCredential }
        }

        # Prompts the user for interactive login flow if automation credential is not specified
        #$DebugPreference = "Continue"
        $azureAccount = Add-AzureRmAccount @params

        if ($SubscriptionName) {
            Select-AzureRmSubscription -SubscriptionName $SubscriptionName | Out-Null
        }
        elseif ($SubscriptionId) {
            Select-AzureRmSubscription -SubscriptionId $SubscriptionId  | Out-Null
        }

        return $azureAccount
    }

    Invoke-Main
}

<#
.Synopsis
Consents to any missing permissions for Azure Stack identity applications in the home directory of Azure Stack.
.DESCRIPTION
Consents to any missing permissions for Azure Stack identity applications in the home directory of Azure Stack. This is needed to complete the "installation" of new Resource Provider identity applications in Azure Stack. 
.EXAMPLE
$adminResourceManagerEndpoint = "https://adminmanagement.local.azurestack.external"
$homeDirectoryTenantName = "<homeDirectoryTenant>.onmicrosoft.com"

Update-AzsHomeDirectoryTenant -AdminResourceManagerEndpoint $adminResourceManagerEndpoint `
    -DirectoryTenantName $homeDirectoryTenantName -Verbose
#>

function Update-AzsHomeDirectoryTenant {
    [CmdletBinding()]
    param
    (
        # The endpoint of the Azure Stack Resource Manager service.
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateScript( {$_.Scheme -eq [System.Uri]::UriSchemeHttps})]
        [uri] $AdminResourceManagerEndpoint,

        # The name of the home Directory Tenant in which the Azure Stack Administrator subscription resides.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $DirectoryTenantName,

        # Optional: A credential used to authenticate with Azure Stack. Must support a non-interactive authentication flow. If not provided, the script will prompt for user credentials.
        [Parameter()]
        [ValidateNotNull()]
        [pscredential] $AutomationCredential = $null
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    # Install-Module AzureRm
    Import-Module 'AzureRm.Profile' -Verbose:$false 4> $null
    Import-Module "$PSScriptRoot\GraphAPI\GraphAPI.psm1" -Verbose:$false 4> $null

    function Invoke-Main {
        # Initialize the Azure PowerShell module to communicate with the Azure Resource Manager in the public cloud corresponding to the Azure Stack Graph Service. Will prompt user for credentials.
        Write-Host "Authenticating user..."
        $azureStackEnvironment = Initialize-AzureRmEnvironment 'AzureStackAdmin'
        $refreshToken = Initialize-AzureRmUserAccount $azureStackEnvironment

        # Initialize the Graph PowerShell module to communicate with the correct graph service
        $graphEnvironment = Resolve-GraphEnvironment $azureStackEnvironment
        Initialize-GraphEnvironment -Environment $graphEnvironment -DirectoryTenantId $DirectoryTenantName -RefreshToken $refreshToken

        # Call Azure Stack Resource Manager to retrieve the list of registered applications which need to be initialized in the onboarding directory tenant
        Write-Host "Acquiring an access token to communicate with Resource Manager..."
        $armAccessToken = Get-ArmAccessToken $azureStackEnvironment

        Write-Host "Looking-up the registered identity applications which need to be installed in your directory..."
        $applicationRegistrationParams = @{
            Method  = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
            Headers = @{ Authorization = "Bearer $armAccessToken" }
            Uri     = "$($AdminResourceManagerEndpoint.ToString().TrimEnd('/'))/applicationRegistrations?api-version=2014-04-01-preview"
        }
        $applicationRegistrations = Invoke-RestMethod @applicationRegistrationParams | Select -ExpandProperty value

        # Identify which permissions have already been granted to each registered application and which additional permissions need to be granted
        $permissions = @()
        $count = 0
        foreach ($applicationRegistration in $applicationRegistrations) {
            # Initialize the service principal for the registered application
            $count++
            $applicationServicePrincipal = Initialize-GraphApplicationServicePrincipal -ApplicationId $applicationRegistration.appId
            Write-Host "Installing Application... ($($count) of $($applicationRegistrations.Count)): $($applicationServicePrincipal.appId) '$($applicationServicePrincipal.appDisplayName)'"

            # WORKAROUND - the recent Azure Stack update has a missing permission registration; temporarily "inject" this permission registration into the returned data
            if ($applicationServicePrincipal.servicePrincipalNames | Where { $_ -like 'https://deploymentprovider.*/*' }) {
                Write-Verbose "Adding missing permission registrations for application '$($applicationServicePrincipal.appDisplayName)' ($($applicationServicePrincipal.appId))..." -Verbose

                $graph = Get-GraphApplicationServicePrincipal -ApplicationId (Get-GraphEnvironmentInfo).Applications.WindowsAzureActiveDirectory.Id

                $applicationRegistration.appRoleAssignments = @(
                    [pscustomobject]@{
                        resource = (Get-GraphEnvironmentInfo).Applications.WindowsAzureActiveDirectory.Id
                        client   = $applicationRegistration.appId
                        roleId   = $graph.appRoles | Where value -EQ 'Directory.Read.All' | Select -ExpandProperty id
                    },

                    [pscustomobject]@{
                        resource = (Get-GraphEnvironmentInfo).Applications.WindowsAzureActiveDirectory.Id
                        client   = $applicationRegistration.appId
                        roleId   = $graph.appRoles | Where value -EQ 'Application.ReadWrite.OwnedBy' | Select -ExpandProperty id
                    }
                )
            }

            # Initialize the necessary tags for the registered application
            if ($applicationRegistration.tags) {
                Update-GraphApplicationServicePrincipalTags -ApplicationId $applicationRegistration.appId -Tags $applicationRegistration.tags
            }

            # Lookup the permission consent status for the *application* permissions (either to or from) which the registered application requires
            foreach ($appRoleAssignment in $applicationRegistration.appRoleAssignments) {
                $params = @{
                    ClientApplicationId   = $appRoleAssignment.client
                    ResourceApplicationId = $appRoleAssignment.resource
                    PermissionType        = 'Application'
                    PermissionId          = $appRoleAssignment.roleId
                }
                $permissions += New-GraphPermissionDescription @params -LookupConsentStatus
            }

            # Lookup the permission consent status for the *delegated* permissions (either to or from) which the registered application requires
            foreach ($oauth2PermissionGrant in $applicationRegistration.oauth2PermissionGrants) {
                $resourceApplicationServicePrincipal = Initialize-GraphApplicationServicePrincipal -ApplicationId $oauth2PermissionGrant.resource
                foreach ($scope in $oauth2PermissionGrant.scope.Split(' ')) {
                    $params = @{
                        ClientApplicationId                 = $oauth2PermissionGrant.client
                        ResourceApplicationServicePrincipal = $resourceApplicationServicePrincipal
                        PermissionType                      = 'Delegated'
                        PermissionId                        = ($resourceApplicationServicePrincipal.oauth2Permissions | Where value -EQ $scope).id
                    }
                    $permissions += New-GraphPermissionDescription @params -LookupConsentStatus
                }
            }
        }

        # Trace the permission status
        Write-Verbose "Current permission status: $($permissions | ConvertTo-Json -Depth 4)" -Verbose

        $permissionFile = Join-Path -Path $PSScriptRoot -ChildPath "$DirectoryTenantName.permissions.json"
        $permissionContent = $permissions | Select -Property * -ExcludeProperty isConsented | ConvertTo-Json -Depth 4 | Out-String
        $permissionContent > $permissionFile

        # Display application status to user
        $permissionsByClient = $permissions | Select *, @{n = 'Client'; e = {'{0} {1}' -f $_.clientApplicationId, $_.clientApplicationDisplayName}} | Sort clientApplicationDisplayName | Group Client
        $readyApplications = @()
        $pendingApplications = @()
        foreach ($client in $permissionsByClient) {
            if ($client.Group.isConsented -Contains $false) {
                $pendingApplications += $client
            }
            else {
                $readyApplications += $client
            }
        }

        Write-Host ""
        if ($readyApplications) {
            Write-Host "Applications installed and configured:"
            Write-Host "`t$($readyApplications.Name -join "`r`n`t")"
        }
        if ($readyApplications -and $pendingApplications) {
            Write-Host ""
        }
        if ($pendingApplications) {
            Write-Host "Applications waiting to be configured:"
            Write-Host "`t$($pendingApplications.Name -join "`r`n`t")"
        }
        Write-Host ""

        # Grant any missing permissions for registered applications
        if ($permissions | Where isConsented -EQ $false | Select -First 1) {
            Write-Host "Configuring applications... (this may take up to a few minutes to complete)"
            Write-Host ""
            $permissions | Where isConsented -EQ $false | Grant-GraphApplicationPermission
        }

        Write-Host "All applications installed and configured! Your home directory '$DirectoryTenantName' has been successfully updated to be used with Azure Stack!"
        Write-Host ""
        Write-Host "A more detailed description of the applications installed and with what permissions they have been configured can be found in the file '$permissionFile'."
        Write-Host "Run this script again at any time to check the status of the Azure Stack applications in your directory."
        Write-Warning "If your Azure Stack Administrator installs new services or updates in the future, you may need to run this script again."
    }

    function Initialize-AzureRmEnvironment([string]$environmentName) {
        $endpoints = Invoke-RestMethod -Method Get -Uri "$($AdminResourceManagerEndpoint.ToString().TrimEnd('/'))/metadata/endpoints?api-version=2015-01-01" -Verbose
        Write-Verbose -Message "Endpoints: $(ConvertTo-Json $endpoints)" -Verbose

        # resolve the directory tenant ID from the name
        $directoryTenantId = (New-Object uri(Invoke-RestMethod "$($endpoints.authentication.loginEndpoint.TrimEnd('/'))/$DirectoryTenantName/.well-known/openid-configuration").token_endpoint).AbsolutePath.Split('/')[1]

        $azureEnvironmentParams = @{
            Name                                     = $environmentName
            ActiveDirectoryEndpoint                  = $endpoints.authentication.loginEndpoint.TrimEnd('/') + "/"
            ActiveDirectoryServiceEndpointResourceId = $endpoints.authentication.audiences[0]
            AdTenant                                 = $directoryTenantId
            ResourceManagerEndpoint                  = $AdminResourceManagerEndpoint
            GalleryEndpoint                          = $endpoints.galleryEndpoint
            GraphEndpoint                            = $endpoints.graphEndpoint
            GraphAudience                            = $endpoints.graphEndpoint
        }

        $azureEnvironment = Add-AzureRmEnvironment @azureEnvironmentParams -ErrorAction Ignore
        $azureEnvironment = Get-AzureRmEnvironment -Name $environmentName -ErrorAction Stop

        return $azureEnvironment
    }

    function Initialize-AzureRmUserAccount([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureStackEnvironment) {
        $params = @{
            EnvironmentName = $azureStackEnvironment.Name
            TenantId        = $azureStackEnvironment.AdTenant
        }

        if ($AutomationCredential) {
            $params += @{ Credential = $AutomationCredential }
        }

        # Prompts the user for interactive login flow if automation credential is not specified
        $azureStackAccount = Add-AzureRmAccount @params

        # Retrieve the refresh token
        $tokens = @()
        $tokens += try { [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared.ReadItems()        } catch {}
        $tokens += try { [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems() } catch {}
        $refreshToken = $tokens |
            Where Resource -EQ $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId |
            Where IsMultipleResourceRefreshToken -EQ $true |
            Where DisplayableId -EQ $azureStackAccount.Context.Account.Id |
            Sort ExpiresOn |
            Select -Last 1 -ExpandProperty RefreshToken |
            ConvertTo-SecureString -AsPlainText -Force

        # Workaround due to regression in AzurePowerShell profile module which fails to populate the response object of "Add-AzureRmAccount" cmdlet
        if (-not $refreshToken) {
            if ($tokens.Count -eq 1) {
                Write-Warning "Failed to find target refresh token from Azure PowerShell Cache; attempting to reuse the single cached auth context..."
                $refreshToken = $tokens[0].RefreshToken | ConvertTo-SecureString -AsPlainText -Force
            }
            else {
                throw "Unable to find refresh token from Azure PowerShell Cache. Please try the command again in a fresh PowerShell instance after running 'Clear-AzureRmContext -Scope CurrentUser -Force -Verbose'."
            }
        }

        return $refreshToken
    }

    function Resolve-GraphEnvironment([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment) {
        $graphEnvironment = switch ($azureEnvironment.ActiveDirectoryAuthority) {
            'https://login.microsoftonline.com/' { 'AzureCloud'        }
            'https://login.chinacloudapi.cn/' { 'AzureChinaCloud'   }
            'https://login-us.microsoftonline.com/' { 'AzureUSGovernment' }
            'https://login.microsoftonline.de/' { 'AzureGermanCloud'  }

            Default { throw "Unsupported graph resource identifier: $_" }
        }

        return $graphEnvironment
    }

    function Get-ArmAccessToken([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureStackEnvironment) {
        $armAccessToken = $null
        $attempts = 0
        $maxAttempts = 12
        $delayInSeconds = 5
        do {
            try {
                $attempts++
                $armAccessToken = (Get-GraphToken -Resource $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId -UseEnvironmentData -ErrorAction Stop).access_token
            }
            catch {
                if ($attempts -ge $maxAttempts) {
                    throw
                }
                Write-Verbose "Error attempting to acquire ARM access token: $_`r`n$($_.Exception)" -Verbose
                Write-Verbose "Delaying for $delayInSeconds seconds before trying again... (attempt $attempts/$maxAttempts)" -Verbose
                Start-Sleep -Seconds $delayInSeconds
            }
        }
        while (-not $armAccessToken)

        return $armAccessToken
    }

    $logFile = Join-Path -Path $PSScriptRoot -ChildPath "$DirectoryTenantName.$(Get-Date -Format MM-dd_HH-mm-ss_ms).log"
    Write-Verbose "Logging additional information to log file '$logFile'" -Verbose

    $logStartMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Beginning invocation of '$($MyInvocation.InvocationName)' with parameters: $(ConvertTo-Json $PSBoundParameters -Depth 4)"
    $logStartMessage >> $logFile

    try {
        # Redirect verbose output to a log file
        Invoke-Main 4>> $logFile

        $logEndMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script completed successfully."
        $logEndMessage >> $logFile
    }
    catch {
        $logErrorMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script terminated with error: $_`r`n$($_.Exception)"
        $logErrorMessage >> $logFile
        Write-Warning "An error has occurred; more information may be found in the log file '$logFile'" -WarningAction Continue
        throw
    }
}

<#
.Synopsis
Consents to the given Azure Stack instance within the callers's Azure Directory Tenant.
.DESCRIPTION
Consents to the given Azure Stack instance within the callers's Azure Directory Tenant. This is needed to propagate Azure Stack applications into the user's directory tenant. 
.EXAMPLE
$tenantARMEndpoint = "https://management.local.azurestack.external"
$myDirectoryTenantName = "<guestDirectoryTenant>.onmicrosoft.com"

Register-AzsWithMyDirectoryTenant -TenantResourceManagerEndpoint $tenantARMEndpoint `
    -DirectoryTenantName $myDirectoryTenantName -Verbose -Debug
#>

function Register-AzsWithMyDirectoryTenant {
    [CmdletBinding()]
    param
    (
        # The endpoint of the Azure Stack Resource Manager service.
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateScript( {$_.Scheme -eq [System.Uri]::UriSchemeHttps})]
        [uri] $TenantResourceManagerEndpoint,

        # The name of the directory tenant being onboarded.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $DirectoryTenantName,

        # Optional: A credential used to authenticate with Azure Stack. Must support a non-interactive authentication flow. If not provided, the script will prompt for user credentials.
        [Parameter()]
        [ValidateNotNull()]
        [pscredential] $AutomationCredential = $null
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    # Install-Module AzureRm
    Import-Module 'AzureRm.Profile' -Verbose:$false 4> $null
    Import-Module "$PSScriptRoot\GraphAPI\GraphAPI.psm1" -Verbose:$false 4> $null

    function Invoke-Main {
        # Initialize the Azure PowerShell module to communicate with the Azure Resource Manager in the public cloud corresponding to the Azure Stack Graph Service. Will prompt user for credentials.
        Write-Host "Authenticating user..."
        $azureStackEnvironment = Initialize-AzureRmEnvironment 'AzureStack'
        $azureEnvironment = Resolve-AzureEnvironment $azureStackEnvironment
        $refreshToken = Initialize-AzureRmUserAccount $azureEnvironment $azureStackEnvironment.AdTenant

        # Initialize the Graph PowerShell module to communicate with the correct graph service
        $graphEnvironment = Resolve-GraphEnvironment $azureEnvironment
        Initialize-GraphEnvironment -Environment $graphEnvironment -DirectoryTenantId $DirectoryTenantName -RefreshToken $refreshToken

        # Initialize the service principal for the Azure Stack Resource Manager application
        Write-Host "Installing Resource Manager in your directory ('$DirectoryTenantName')..."
        $resourceManagerServicePrincipal = Initialize-ResourceManagerServicePrincipal

        # Authorize the Azure Powershell module to act as a client to call the Azure Stack Resource Manager in the onboarding directory tenant
        Write-Host "Authorizing the Azure PowerShell module to communicate with Resource Manager in your directory..."
        Initialize-GraphOAuth2PermissionGrant -ClientApplicationId (Get-GraphEnvironmentInfo).Applications.PowerShell.Id -ResourceApplicationIdentifierUri $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId

        # Call Azure Stack Resource Manager to retrieve the list of registered applications which need to be initialized in the onboarding directory tenant
        Write-Host "Acquiring an access token to communicate with Resource Manager... (this may take up to a few minutes to complete)"
        $armAccessToken = Get-ArmAccessToken $azureStackEnvironment

        Write-Host "Looking-up the registered identity applications which need to be installed in your directory..."
        $applicationRegistrationParams = @{
            Method  = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
            Headers = @{ Authorization = "Bearer $armAccessToken" }
            Uri     = "$($TenantResourceManagerEndpoint.ToString().TrimEnd('/'))/applicationRegistrations?api-version=2014-04-01-preview"
        }
        $applicationRegistrations = Invoke-RestMethod @applicationRegistrationParams | Select -ExpandProperty value

        # Identify which permissions have already been granted to each registered application and which additional permissions need to be granted
        $permissions = @()
        $count = 0
        foreach ($applicationRegistration in $applicationRegistrations) {
            # Initialize the service principal for the registered application
            $count++
            $applicationServicePrincipal = Initialize-GraphApplicationServicePrincipal -ApplicationId $applicationRegistration.appId
            Write-Host "Installing Application... ($($count) of $($applicationRegistrations.Count)): $($applicationServicePrincipal.appId) '$($applicationServicePrincipal.appDisplayName)'"

            # Initialize the necessary tags for the registered application
            if ($applicationRegistration.tags) {
                Update-GraphApplicationServicePrincipalTags -ApplicationId $applicationRegistration.appId -Tags $applicationRegistration.tags
            }

            # Lookup the permission consent status for the *application* permissions (either to or from) which the registered application requires
            foreach ($appRoleAssignment in $applicationRegistration.appRoleAssignments) {
                $params = @{
                    ClientApplicationId   = $appRoleAssignment.client
                    ResourceApplicationId = $appRoleAssignment.resource
                    PermissionType        = 'Application'
                    PermissionId          = $appRoleAssignment.roleId
                }
                $permissions += New-GraphPermissionDescription @params -LookupConsentStatus
            }

            # Lookup the permission consent status for the *delegated* permissions (either to or from) which the registered application requires
            foreach ($oauth2PermissionGrant in $applicationRegistration.oauth2PermissionGrants) {
                $resourceApplicationServicePrincipal = Initialize-GraphApplicationServicePrincipal -ApplicationId $oauth2PermissionGrant.resource
                foreach ($scope in $oauth2PermissionGrant.scope.Split(' ')) {
                    $params = @{
                        ClientApplicationId                 = $oauth2PermissionGrant.client
                        ResourceApplicationServicePrincipal = $resourceApplicationServicePrincipal
                        PermissionType                      = 'Delegated'
                        PermissionId                        = ($resourceApplicationServicePrincipal.oauth2Permissions | Where value -EQ $scope).id
                    }
                    $permissions += New-GraphPermissionDescription @params -LookupConsentStatus
                }
            }
        }

        # Trace the permission status
        Write-Verbose "Current permission status: $($permissions | ConvertTo-Json -Depth 4)" -Verbose

        $permissionFile = Join-Path -Path $PSScriptRoot -ChildPath "$DirectoryTenantName.permissions.json"
        $permissionContent = $permissions | Select -Property * -ExcludeProperty isConsented | ConvertTo-Json -Depth 4 | Out-String
        $permissionContent > $permissionFile

        # Display application status to user
        $permissionsByClient = $permissions | Select *, @{n = 'Client'; e = {'{0} {1}' -f $_.clientApplicationId, $_.clientApplicationDisplayName}} | Sort clientApplicationDisplayName | Group Client
        $readyApplications = @()
        $pendingApplications = @()
        foreach ($client in $permissionsByClient) {
            if ($client.Group.isConsented -Contains $false) {
                $pendingApplications += $client
            }
            else {
                $readyApplications += $client
            }
        }

        Write-Host ""
        if ($readyApplications) {
            Write-Host "Applications installed and configured:"
            Write-Host "`t$($readyApplications.Name -join "`r`n`t")"
        }
        if ($readyApplications -and $pendingApplications) {
            Write-Host ""
        }
        if ($pendingApplications) {
            Write-Host "Applications waiting to be configured:"
            Write-Host "`t$($pendingApplications.Name -join "`r`n`t")"
        }
        Write-Host ""

        # Grant any missing permissions for registered applications
        if ($permissions | Where isConsented -EQ $false | Select -First 1) {
            Write-Host "Configuring applications... (this may take up to a few minutes to complete)"
            Write-Host ""
            $permissions | Where isConsented -EQ $false | Grant-GraphApplicationPermission
        }

        Write-Host "All applications installed and configured! Your directory '$DirectoryTenantName' has been successfully onboarded and can now be used with Azure Stack!"
        Write-Host ""
        Write-Host "A more detailed description of the applications installed and with what permissions they have been configured can be found in the file '$permissionFile'."
        Write-Host "Run this script again at any time to check the status of the Azure Stack applications in your directory."
        Write-Warning "If your Azure Stack Administrator installs new services or updates in the future, you may need to run this script again."
    }

    function Initialize-AzureRmEnvironment([string]$environmentName) {
        $endpoints = Invoke-RestMethod -Method Get -Uri "$($TenantResourceManagerEndpoint.ToString().TrimEnd('/'))/metadata/endpoints?api-version=2015-01-01" -Verbose
        Write-Verbose -Message "Endpoints: $(ConvertTo-Json $endpoints)" -Verbose

        # resolve the directory tenant ID from the name
        $directoryTenantId = (New-Object uri(Invoke-RestMethod "$($endpoints.authentication.loginEndpoint.TrimEnd('/'))/$DirectoryTenantName/.well-known/openid-configuration").token_endpoint).AbsolutePath.Split('/')[1]

        $azureEnvironmentParams = @{
            Name                                     = $environmentName
            ActiveDirectoryEndpoint                  = $endpoints.authentication.loginEndpoint.TrimEnd('/') + "/"
            ActiveDirectoryServiceEndpointResourceId = $endpoints.authentication.audiences[0]
            AdTenant                                 = $directoryTenantId
            ResourceManagerEndpoint                  = $TenantResourceManagerEndpoint
            GalleryEndpoint                          = $endpoints.galleryEndpoint
            GraphEndpoint                            = $endpoints.graphEndpoint
            GraphAudience                            = $endpoints.graphEndpoint
        }

        $azureEnvironment = Add-AzureRmEnvironment @azureEnvironmentParams -ErrorAction Ignore
        $azureEnvironment = Get-AzureRmEnvironment -Name $environmentName -ErrorAction Stop

        return $azureEnvironment
    }

    function Resolve-AzureEnvironment([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureStackEnvironment) {
        $azureEnvironment = Get-AzureRmEnvironment |
            Where GraphEndpointResourceId -EQ $azureStackEnvironment.GraphEndpointResourceId |
            Where Name -In @('AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment', 'AzureGermanCloud')

        # Differentiate between AzureCloud and AzureUSGovernment
        if ($azureEnvironment.Count -ge 2) {
            $name = if ($azureStackEnvironment.ActiveDirectoryAuthority -eq 'https://login-us.microsoftonline.com/') { 'AzureUSGovernment' } else { 'AzureCloud' }
            $azureEnvironment = $azureEnvironment | Where Name -EQ $name
        }

        return $azureEnvironment
    }

    function Initialize-AzureRmUserAccount([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment, [string]$directoryTenantId) {
        $params = @{
            EnvironmentName = $azureEnvironment.Name
            TenantId        = $directoryTenantId
        }

        if ($AutomationCredential) {
            $params += @{ Credential = $AutomationCredential }
        }

        # Prompts the user for interactive login flow if automation credential is not specified
        $azureAccount = Add-AzureRmAccount @params

        # Retrieve the refresh token
        $tokens = @()
        $tokens += try { [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared.ReadItems()        } catch {}
        $tokens += try { [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems() } catch {}
        $refreshToken = $tokens |
            Where Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId |
            Where IsMultipleResourceRefreshToken -EQ $true |
            Where DisplayableId -EQ $azureAccount.Context.Account.Id |
            Sort ExpiresOn |
            Select -Last 1 -ExpandProperty RefreshToken |
            ConvertTo-SecureString -AsPlainText -Force

        # Workaround due to regression in AzurePowerShell profile module which fails to populate the response object of "Add-AzureRmAccount" cmdlet
        if (-not $refreshToken) {
            if ($tokens.Count -eq 1) {
                Write-Warning "Failed to find target refresh token from Azure PowerShell Cache; attempting to reuse the single cached auth context..."
                $refreshToken = $tokens[0].RefreshToken | ConvertTo-SecureString -AsPlainText -Force
            }
            else {
                throw "Unable to find refresh token from Azure PowerShell Cache. Please try the command again in a fresh PowerShell instance after running 'Clear-AzureRmContext -Scope CurrentUser -Force -Verbose'."
            }
        }

        return $refreshToken
    }

    function Resolve-GraphEnvironment([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment) {
        $graphEnvironment = switch ($azureEnvironment.ActiveDirectoryAuthority) {
            'https://login.microsoftonline.com/' { 'AzureCloud'        }
            'https://login.chinacloudapi.cn/' { 'AzureChinaCloud'   }
            'https://login-us.microsoftonline.com/' { 'AzureUSGovernment' }
            'https://login.microsoftonline.de/' { 'AzureGermanCloud'  }

            Default { throw "Unsupported graph resource identifier: $_" }
        }

        return $graphEnvironment
    }

    function Initialize-ResourceManagerServicePrincipal {
        $identityInfo = Invoke-RestMethod -Method Get -Uri "$($TenantResourceManagerEndpoint.ToString().TrimEnd('/'))/metadata/identity?api-version=2015-01-01" -Verbose
        Write-Verbose -Message "Resource Manager identity information: $(ConvertTo-Json $identityInfo)" -Verbose

        $resourceManagerServicePrincipal = Initialize-GraphApplicationServicePrincipal -ApplicationId $identityInfo.applicationId -Verbose

        return $resourceManagerServicePrincipal
    }

    function Get-ArmAccessToken([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureStackEnvironment) {
        $armAccessToken = $null
        $attempts = 0
        $maxAttempts = 12
        $delayInSeconds = 5
        do {
            try {
                $attempts++
                $armAccessToken = (Get-GraphToken -Resource $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId -UseEnvironmentData -ErrorAction Stop).access_token
            }
            catch {
                if ($attempts -ge $maxAttempts) {
                    throw
                }
                Write-Verbose "Error attempting to acquire ARM access token: $_`r`n$($_.Exception)" -Verbose
                Write-Verbose "Delaying for $delayInSeconds seconds before trying again... (attempt $attempts/$maxAttempts)" -Verbose
                Start-Sleep -Seconds $delayInSeconds
            }
        }
        while (-not $armAccessToken)

        return $armAccessToken
    }

    $logFile = Join-Path -Path $PSScriptRoot -ChildPath "$DirectoryTenantName.$(Get-Date -Format MM-dd_HH-mm-ss_ms).log"
    Write-Verbose "Logging additional information to log file '$logFile'" -Verbose

    $logStartMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Beginning invocation of '$($MyInvocation.InvocationName)' with parameters: $(ConvertTo-Json $PSBoundParameters -Depth 4)"
    $logStartMessage >> $logFile

    try {
        # Redirect verbose output to a log file
        Invoke-Main 4>> $logFile

        $logEndMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script completed successfully."
        $logEndMessage >> $logFile
    }
    catch {
        $logErrorMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script terminated with error: $_`r`n$($_.Exception)"
        $logErrorMessage >> $logFile
        Write-Warning "An error has occurred; more information may be found in the log file '$logFile'" -WarningAction Continue
        throw
    }
}

<#
.Synopsis
Removes a Guest Directory Tenant from Azure Stack.
.DESCRIPTION
Running this cmdlet will remove the specified directory tenant from the Azure Stack whitelist.
Ensure an Admin of the directory tenant has already run "Unregister-AzsWithMyDirectoryTenant" or they will be unable to
complete that cleanup of their directory tenant (this cmdlet will remove the permissions they need to query Azure Stack to determine what to delete).
.EXAMPLE
$adminARMEndpoint = "https://adminmanagement.local.azurestack.external"
$azureStackDirectoryTenant = "<homeDirectoryTenant>.onmicrosoft.com"
$guestDirectoryTenantToBeOnboarded = "<guestDirectoryTenant>.onmicrosoft.com"

Unregister-AzsGuestDirectoryTenant -AdminResourceManagerEndpoint $adminARMEndpoint -DirectoryTenantName $azureStackDirectoryTenant -GuestDirectoryTenantName $guestDirectoryTenantToBeOnboarded
#>

function Unregister-AzsGuestDirectoryTenant {
    [CmdletBinding()]
    param
    (
        # The endpoint of the Azure Stack Resource Manager service.
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateScript( {$_.Scheme -eq [System.Uri]::UriSchemeHttps})]
        [uri] $AdminResourceManagerEndpoint,

        # The name of the home Directory Tenant in which the Azure Stack Administrator subscription resides.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $DirectoryTenantName,

        # The name of the guest Directory Tenant which is to be decommissioned.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $GuestDirectoryTenantName,

        # The name of the resource group in which the directory tenant resource was created.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $null,

        # The identifier of the Administrator Subscription. If not specified, the script will attempt to use the set default subscription.
        [Parameter()]
        [ValidateNotNull()]
        [string] $SubscriptionId = $null,

        # The display name of the Administrator Subscription. If not specified, the script will attempt to use the set default subscription.
        [Parameter()]
        [ValidateNotNull()]
        [string] $SubscriptionName = $null,

        # Optional: A credential used to authenticate with Azure Stack. Must support a non-interactive authentication flow. If not provided, the script will prompt for user credentials.
        [Parameter()]
        [ValidateNotNull()]
        [pscredential] $AutomationCredential = $null
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $ResourceManagerEndpoint = $AdminResourceManagerEndpoint

    # Install-Module AzureRm
    Import-Module 'AzureRm.Profile' -Verbose:$false 4> $null

    function Invoke-Main {
        Write-DecommissionImplicationsWarning

        # Initialize the Azure PowerShell module to communicate with Azure Stack. Will prompt user for credentials.
        $azureEnvironment = Initialize-AzureRmEnvironment 'AzureStackAdmin'
        $azureAccount = Initialize-AzureRmUserAccount $azureEnvironment

        # Remove the new directory tenant to the Azure Stack deployment
        $params = @{
            ResourceId = "/subscriptions/$($azureAccount.Context.Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Subscriptions.Admin/directoryTenants/$GuestDirectoryTenantName"
            ApiVersion = '2015-11-01'
        }
        $output = Remove-AzureRmResource @params -Force -Verbose -ErrorAction Stop
        Write-Verbose -Message "Directory Tenant decommissioned: $($params.ResourceId)" -Verbose
    }

    function Initialize-AzureRmEnvironment([string]$environmentName) {
        $endpoints = Invoke-RestMethod -Method Get -Uri "$($ResourceManagerEndpoint.ToString().TrimEnd('/'))/metadata/endpoints?api-version=2015-01-01" -Verbose
        Write-Verbose -Message "Endpoints: $(ConvertTo-Json $endpoints)" -Verbose

        # resolve the directory tenant ID from the name
        $directoryTenantId = (New-Object uri(Invoke-RestMethod "$($endpoints.authentication.loginEndpoint.TrimEnd('/'))/$DirectoryTenantName/.well-known/openid-configuration").token_endpoint).AbsolutePath.Split('/')[1]

        $azureEnvironmentParams = @{
            Name                                     = $environmentName
            ActiveDirectoryEndpoint                  = $endpoints.authentication.loginEndpoint.TrimEnd('/') + "/"
            ActiveDirectoryServiceEndpointResourceId = $endpoints.authentication.audiences[0]
            AdTenant                                 = $directoryTenantId
            ResourceManagerEndpoint                  = $ResourceManagerEndpoint
            GalleryEndpoint                          = $endpoints.galleryEndpoint
            GraphEndpoint                            = $endpoints.graphEndpoint
            GraphAudience                            = $endpoints.graphEndpoint
        }

        $azureEnvironment = Add-AzureRmEnvironment @azureEnvironmentParams -ErrorAction Ignore
        $azureEnvironment = Get-AzureRmEnvironment -Name $environmentName -ErrorAction Stop

        return $azureEnvironment
    }

    function Initialize-AzureRmUserAccount([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment) {
        $params = @{
            EnvironmentName = $azureEnvironment.Name
            TenantId        = $azureEnvironment.AdTenant
        }

        if ($AutomationCredential) {
            $params += @{ Credential = $AutomationCredential }
        }

        # Prompts the user for interactive login flow if automation credential is not specified
        $azureAccount = Add-AzureRmAccount @params

        if ($SubscriptionName) {
            Select-AzureRmSubscription -SubscriptionName $SubscriptionName | Out-Null
        }
        elseif ($SubscriptionId) {
            Select-AzureRmSubscription -SubscriptionId $SubscriptionId  | Out-Null
        }

        return $azureAccount
    }

    function Write-DecommissionImplicationsWarning {
        $params = @{
            Message       = ''
            WarningAction = 'Inquire'
        }
        $params.Message += 'You are removing a directory tenant from your Azure Stack deployment.'
        $params.Message += ' Users in this directory will be unable to access or manage any existing subscriptions (access to any existing resources may be impaired if they require identity integration).'
        $params.Message += " Additionally, you should first ensure that an Administrator of the directory '$directoryTenantName' has completed their decommissioning process before removing this access"
        $params.Message += ' (they will need to query your Azure Stack deployment to see which identities need to be removed from their directory).'

        if ($AutomationCredential) {
            $params.WarningAction = 'Continue'
        }
        else {
            $params.Message += " Would you like to proceed?"
        }

        Write-Warning @params
    }

    Invoke-Main
}

<#
.Synopsis
Removes the installed Azure Stack identity applications and their permissions within the callers's Azure Directory Tenant.
.DESCRIPTION
Removes the installed Azure Stack identity applications and their permissions within the callers's Azure Directory Tenant.
.EXAMPLE
$tenantARMEndpoint = "https://management.local.azurestack.external"
$myDirectoryTenantName = "<guestDirectoryTenant>.onmicrosoft.com"

Unregister-AzsWithMyDirectoryTenant -TenantResourceManagerEndpoint $tenantARMEndpoint `
    -DirectoryTenantName $myDirectoryTenantName -Verbose -Debug
#>

function Unregister-AzsWithMyDirectoryTenant {
    [CmdletBinding()]
    param
    (
        # The endpoint of the Azure Stack Resource Manager service.
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateScript( {$_.Scheme -eq [System.Uri]::UriSchemeHttps})]
        [uri] $TenantResourceManagerEndpoint,

        # The name of the directory tenant being onboarded.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $DirectoryTenantName,

        # Optional: A credential used to authenticate with Azure Stack. Must support a non-interactive authentication flow. If not provided, the script will prompt for user credentials.
        [Parameter()]
        [ValidateNotNull()]
        [pscredential] $AutomationCredential = $null
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = 'Continue'

    $ResourceManagerEndpoint = $TenantResourceManagerEndpoint
    
    # Install-Module AzureRm
    Import-Module 'AzureRm.Profile' -Verbose:$false 4> $null
    Import-Module "$PSScriptRoot\GraphAPI\GraphAPI.psm1" -Verbose:$false 4> $null
    
    function Invoke-Main {
        Write-DecommissionImplicationsWarning
    
        # Initialize the Azure PowerShell module to communicate with the Azure Resource Manager in the public cloud corresponding to the Azure Stack Graph Service. Will prompt user for credentials.
        Write-Host "Authenticating user..."
        $azureStackEnvironment = Initialize-AzureRmEnvironment 'AzureStack'
        $azureEnvironment = Resolve-AzureEnvironment $azureStackEnvironment
        $refreshToken = Initialize-AzureRmUserAccount $azureEnvironment $azureStackEnvironment.AdTenant
    
        # Initialize the Graph PowerShell module to communicate with the correct graph service
        $graphEnvironment = Resolve-GraphEnvironment $azureEnvironment
        Initialize-GraphEnvironment -Environment $graphEnvironment -DirectoryTenantId $DirectoryTenantName -RefreshToken $refreshToken
    
        # Call Azure Stack Resource Manager to retrieve the list of registered applications which need to be removed from the directory tenant
        Write-Host "Acquiring an access token to communicate with Resource Manager... (if you already decommissioned this directory you may get an error here which you can ignore)"
        $armAccessToken = (Get-GraphToken -Resource $azureStackEnvironment.ActiveDirectoryServiceEndpointResourceId -UseEnvironmentData -ErrorAction Stop).access_token
    
        Write-Host "Looking-up the registered identity applications which need to be uninstalled from your directory..."
        $applicationRegistrationParams = @{
            Method  = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
            Headers = @{ Authorization = "Bearer $armAccessToken" }
            Uri     = "$($ResourceManagerEndpoint.ToString().TrimEnd('/'))/applicationRegistrations?api-version=2014-04-01-preview"
        }
        $applicationRegistrations = Invoke-RestMethod @applicationRegistrationParams | Select -ExpandProperty value
    
        # Delete the service principals for the registered applications
        foreach ($applicationRegistration in $applicationRegistrations) {
            if (($applicationServicePrincipal = Get-GraphApplicationServicePrincipal -ApplicationId $applicationRegistration.appId -ErrorAction Continue)) {
                Write-Verbose "Uninstalling service principal: $(ConvertTo-Json $applicationServicePrincipal)" -Verbose
                Remove-GraphObject -objectId $applicationServicePrincipal.objectId
                Write-Host "Application '$($applicationServicePrincipal.appId)' ($($applicationServicePrincipal.appDisplayName)) was successfully uninstalled from your directory."
            }
            else {
                Write-Host "Application '$($applicationRegistration.appId)' is not installed or was already successfully uninstalled from your directory."
            }
        }
    
        Write-Host "All Azure Stack applications have been uninstalled! Your directory '$DirectoryTenantName' has been successfully decommissioned and can no-longer be used with Azure Stack."
    }
    
    function Initialize-AzureRmEnvironment([string]$environmentName) {
        $endpoints = Invoke-RestMethod -Method Get -Uri "$($ResourceManagerEndpoint.ToString().TrimEnd('/'))/metadata/endpoints?api-version=2015-01-01" -Verbose
        Write-Verbose -Message "Endpoints: $(ConvertTo-Json $endpoints)" -Verbose
    
        # resolve the directory tenant ID from the name
        $directoryTenantId = (New-Object uri(Invoke-RestMethod "$($endpoints.authentication.loginEndpoint.TrimEnd('/'))/$DirectoryTenantName/.well-known/openid-configuration").token_endpoint).AbsolutePath.Split('/')[1]
    
        $azureEnvironmentParams = @{
            Name                                     = $environmentName
            ActiveDirectoryEndpoint                  = $endpoints.authentication.loginEndpoint.TrimEnd('/') + "/"
            ActiveDirectoryServiceEndpointResourceId = $endpoints.authentication.audiences[0]
            AdTenant                                 = $directoryTenantId
            ResourceManagerEndpoint                  = $ResourceManagerEndpoint
            GalleryEndpoint                          = $endpoints.galleryEndpoint
            GraphEndpoint                            = $endpoints.graphEndpoint
            GraphAudience                            = $endpoints.graphEndpoint
        }
    
        $azureEnvironment = Add-AzureRmEnvironment @azureEnvironmentParams -ErrorAction Ignore
        $azureEnvironment = Get-AzureRmEnvironment -Name $environmentName -ErrorAction Stop
    
        return $azureEnvironment
    }
    
    function Resolve-AzureEnvironment([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureStackEnvironment) {
        $azureEnvironment = Get-AzureRmEnvironment |
            Where GraphEndpointResourceId -EQ $azureStackEnvironment.GraphEndpointResourceId |
            Where Name -In @('AzureCloud', 'AzureChinaCloud', 'AzureUSGovernment', 'AzureGermanCloud')
    
        # Differentiate between AzureCloud and AzureUSGovernment
        if ($azureEnvironment.Count -ge 2) {
            $name = if ($azureStackEnvironment.ActiveDirectoryAuthority -eq 'https://login-us.microsoftonline.com/') { 'AzureUSGovernment' } else { 'AzureCloud' }
            $azureEnvironment = $azureEnvironment | Where Name -EQ $name
        }
    
        return $azureEnvironment
    }
    
    function Initialize-AzureRmUserAccount([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment, [string]$directoryTenantId) {
        $params = @{
            EnvironmentName = $azureEnvironment.Name
            TenantId        = $directoryTenantId
        }
    
        if ($AutomationCredential) {
            $params += @{ Credential = $AutomationCredential }
        }
    
        # Prompts the user for interactive login flow if automation credential is not specified
        $azureAccount = Add-AzureRmAccount @params
    
        # Retrieve the refresh token
        $tokens = @()
        $tokens += try { [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared.ReadItems()        } catch {}
        $tokens += try { [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.TokenCache.ReadItems() } catch {}
        $refreshToken = $tokens |
            Where Resource -EQ $azureEnvironment.ActiveDirectoryServiceEndpointResourceId |
            Where IsMultipleResourceRefreshToken -EQ $true |
            Where DisplayableId -EQ $azureAccount.Context.Account.Id |
            Sort ExpiresOn |
            Select -Last 1 -ExpandProperty RefreshToken |
            ConvertTo-SecureString -AsPlainText -Force

        # Workaround due to regression in AzurePowerShell profile module which fails to populate the response object of "Add-AzureRmAccount" cmdlet
        if (-not $refreshToken) {
            if ($tokens.Count -eq 1) {
                Write-Warning "Failed to find target refresh token from Azure PowerShell Cache; attempting to reuse the single cached auth context..."
                $refreshToken = $tokens[0].RefreshToken | ConvertTo-SecureString -AsPlainText -Force
            }
            else {
                throw "Unable to find refresh token from Azure PowerShell Cache. Please try the command again in a fresh PowerShell instance after running 'Clear-AzureRmContext -Scope CurrentUser -Force -Verbose'."
            }
        }

        return $refreshToken
    }
    
    function Resolve-GraphEnvironment([Microsoft.Azure.Commands.Profile.Models.PSAzureEnvironment]$azureEnvironment) {
        $graphEnvironment = switch ($azureEnvironment.ActiveDirectoryAuthority) {
            'https://login.microsoftonline.com/' { 'AzureCloud'        }
            'https://login.chinacloudapi.cn/' { 'AzureChinaCloud'   }
            'https://login-us.microsoftonline.com/' { 'AzureUSGovernment' }
            'https://login.microsoftonline.de/' { 'AzureGermanCloud'  }
    
            Default { throw "Unsupported graph resource identifier: $_" }
        }
    
        return $graphEnvironment
    }
    
    function Write-DecommissionImplicationsWarning {
        $params = @{
            Message       = ''
            WarningAction = 'Inquire'
        }
        $params.Message += 'You are removing access from an Azure Stack deployment to your directory tenant.'
        $params.Message += ' Users in your directory will be unable to access or manage any existing subscriptions in the Azure Stack deployment (access to any existing resources may be impaired if they require identity integration).'
    
        if ($AutomationCredential) {
            $params.WarningAction = 'Continue'
        }
        else {
            $params.Message += " Would you like to proceed?"
        }
    
        Write-Warning @params
    }
    
    $logFile = Join-Path -Path $PSScriptRoot -ChildPath "$DirectoryTenantName.$(Get-Date -Format MM-dd_HH-mm-ss_ms).log"
    Write-Verbose "Logging additional information to log file '$logFile'" -Verbose
    
    $logStartMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Beginning invocation of '$($MyInvocation.InvocationName)' with parameters: $(ConvertTo-Json $PSBoundParameters -Depth 4)"
    $logStartMessage >> $logFile
    
    try {
        # Redirect verbose output to a log file
        Invoke-Main 4>> $logFile
    
        $logEndMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script completed successfully."
        $logEndMessage >> $logFile
    }
    catch {
        $logErrorMessage = "[$(Get-Date -Format 'hh:mm:ss tt')] - Script terminated with error: $_`r`n$($_.Exception)"
        $logErrorMessage >> $logFile
        Write-Warning "An error has occurred; more information may be found in the log file '$logFile'" -WarningAction Continue
        throw
    }
}

Export-ModuleMember -Function @(
    "Repair-AzsApplicationRegistrations",
    "Update-AzsHomeDirectoryTenant",
    "Register-AzsGuestDirectoryTenant",
    "Register-AzsWithMyDirectoryTenant",
    "Unregister-AzsWithMyDirectoryTenant",
    "Unregister-AzsGuestDirectoryTenant",
    "Get-AzsDirectoryTenantidentifier",
    "New-AzsADGraphServicePrincipal"
)
