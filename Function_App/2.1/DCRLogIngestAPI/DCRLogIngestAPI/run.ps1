#DCR/DCE Function App

<#
.SYNOPSIS
Function App for uploading DCR/DCE based content instead of using the legacy HTTP API.
Can be ran locally via Visual Studio Code if a proper App Registration / Secret is provided. App reg and secret not required or recommended when running from Azure.
            
.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2021-06-07
Updated:     2023-02-17
Credit:      This Function incorporates the work of Nickolaj Andersen (@NickolajA) of the MSEndpointMgr team and the AADDeviceTurst project. 
             The way I am using it for Log Analytics is conceptually based on the work of Jan Ketil Skanke (@JankeSkanke) of the MSEndpointMgr team and the Intune Enhanced Inventory project. See the credit section in my blog below for more details. 
Blog:        https://azuretothemax.net/2023/05/31/powershell-dcr-log-analytics-part-2-1-overview/

            
Version history:
1 - 2021-06-07 Function created (Nickolaj Andersen)
2 - 2022-12-08 Function updated to use DCR/DCE (Maxton Allen)
3 - 2023-02-17 Updated to newer Authentication API's, updated ability to run locally using app reg or use self auth for all items. (Maxton Allen)
4 - 2023-05-27 Function app updated to latest authentication methods improved by @AzureToTheMax.
#>



using namespace System.Net
# Input bindings are passed in via param block.

param($Request)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


#region functions
function Get-SelfGraphAuthToken {
    <#
    .SYNOPSIS
        Use the permissions granted to the Function App itself to obtain a Graph token for running Graph queries. 
        Returns a formated header for use with the original code.
    
    .NOTES
        Author:      Maxton Allen
        Contact:     @AzureToTheMax
        Created:     2021-06-07
        Updated:     2023-02-17
        Original: Nickolaj Andersen, @NickolajA

    
        Version history:
        1 - 2021-06-07 Function created
        2 - 2023-02-17 Updated to API Version 2019-08-01 from 2017-09-01
    #>
    Process {

        $resourceURI = "https://graph.microsoft.com"
        $tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
        $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $tokenAuthURI

        
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($tokenResponse.access_token)"
            "ExpiresOn" = $tokenResponse.expires_on
        }
        return $AuthenticationHeader
    }
}#end function 





#region functions
function Get-SelfUploadToken {
<#
.SYNOPSIS
    Use the permissions granted to the Function App itself to obtain an Azure token for uploading data to the DCE/DCR.
    Returns a raw bearer token.

.NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Created:     2023-02-17
    Updated:     2023-02-17

    Version history:
    1 (2023-02-17) Function created
#>
Process {

    $resourceURI = "https://monitor.azure.com"
    $tokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$resourceURI&api-version=2019-08-01"
    $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER"="$env:IDENTITY_HEADER"} -Uri $tokenAuthURI
    $accessToken = $tokenResponse.access_token


    If ($accessToken) { 
        return $accessToken  
    } 
    Else { 
        Throw "Authentication failed" 
    } 
}
}#end function 







Function Get-AppRegGraphToken { 
<#
.SYNOPSIS
    Use the permissions granted to the App Registration to obtain a Graph token for making Graph queries. 
    Returns a formatted header.

.NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Created:     2023-02-17
    Updated:     2023-05-07

    Version history:
    1 (2023-02-17) Function created
    2 (2023-05-07) Reformated to return a full header rather than just the bearer token as new process no longer requires both.
#>

    [cmdletbinding()] 
    Param( 
        [parameter(Mandatory = $true)] 
        [pscredential]$Credential, 
        [parameter(Mandatory = $true)] 
        [string]$tenantID 
    ) 

    
    #Get token 
    $AuthUri = "https://login.microsoftonline.com/$TenantID/oauth2/token" 
    $Resource = 'graph.microsoft.com' 
    $AuthBody = "grant_type=client_credentials&client_id=$($credential.UserName)&client_secret=$($credential.GetNetworkCredential().Password)&resource=https%3A%2F%2F$Resource%2F" 
    $Response = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $AuthBody 
    If ($Response.access_token) { 
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
            "ExpiresOn" = $Response.expires_on
        }
        return $AuthenticationHeader
    } 
    Else { 
        Throw "Authentication failed" 
    } 
} #End function






Function Get-AppRegUploadToken{
<#
.SYNOPSIS
    Use the permissions granted to the App Registration to obtain an Azure token for uploading to the DCE/DCR. 
    Returns a raw bearer token.

.NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Created:     2023-02-17
    Updated:     2023-02-17

    Version history:
    1 (2023-02-17) Function created
#>
    [cmdletbinding()] 
    Param(
        [parameter(Mandatory = $true)] 
        [string]$TenantID,
        [parameter(Mandatory = $true)] 
        [string]$appId,
        [parameter(Mandatory = $true)] 
        [string]$appSecret
    )

    $scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
    $body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
    $headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
    $uri = "https://login.microsoftonline.com/$($tenantId)/oauth2/v2.0/token"

    $response = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers

    If ($Response.access_token) { 
        return $Response.access_token 
    } 
    Else { 
        Throw "Authentication failed" 
    } 


}






function Send-LogAnalyticsData() {
    <#
   .SYNOPSIS
       Send log data to Azure Monitor (DCR/DCE) by using Invoke-WebRequest.

   .DESCRIPTION
       This does not use the Rest API (Invoke-RestMethod) because the default response to the REST API is empty. I don't like assuming nothing means success. 
       Invoke-WebRequest returns a 204 (No Content) which is a much nicer confirmation than silence. 
   
   .NOTES
       Author:      Maxton Allen
       Contact:     @AzureToTheMax
       Created:     12-08-2022
       Updated:     02-17-2022
       Original HTTP API Version by: Jan Ketil Skanke
   
       Version history:
        1 - (12-08-2022) Function created
        2 - (02-17-2022) Minor wording tweaks.
   #>
   param(
       [string]$log, 
       [string]$Table, 
       [string]$DcrImmutableId, 
       [string]$bearerToken
   )


   #Construct our Header.
    $headers = @{
        "Authorization" = "Bearer $($bearerToken)";
        "Content-Type" = "application/json"; 
    }

    #Compile URL for upload from provided variables.
    $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2021-11-01-preview";
    write-Information "URI - $($uri)"

    #Check log size and throw error if it's too large.
     if($log.Length -gt (1*1024*1024))
     {
         throw ("Upload payload is too big and exceed the 1mb limit for a single upload.  Please reduce the payload size.  Current payload size is: " + ($log.Length/1024/1024).ToString("#.#") + "Mb")
     }
     $payloadsize = ("Upload payload size is " + ($log.Length/1024).ToString("#.#") + "Kb")
     write-Information "Payload Size: $($payloadsize)
     "

     #Send upload and put response in variable
     $uploadResponse = Invoke-WebRequest -Uri $uri -Method "Post" -Body $log -Headers $headers -UseBasicParsing

     #Write information to trace
     write-Information "Status Code: $($uploadResponse.StatusCode)"
     write-Information "Status Description: $($uploadResponse.StatusDescription)"

     #Compile response code to provide back to requestor
    $statusmessage = "$($uploadResponse.StatusCode): $($payloadsize)"

    #Return status message
    return $statusmessage

}#end function



function Get-AzureADDeviceAlternativeSecurityIds {
    <#
    .SYNOPSIS
        Decodes Key property of an Azure AD device record into prefix, thumbprint and publickeyhash values.
    
    .DESCRIPTION
        Decodes Key property of an Azure AD device record into prefix, thumbprint and publickeyhash values.

    .PARAMETER Key
        Specify the 'key' property of the alternativeSecurityIds property retrieved from the Get-AzureADDeviceRecord function.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the 'key' property of the alternativeSecurityIds property retrieved from the Get-AzureADDeviceRecord function.")]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )
    Process {
        $DecodedKey = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Key))
        $PSObject = [PSCustomObject]@{
            "Prefix" = $DecodedKey.SubString(0,21)
            "Thumbprint" = $DecodedKey.Split(">")[1].SubString(0,40)
            "PublicKeyHash" = $DecodedKey.Split(">")[1].SubString(40)
        }

        # Handle return response
        return $PSObject
    }
}

function Get-AzureADDeviceRecord {
    <#
    .SYNOPSIS
        Retrieve an Azure AD device record.
    
    .DESCRIPTION
        Retrieve an Azure AD device record.

    .PARAMETER DeviceID
        Specify the Device ID of an Azure AD device record.

    .PARAMETER AuthToken
        Specify a hash table consisting of the authentication headers.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2022-01-01
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2022-01-01) Added support for passing in the authentication header table to the function
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Device ID of an Azure AD device record.")]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceID,

        [parameter(Mandatory = $true, HelpMessage = "Specify a hash table consisting of the authentication headers.")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$AuthToken
    )
    Process {
        $GraphURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($DeviceID)'"
        $GraphResponse = (Invoke-RestMethod -Method "Get" -Uri $GraphURI -ContentType "application/json" -Headers $AuthToken -ErrorAction Stop).value
        
        # Handle return response
        return $GraphResponse
    }
}

function Test-AzureADDeviceAlternativeSecurityIds {
    <#
    .SYNOPSIS
        Validate the thumbprint and publickeyhash property values of the alternativeSecurityIds property from the Azure AD device record.
    
    .DESCRIPTION
        Validate the thumbprint and publickeyhash property values of the alternativeSecurityIds property from the Azure AD device record.

    .PARAMETER AlternativeSecurityIdKey
        Specify the alternativeSecurityIds.Key property from an Azure AD device record.

    .PARAMETER Type
        Specify the type of the AlternativeSecurityIdsKey object, e.g. Thumbprint or Hash.

    .PARAMETER Value
        Specify the value of the type to be validated.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2023-05-10
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2023-02-10) @AzureToTheMax
            1. Updated Thumbprint compare to use actual PEM cert via X502 class rather than simply a passed and seperate thumbprint value.
            2. Updated Hash compare to use full PEM cert via the X502 class, pull out just the public key data, and compare from that like before.

    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the alternativeSecurityIds.Key property from an Azure AD device record.")]
        [ValidateNotNullOrEmpty()]
        [string]$AlternativeSecurityIdKey,

        [parameter(Mandatory = $true, HelpMessage = "Specify the type of the AlternativeSecurityIdsKey object, e.g. Thumbprint or Hash.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Thumbprint", "Hash")]
        [string]$Type,

        [parameter(Mandatory = $true, HelpMessage = "Specify the value of the type to be validated.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    Process {
        # Construct custom object for alternativeSecurityIds property from Azure AD device record, used as reference value when compared to input value
        $AzureADDeviceAlternativeSecurityIds = Get-AzureADDeviceAlternativeSecurityIds -Key $AlternativeSecurityIdKey
        
        switch ($Type) {
            "Thumbprint" {
                Write-Output "Using new X502 Thumbprint compare"

                # Convert Value (cert) passed back to X502 Object
                $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($Value))

                # Validate match
                if ($X502.thumbprint -match $AzureADDeviceAlternativeSecurityIds.Thumbprint) {
                    return $true
                }
                else {
                    return $false
                }
            }
            "Hash" {
                Write-Output "Using new X502 hash compare"

                # Convert Value (cert) passed back to X502 Object
                $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($Value))

                # Pull out just the public key, removing extended values
                $X502Pub = [System.Convert]::ToBase64String($X502.PublicKey.EncodedKeyValue.rawData)
        
                # Convert from Base64 string to byte array
                $DecodedBytes = [System.Convert]::FromBase64String($X502Pub)
                
                # Construct a new SHA256Managed object to be used when computing the hash
                $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

                # Compute the hash
                [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($DecodedBytes)

                # Convert computed hash to Base64 string
                $ComputedHashString = [System.Convert]::ToBase64String($ComputedHash)

                # Validate match
                if ($ComputedHashString -like $AzureADDeviceAlternativeSecurityIds.PublicKeyHash) {
                    return $true
                }
                else {
                    return $false
                }
            }
        }
    }
}


function Test-Encryption {
    <#
    .SYNOPSIS
        Test the signature created with the private key by using the public key.
    
    .DESCRIPTION
        Test the signature created with the private key by using the public key.

    .PARAMETER PublicKeyEncoded
        Specify the Base64 encoded string representation of the Public Key.

    .PARAMETER Signature
        Specify the Base64 encoded string representation of the signature coming from the inbound request.

    .PARAMETER Content
        Specify the content string that the signature coming from the inbound request is based upon.
    
    .NOTES
        Author:      Nickolaj Andersen / Thomas Kurth
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2023-05-10
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2023-05-10) @AzureToTheMax - Updated to use full PEM cert via X502, extract the public key, and perform test like before using that.

        Credits to Thomas Kurth for sharing his original C# code.
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Base64 encoded string representation of the Public Key.")]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKeyEncoded,

        [parameter(Mandatory = $true, HelpMessage = "Specify the Base64 encoded string representation of the signature coming from the inbound request.")]
        [ValidateNotNullOrEmpty()]
        [string]$Signature,

        [parameter(Mandatory = $true, HelpMessage = "Specify the content string that the signature coming from the inbound request is based upon.")]
        [ValidateNotNullOrEmpty()]
        [string]$Content
    )
    Process {

        Write-Output "Using new X502 encryption test"
        # Convert Value (cert) passed back to X502 Object
        $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($PublicKeyEncoded))

        # Pull out just the public key, removing extended values
        $X502Pub = [System.Convert]::ToBase64String($X502.PublicKey.EncodedKeyValue.rawData)

        # Convert encoded public key from Base64 string to byte array
        $PublicKeyBytes = [System.Convert]::FromBase64String($X502Pub)

        # Convert signature from Base64 string
        [byte[]]$Signature = [System.Convert]::FromBase64String($Signature)

        # Extract the modulus and exponent based on public key data
        $ExponentData = [System.Byte[]]::CreateInstance([System.Byte], 3)
        $ModulusData = [System.Byte[]]::CreateInstance([System.Byte], 256)
        [System.Array]::Copy($PublicKeyBytes, $PublicKeyBytes.Length - $ExponentData.Length, $ExponentData, 0, $ExponentData.Length)
        [System.Array]::Copy($PublicKeyBytes, 9, $ModulusData, 0, $ModulusData.Length)

        # Construct RSACryptoServiceProvider and import modolus and exponent data as parameters to reconstruct the public key from bytes
        $PublicKey = [System.Security.Cryptography.RSACryptoServiceProvider]::Create(2048)
        $RSAParameters = $PublicKey.ExportParameters($false)
        $RSAParameters.Modulus = $ModulusData
        $RSAParameters.Exponent = $ExponentData
        $PublicKey.ImportParameters($RSAParameters)

        # Construct a new SHA256Managed object to be used when computing the hash
        $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

        # Construct new UTF8 unicode encoding object
        $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8

        # Convert content to byte array
        [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)

        # Compute the hash
        [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)

        # Verify the signature with the computed hash of the content using the public key
        $PublicKey.VerifyHash($ComputedHash, $Signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
}

function Get-AzureADDeviceIDFromCertificate {
    <#
   .SYNOPSIS
       Used to pull the Azure Device ID from the provided Base64 certificate.
   
   .DESCRIPTION
       Used by the function app to pull the Azure Device ID from the provided Base64 certificate.
   
   .NOTES
       Author:      Maxton Allen 
       Contact:     @AzureToTheMax
       Created:     2023-05-14
       Updated:     2023-05-14
   
       Version history:
       1.0.0 - (2023-05-14) created
   #>
   param(    
       [parameter(Mandatory = $true, HelpMessage = "Specify a Base64 encoded value for which an Azure Device ID will be extracted.")]
       [ValidateNotNullOrEmpty()]
       [string]$Value
   )
   Process {
       # Convert Value (cert) passed back to X502 Object
       $X502 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([System.Convert]::FromBase64String($Value))

       # Get the Subject (issued to)
       $Subject = $X502.Subject

       # Remove the leading "CN="
       $SubjectTrimed = $Subject.TrimStart("CN=")

       # Handle return
       Return $SubjectTrimed
   }
}
#endregion
######################################################################


#Start Script
Write-Information "LogCollectorAPI function received a request."

# Setting inital Status Code: 
$StatusCode = [HttpStatusCode]::OK



######################################################################
#region Variables
# Define variables from Function App Configuration
$DceURI = $env:DceURI #DCE URI
$TenantID = $env:TenantID #Your Tenant ID

<#
.Description
If you had to use an App registration alone, you could swap out all instance of self-auth funciton calls with AppReg function calls and use the below to tell the Function those values.
You would want to use a key vault for the secret.

# Get secrets from Keyvault
$appId = $env:appId #Enterprise App Registrations App ID
$appSecret = $env:appSecret #Your Registered Apps Secret Key Value
#>



#This allows you to run the app in visual. 
#You need an App Registration with the same permissions as the Function and you need those values in a CSV file on your system.
#CSV is better - that way you can push code without redacting keys and secrets.
$RunningComputerName = $env:COMPUTERNAME
$MyComputerName = "XXXXXX" #Your Computer Name
    if ($RunningComputerName -eq $MyComputerName){
          
        #Set Running as Local
        $RunLocation = "Local"

        #The location of your CSV file containing headers and information for the below variables.
        $SecretsCSV = Import-Csv "C:\path\to\Secrets.csv"

        #See Above Section for explination on values
        $appId = $SecretsCSV.Appid
        $appSecret = $SecretsCSV.AppSecret
        $DceURI = $SecretsCSV.DceURI
        $TenantID = $SecretsCSV.TenantID

        } else {
            #Set our token method to cloud (It's the Function App)
            $RunLocation = "Cloud"
        }


#get auth token for use within script either via cloud or local (app reg)
        if($RunLocation -eq "Cloud"){
            #Use Function permissions to get Graph token
            write-host "Running as Cloud: Using Self-Authentication"
            $AuthToken = Get-SelfGraphAuthToken
            #Write-Information "Cloud auth token: $($AuthToken.Authorization)" #Used in troubleshooting
        } else {
            #Use app reg for Graph token
            write-host "Running as Local: Using App Registration"
            $Credential = New-Object System.Management.Automation.PSCredential($AppID, (ConvertTo-SecureString $AppSecret -AsPlainText -Force)) 
            $AuthToken = Get-AppRegGraphToken -credential $Credential -TenantID $TenantID 
            #Write-Information "Local auth token: $($AuthToken.Authorization)" #Used in troubleshooting
        }


#Extract variables from payload with information on where the payload needs to go
$MainPayLoad = $Request.Body.LogPayloads #The Logs themselves
$Table = $Request.Body.Table #The Table name the logs need to go into 
$DcrImmutableId = $Request.Body.DcrImmutableId #The DCR Immutable ID that the logs need to go to in order to reach the destination table

$DeviceName = $Request.Body.DeviceName #From AADDeviceTrust
$Signature = $Request.Body.Signature #From AADDeviceTrust
$PublicKey = $Request.Body.PublicKey #From AADDeviceTrust

#Get Device ID from the cert
$DeviceID = Get-AzureADDeviceIDFromCertificate -Value $PublicKey

#endregion
######################################################################


######################################################################
#region Process


# Write logging output.
Write-Output -InputObject "Initiating request handling for device named as '$($DeviceName)' with identifier: $($DeviceID)"

#Check what logs we recieved
$LogsReceived = New-Object -TypeName System.Collections.ArrayList
foreach ($Key in $MainPayLoad.Keys) {
    $LogsReceived.Add($($Key)) | Out-Null
}
Write-Information "Logs Received: $($LogsReceived)"

# Declare response object as Arraylist
$ResponseArray = New-Object -TypeName System.Collections.ArrayList

# Retrieve Azure AD device record based on DeviceID property from incoming request body
$AzureADDeviceRecord = Get-AzureADDeviceRecord -DeviceID $DeviceID -AuthToken $AuthToken

#Write-Output "Azure AD Device Record is $($AzureADDeviceRecord) with id $($AzureADDeviceRecord.id)"

if ($AzureADDeviceRecord -ne $null) {
    Write-Output -InputObject "Found trusted Azure AD device record with object identifier: $($AzureADDeviceRecord.id)"

    # Validate thumbprint from input request with Azure AD device record's alternativeSecurityIds details
    if (Test-AzureADDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $AzureADDeviceRecord.alternativeSecurityIds.key -Type "Thumbprint" -Value $PublicKey) {
        Write-Output -InputObject "Successfully validated certificate thumbprint from inbound request"

        # Validate public key hash from input request with Azure AD device record's alternativeSecurityIds details
        if (Test-AzureADDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $AzureADDeviceRecord.alternativeSecurityIds.key -Type "Hash" -Value $PublicKey) {
            Write-Output -InputObject "Successfully validated certificate SHA256 hash value from inbound request"

            $EncryptionVerification = Test-Encryption -PublicKeyEncoded $PublicKey -Signature $Signature -Content $AzureADDeviceRecord.deviceId
            if ($EncryptionVerification -eq $true) {
                Write-Output -InputObject "Successfully validated inbound request came from a trusted Azure AD device record"

                # Validate that the inbound request came from a trusted device that's not disabled
                if ($AzureADDeviceRecord.accountEnabled -eq $true) {
                    Write-Output -InputObject "Azure AD device record was validated as enabled"


                    ###################################
                    #Start tag checking and conversion#
                    ###################################
                    

                    foreach ($LogName in $LogsReceived){
                        Write-Information "Processing $( )"
                            
                            #Check that we have a Table and DCR in the JSON
                            if ($Table -ne $null -and $DcrImmutableId -ne $null){
                            write-host "Table and DCR ID provided"
                            $Json = $MainPayLoad.$LogName
                            $LogSize = $json.Length
        
                            # Verify if log has data before sending to Log Analytics
                                if ($LogSize -gt 0){
                                    Write-Information "Log $($logname) has content. Size is $($json.Length)"
                                    $LogBody = ([System.Text.Encoding]::UTF8.GetBytes($Json))
                                    
                                        # Retrieve authentication token either via cloud or local (app reg)
                                    if($RunLocation -eq "Cloud"){
                                        write-host "Upload - Running as Cloud: Using Self-Authentication"
                                        $bearerToken = Get-SelfUploadToken
                                    } else {
                                        #Slightly complicated as Get-SelfGraphAuthToken returns a formated bearer token, where as Get-AppRegGraphToken is just the token which is the format needed later
                                        write-host "Upload - Running as Local: Using App Registration"
                                        $bearerToken = Get-AppRegUploadToken -TenantID $TenantID -appId $appId -appSecret $appSecret
                                    }
        
                                    #Enable for troubleshooting
                                    #Write-Information $bearerToken
                                    #Write-Information "Log: $($logname) Table: $($Table) DcrImmutableId: $($DcrImmutableId) Json: $($Json)"
                                    #Write-Information "Custom Query Result: $env:username"
                                    
                                    #Call the send function - Send the data!
                                    $ResponseLogInventory = Send-LogAnalyticsData -log $Json -Table $Table -DcrImmutableId $DcrImmutableId -bearerToken $bearerToken
        
                                    #write status of send
                                    Write-Information "$($LogName) Logs sent to DCR $($ResponseLogInventory)"
                                    $PSObject = [PSCustomObject]@{
                                        LogName = $LogName
                                        Response = $ResponseLogInventory
                                    }
                                    $ResponseArray.Add($PSObject) | Out-Null
                                    $StatusCode = [HttpStatusCode]::OK
        
                                    } else {
                                    # Log is empty - return status 200 but with info about empty log
                                    Write-Information "Log $($logname) has no content. Size is $($json.Length)"
                                    $PSObject = [PSCustomObject]@{
                                        LogName = $LogName
                                        Response = "200:Log does not contain data"
                                }
                                $ResponseArray.Add($PSObject) | Out-Null
                            }
                         } Else {
                            #If no Table was in the payload
                            Write-Information "$($LogName) - No Table and DCR was provided!"
        
                            }
    
                    }

        
                    ########################
                    #Resume original script#
                    ########################


                }
                else {
                    Write-Output -InputObject "Trusted Azure AD device record validation for inbound request failed, record with deviceId '$($DeviceID)' is disabled"
                    $StatusCode = [HttpStatusCode]::Forbidden
                    $Body = "Disabled device record"
                }
            }
            else {
                Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate signed content from client"
                $StatusCode = [HttpStatusCode]::Forbidden
                $Body = "Untrusted request"
            }
        }
        else {
            Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate certificate SHA256 hash value"
            $StatusCode = [HttpStatusCode]::Forbidden
            $Body = "Untrusted request"
        }
    }
    else {
        Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate certificate thumbprint"
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = "Untrusted request"
    }
}
else {
    Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
    $StatusCode = [HttpStatusCode]::Forbidden
    $Body = "Untrusted request"
}


######################################################################
#Region Reply
#Determine $Body. Could be from failure responses or JSON from correct reply.
if ($null -ne $ResponseArray){
    $body = $ResponseArray | ConvertTo-Json 
} else {
    $Body = $body  
}
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})
#endregion
