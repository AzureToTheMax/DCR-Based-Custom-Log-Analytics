#DCR/DCE Function App

<#
.SYNOPSIS
Function App for uploading DCR/DCE based content instead of using the legacy HTTP API.
Uses the devices reported Tenant and ID to authenticate the upload.
Can be ran locally via Visual Studio Code if a proper App Registration / Secret is provided. 
            
.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2021-06-07
Updated:     2023-02-17
Original: Nickolaj Andersen, @NickolajA

            
Version history:
1 - 2021-06-07 Function created (Nickolaj Andersen)
2 - 2022-12-08 Function updatd to use DCR/DCE (Maxton Allen)
3 - 2023-02-17 Updated to newer Authentication API's, updated ability to run locally using app reg or use self auth for all items. (Maxton Allen)
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
        return $Response.access_token 
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




#endregion functions
######################################################################


#Start Script
Write-Information "LogCollectorAPI function received a request."

# Setting inital Status Code: 
$StatusCode = [HttpStatusCode]::OK



######################################################################
#region Variables
# Define variables from Function App Configuration
$LogControll = $env:LogControl #A true/false value, really no point in using this anymore.
$DceURI = $env:DceURI #DCE URL
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
$MyComputerName = "XXXX" #Your Computer Name
    if ($RunningComputerName -eq $MyComputerName){
          
        #Set Running as Local
        $RunLocation = "Local"

        #The location of your CSV file containing headers and information for the below variables.
        $SecretsCSV = Import-Csv "C:\PATH TO SECRETS\Secrets.csv"

        #See Above Section for explination on values
        $appId = $SecretsCSV.Appid
        $appSecret = $SecretsCSV.AppSecret
        $DceURI = $SecretsCSV.DceURI
        $LogControll = $SecretsCSV.LogControll
        $TenantID = $SecretsCSV.TenantID

        } else {
            #Set our token method to cloud (It's the Function App)
            $RunLocation = "Cloud"
        }



#Extract variables from payload with information on where the payload needs to go
$MainPayLoad = $Request.Body.LogPayloads #The Logs themselves
$InboundDeviceID= $Request.Body.AzureADDeviceID #The Azure Device ID of the inbound device
$InboundTenantID = $Request.Body.AzureADTenantID #The Tenant ID reported by the device 
$Table = $Request.Body.Table #The Table name the logs need to go into 
$DcrImmutableId = $Request.Body.DcrImmutableId #The DCR Immutable ID that the logs need to go to in order to reach the destination table

#endregion
######################################################################


######################################################################
#region Process

$LogsReceived = New-Object -TypeName System.Collections.ArrayList
foreach ($Key in $MainPayLoad.Keys) {
    $LogsReceived.Add($($Key)) | Out-Null
}
Write-Information "Logs Received $($LogsReceived)"

# Write logging output.
Write-Information "Inbound DeviceID $($InboundDeviceID)"
Write-Information "Inbound TenantID $($InboundTenantID)"
Write-Information "Environment TenantID $TenantID"

# Declare response object as Arraylist
$ResponseArray = New-Object -TypeName System.Collections.ArrayList

# Verify request comes from correct tenant
if($TenantID -eq $InboundTenantID){
    Write-Information "Request is comming from correct tenant"


    # Retrieve authentication token either via cloud or local (app reg)
    if($RunLocation -eq "Cloud"){
        write-host "Graph Call - Running as Cloud: Using Self-Authentication"
        $Script:AuthToken = Get-SelfGraphAuthToken
    } else {
        #Slightly complicated as Get-SelfGraphAuthToken returns a formated bearer token, where as Get-AppRegGraphToken is just the token which is the format needed later
        write-host "Graph Call - Running as Local: Using App Registration"
        $Credential = New-Object System.Management.Automation.PSCredential($AppID, (ConvertTo-SecureString $AppSecret -AsPlainText -Force)) 
        $Token = Get-AppRegGraphToken -credential $Credential -TenantID $TenantID 
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $Token"
        }
        $Script:AuthToken = $AuthenticationHeader 
    }

    
    # Query graph for device verification 
    $DeviceURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($InboundDeviceID)'"
    $DeviceIDResponse = (Invoke-RestMethod -Method "Get" -Uri $DeviceURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value

    # Assign to variables for matching 
    $DeviceID = $DeviceIDResponse.deviceId  
    $DeviceEnabled = $DeviceIDResponse.accountEnabled    
    Write-Information "DeviceID $DeviceID"   
    Write-Information "DeviceEnabled: $DeviceEnabled"
    # Verify request comes from a valid device

    #change to ("1" -eq "1") for local testing
    if($DeviceID -eq $InboundDeviceID){
        Write-Information "Request is coming from a valid device in Azure AD"
        if($DeviceEnabled -eq "True"){
            Write-Information "Requesting device is not disabled in Azure AD"                       
            foreach ($LogName in $LogsReceived){
                Write-Information "Processing $($LogName)"


                # Check if Log type control is enabled
                if ($LogControll -eq "true"){
                # Verify log name applicability
                Write-Information "Log name control is enabled, verifying log name against allowed values"
                [Array]$AllowedLogNames = $env:AllowedLogNames
                Write-Information "Allowed log names: $($AllowedLogNames)"
                $LogCheck = $AllowedLogNames -match $LogName
                    if(-not ([string]::IsNullOrEmpty($LogCheck))){
                        Write-Host "Log $LogName Allowed"
                        [bool]$LogState = $true
                    }
                    else {
                        Write-Warning "Logname $LogName not allowed"
                        [bool]$LogState = $false
                    }       
                     }
                    else{
                    Write-Information "Log control is not enabled, continue"
                    [bool]$LogState = $true
                    }

                    
                if ($LogState){
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
                                write-host "Upload - unning as Local: Using App Registration"
                                $bearerToken = Get-AppRegUploadToken -TenantID $TenantID -appId $appId -appSecret $appSecret
                            }

                            #Enable for troubleshooting
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

            } else {
                    #If log control was on and table not known
                    Write-Warning "Log $($LogName) is not allowed"
                    $StatusCode = [HttpStatusCode]::OK
                    $PSObject = [PSCustomObject]@{
                        LogName = $LogName
                        Response = "Logtype is not allowed"
                    }
                    $ResponseArray.Add($PSObject) | Out-Null                   
                }
            }
        }
        else{
            Write-Warning "Device is not enabled - Forbidden"
            $StatusCode = [HttpStatusCode]::Forbidden
        }
    }
    else{
        Write-Warning  "Device not in my Tenant - Forbidden"
        $StatusCode = [HttpStatusCode]::Forbidden
    }
}
else{
    Write-Warning "Tenant not allowed - Forbidden"
    $StatusCode = [HttpStatusCode]::Forbidden
}
#endregion
######################################################################

######################################################################
#Region Reply
$body = $ResponseArray | ConvertTo-Json 
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})
#endregion