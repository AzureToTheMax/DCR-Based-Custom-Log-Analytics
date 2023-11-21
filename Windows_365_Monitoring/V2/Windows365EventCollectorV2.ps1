#Windows 365 (Cloud PC) Event Collector.

<#
.SYNOPSIS
Windows 365 (Cloud PC) Event Collector.
Collects RDP disconnect, System startup, and RDP TCP/UDP logs.
            
.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2023-02-15
Updated:     2023-06-17
This script is based on the client-side script by Jan Ketil Skanke (@JankeSkanke) of the MSEndpointMgr team for the Intune Enhanced Inventory project.

            
Version history:
1 - 2023-02-15 Created
2 - 2023-06-17 updated to new HTTP auth
#>


######################################################################
#Region Variables
#Controls various Script customizeable variables

#Script Version. Used for denoating updates / tracking.
$ScriptVersion = "2"

#Function URL for Log Upload
$AzureFunctionURL = "Your Function App URI"

#Table name - must be exact
$Table = "Windows365Events_CL"

#DCRImmutableID
$DcrImmutableId = "Your Immutable ID"

#Friendly log name. Name it what you want. Used for logging, local JSON export, and the name the data is referenced by inside the JSON, and log control.
$LogName = "Windows365Events"

#How Many Days backwards to collect on first execution. Should be a negative value. Default is "-7" to collect the previous 7 days.
$InitalCollectionDays = "-7"

#Max Collection Interval in miliseconds. This does not overide inital data collection. 
#This controls the maxmim amount of time a device can try and collect logs from in case it's somehow been running with no internet or something like that.
$MaxCollectionInterval = 1209600000 #value in miliseconds.
#Default is two weeks, 1209600000
#Three weeks 3628800000
#One Week 604800000
#24 hours 86400000 

#Always report startup events and thus upload data each time the script runs. Default is FALSE. 
#When False, startup information is only reported when another event is found to upload. An unused machine may eventually fall out of reporting when set to false.
$AlwaysReportStartup = $false

#Export to JSON for DCR Creation - Should be false
$WriteLogFile = $false
$ScanBackValue = "-7" #How many days to ALWAYS go back when writelogfile is set to true. Only effects when WriteLogFile is on.

#Enable or disable the log upload delay. True/False. Default is $True. Money saving method to have on.
$Delay = $true

#Turn on/off collection - Should be true. Automated to run off CPC name.
if ($ENV:COMPUTERNAME -like "*CPC-*"){
    $collectEvents = $true
} else {
    $collectEvents = $false
    Write-Host "Not a Cloud PC"
    exit 0
}


#misc
$TimeStampField = "" #Leave It Blank

#Clear variables - needed for proper local testing.
$FinalLog = $null
$SecurityLogArray = $null
$SecurityEventsForUpload = $null
$SecutiyLogInventory = $null
$EventCount = $null
$MarkerFileTimeUTC = $null
$DateCurrentUTC = $null




#EndRegion
######################################################################

######################################################################
#region functions
#Get-AzureADJoinDate
#Get-AzureADTenantID
#New-AADDeviceTrustBody
#Test-AzureADDeviceRegistration
#Get-AzureADRegistrationCertificateThumbprint
#Get-PublicKeyBytesEncodedString
#New-RSACertificateSignature
#Get-AzureADDeviceID
######################################################################

function Get-AzureADJoinDate {
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoThumbprint -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                # Handle return value
                return $AzureADJoinDate
            }
            if ($AzureADJoinCertificate -eq $null) {
                $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -eq "CN=$($AzureADJoinInfoThumbprint)" }
                $AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                return $AzureADJoinDate
            }
        }
    }
} #endfunction 
######################################################################
#Function to get AzureAD TenantID
function Get-AzureADTenantID {
    # Cloud Join information registry path
    $AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
    # Retrieve the child key name that is the tenant id for AzureAD
    $AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
    return $AzureADTenantID
}                          


function New-AADDeviceTrustBody {
    <#
    .SYNOPSIS
        Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.

    .DESCRIPTION
        Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.

    .EXAMPLE
        .\New-AADDeviceTrustBody.ps1

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2022-03-14
        Updated:     2023-05-14

        Version history:
        1.0.0 - (2022-03-14) Script created
        1.0.1 - (2023-05-10) @AzureToTheMax - Updated to no longer use Thumbprint field, no redundant.
        1.0.2 - (2023-05-14) @AzureToTheMax - Updating to pull the Azure AD Device ID from the certificate itself.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Process {
        # Retrieve required data for building the request body
        $AzureADDeviceID = Get-AzureADDeviceID # Still needed to form the signature.
        $CertificateThumbprint = Get-AzureADRegistrationCertificateThumbprint
        $Signature = New-RSACertificateSignature -Content $AzureADDeviceID -Thumbprint $CertificateThumbprint
        $PublicKeyBytesEncoded = Get-PublicKeyBytesEncodedString -Thumbprint $CertificateThumbprint

        # Construct client-side request header
        $BodyTable = [ordered]@{
            DeviceName = $env:COMPUTERNAME
            #DeviceID = $AzureADDeviceID - Will be pulled from the key.
            Signature = $Signature
            #Thumbprint = $CertificateThumbprint - Will be pulled from the key.
            PublicKey = $PublicKeyBytesEncoded
        }

        # Handle return value
        return $BodyTable
    }
}

function Test-AzureADDeviceRegistration {
    <#
    .SYNOPSIS
        Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
    
    .DESCRIPTION
        Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2022-01-27
        Updated:     2022-01-27
    
        Version history:
        1.0.0 - (2022-01-27) Function created
    #>
    Process {
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
        if (Test-Path -Path $AzureADJoinInfoRegistryKeyPath) {
            return $true
        }
        else {
            return $false
        }
    }
}
function Get-AzureADDeviceID {
    <#
    .SYNOPSIS
        Get the Azure AD device ID from the local device.
    
    .DESCRIPTION
        Get the Azure AD device ID from the local device.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-05-26
        Updated:     2023-06-20
    
        Version history:
        1.0.0 - (2021-05-26) Function created
        1.0.1 - (2022-10-20) @AzureToTheMax - Fixed issue pertaining to Cloud PCs (Windows 365) devices ability to locate their AzureADDeviceID.
        1.0.2 - (2023-06-20) @AzureToTheMax - Fixed issue pertaining to Cloud PCs (Windows 365) devices where the reported AzureADDeviceID was in all capitals, breaking signature creation.

    #>
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoThumbprint -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                # Convert upper to lowercase.
                $AzureADDeviceID = "$($AzureADDeviceID)".ToLower()

                # Handle return value
                return $AzureADDeviceID

            } else {

                #If no certificate was found, locate it by Common Name instead of Thumbprint. This is likely a CPC or similar.
                $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=($AzureADJoinInfoThumbprint)" }

                    if ($AzureADJoinCertificate -ne $null){
                    # Cert is now found, extract Device ID from Common Name
                    $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                    # Convert upper to lowercase.
                    $AzureADDeviceID = "$($AzureADDeviceID)".ToLower()
                    # Handle return value
                    return $AzureADDeviceID

                    } else {
                    # Last ditch effort, try and use the ThumbPrint (reg key) itself.
                    $AzureADDeviceID=$AzureADJoinInfoThumbprint
                    # Convert upper to lowercase.
                    $AzureADDeviceID = "$($AzureADDeviceID)".ToLower()
                    return $AzureADDeviceID

                    }
            }
        }
    }
}

function Get-AzureADRegistrationCertificateThumbprint {
    <#
    .SYNOPSIS
        Get the thumbprint of the certificate used for Azure AD device registration.
    
    .DESCRIPTION
        Get the thumbprint of the certificate used for Azure AD device registration.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-03
        Updated:     2021-06-03
    
        Version history:
        1.0.0 - (2021-06-03) Function created
        1.0.1 - (2023-05-10) @AzureToTheMax Updated for Cloud PCs which don't have their thumbprint as their JoinInfo key name.
    #>
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        # Check for a cert matching that thumbprint
        $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }

            if($AzureADJoinCertificate -ne $null){
            # if a matching cert was found tied to that reg key (thumbprint) value, then that is the thumbprint and it can be returned.
            $AzureADThumbprint = $AzureADJoinInfoThumbprint

            # Handle return value
            return $AzureADThumbprint

            } else {

            # If a cert was not found, that reg key was not the thumbprint but can be used to locate the cert as it is likely the Azure ID which is in the certs common name.
            $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoThumbprint)" }
            
            #Pull thumbprint from cert
            $AzureADThumbprint = $AzureADJoinCertificate.Thumbprint

            # Handle return value
            return $AzureADThumbprint
            }

    }
}

function Get-PublicKeyBytesEncodedString {
    <#
    .SYNOPSIS
        Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
    
    .DESCRIPTION
        Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
        The certificate used must be available in the LocalMachine\My certificate store.

    .PARAMETER Thumbprint
        Specify the thumbprint of the certificate.
    
    .NOTES
        Author:      Nickolaj Andersen / Thomas Kurth
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2023-05-10
    
        Version history:
        1.0.0 - (2021-06-07) Function created
        1.0.1 - (2023-05-10) @AzureToTheMax - Updated to use X509 for the full public key with extended properties in the PEM format

        Credits to Thomas Kurth for sharing his original C# code.
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint
    )
    Process {

        # Determine the certificate based on thumbprint input
        $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $Thumbprint }
        if ($Certificate -ne $null) {
            # Bring the cert into a X509 object
            $X509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($Certificate)
            #Set the type of export to perform
            $type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
            #Export the public cert
            $PublicKeyBytes = $X509.Export($type, "")

            # Handle return value - convert to Base64
            return [System.Convert]::ToBase64String($PublicKeyBytes)
        }
    }
}

function New-RSACertificateSignature {
    <#
    .SYNOPSIS
        Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
    
    .DESCRIPTION
        Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
        The certificate used must be available in the LocalMachine\My certificate store, and must also contain a private key.

    .PARAMETER Content
        Specify the content string to be signed.

    .PARAMETER Thumbprint
        Specify the thumbprint of the certificate.
    
    .NOTES
        Author:      Nickolaj Andersen / Thomas Kurth
        Contact:     @NickolajA
        Created:     2021-06-03
        Updated:     2021-06-03
    
        Version history:
        1.0.0 - (2021-06-03) Function created

        Credits to Thomas Kurth for sharing his original C# code.
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the content string to be signed.")]
        [ValidateNotNullOrEmpty()]
        [string]$Content,

        [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint
    )
    Process {
        # Determine the certificate based on thumbprint input
        $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $CertificateThumbprint }
        if ($Certificate -ne $null) {
            if ($Certificate.HasPrivateKey -eq $true) {
                # Read the RSA private key
                $RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
                
                if ($RSAPrivateKey -ne $null) {
                    if ($RSAPrivateKey -is [System.Security.Cryptography.RSACng]) {
                        # Construct a new SHA256Managed object to be used when computing the hash
                        $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

                        # Construct new UTF8 unicode encoding object
                        $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8

                        # Convert content to byte array
                        [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)

                        # Compute the hash
                        [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)

                        # Create signed signature with computed hash
                        [byte[]]$SignatureSigned = $RSAPrivateKey.SignHash($ComputedHash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

                        # Convert signature to Base64 string
                        $SignatureString = [System.Convert]::ToBase64String($SignatureSigned)
                        
                        # Handle return value
                        return $SignatureString
                    }
                }
            }
        }
    }
}


######################################################################
#EndRegion
######################################################################



#Enable TLS 1.2 Support
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12





######################################################################
#region Storage Directory

#Create storage dir if it does not exit
$TestFolder = Test-Path C:\Windows\LogAnalytics
if ($TestFolder -eq $false) {
New-Item C:\Windows\LogAnalytics -ItemType Directory -ErrorAction SilentlyContinue > $null 
#Set dirs as hidden
$folder = Get-Item "C:\Windows\LogAnalytics" 
$folder.Attributes = 'Directory','Hidden' 
}
#Endregion
######################################################################





######################################################################
#Region Time Calculation


$DateCurrentUTC = (Get-Date).ToUniversalTime()


#Create our Marker file if it does not exist and provide it a default value
$TestFolder = Test-Path C:\Windows\LogAnalytics\windows365EventCollector.txt
if ($TestFolder -eq $false) {
New-Item C:\Windows\LogAnalytics\windows365EventCollector.txt -ItemType file -ErrorAction SilentlyContinue > $null 
#Set dirs as hidden
$folder = Get-Item "C:\Windows\LogAnalytics\windows365EventCollector.txt" 
$folder.Attributes = 'Directory','Hidden' 

#Supply our inital marker file with a default of X days back for inital ingestion
$MarkerFileTimeUTC = [datetime]$DateCurrentUTC.AddDays($InitalCollectionDays)

#Mark our marker file with the time of script start
Set-Content "C:\Windows\LogAnalytics\windows365EventCollector.txt" "$($DateCurrentUTC)" -Force
Write-Warning "First run! Using Default $($InitalCollectionDays) Day(s) scan!"

} else {
#If the file exists, read it to determine duration
$MarkerFileTimeUTC = Get-Content "C:\Windows\LogAnalytics\windows365EventCollector.txt"

$Difference = NEW-TIMESPAN -Start $MarkerFileTimeUTC -End $DateCurrentUTC
$Difference = $Difference.TotalMilliseconds
$Difference = [math]::Round($Difference)
write-host "Time difference since last run in milisconds is $($Difference)"

        #If the time since last collection is over two weeks
        if ($Difference -gt $MaxCollectionInterval) {
            
            $MarkerFileTimeUTC = $DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval)
            Write-Warning "Range exceeded maximum range of $($MaxCollectionInterval) miliseconds. Using $($DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval))"

        } else {
            write-host "Last scan is within range - Using $MarkerFileTimeUTC as start time"
        
        }

}

#Just in case. Could happen if file exists but is empty.
If ($null -eq $MarkerFileTimeUTC){
    $MarkerFileTimeUTC = $DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval)
    #Set content so it's not a problem next time.
    Set-Content "C:\Windows\LogAnalytics\windows365EventCollector.txt" "$($DateCurrentUTC)" -Force
    write-warning "MarkerFileTimeUTC was somehow null! Using default max range and thus date/time $($DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval))"
}



#If the write-logfile is on.
if ($WriteLogFile) {
write-warning "Write Log File is on! Automatically pulling $($ScanBackValue) days worth of logs! Ignoring time file!"

$MarkerFileTimeUTC = [datetime]$DateCurrentUTC.AddDays($ScanBackValue)
}

#Final Time Conversion to sortable format
$DateCurrentUTC = ([datetime]$DateCurrentUTC).ToString("s")
$MarkerFileTimeUTC = ([datetime]$MarkerFileTimeUTC).ToString("s")
write-host "Time Duration to collect is from $MarkerFileTimeUTC to $DateCurrentUTC"


#endregion
######################################################################






######################################################################
#Region Common Data
#Get Intune DeviceID and ManagedDeviceName
if(@(Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
    $MSDMServerInfo = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
    $ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
}

#Fill some common variables
$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

#Get computer info
$ComputerName = $ENV:COMPUTERNAME

#Get network adapters. Used for determining the region of logs.
$NetWorkArray = @()
	
$CurrentNetAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

foreach ($CurrentNetAdapter in $CurrentNetAdapters) {
    try{
        $IPConfiguration = Get-NetIPConfiguration -InterfaceIndex $CurrentNetAdapter[0].ifIndex -ErrorAction Stop
    }
    catch{
        $IPConfiguration = $null
    }
    $ComputerNetInterfaceDescription = $CurrentNetAdapter.InterfaceDescription
    $ComputerNetProfileName = $IPConfiguration.NetProfile.Name
    $ComputerNetIPv4Adress = $IPConfiguration.IPv4Address.IPAddress
    $ComputerNetInterfaceAlias = $CurrentNetAdapter.InterfaceAlias
    $ComputerNetIPv4DefaultGateway = $IPConfiguration.IPv4DefaultGateway.NextHop
    $ComputerNetMacAddress = $CurrentNetAdapter.MacAddress
    
    $tempnetwork = New-Object -TypeName PSObject
    $tempnetwork | Add-Member -MemberType NoteProperty -Name "NetInterfaceDescription" -Value "$ComputerNetInterfaceDescription" -Force
    $tempnetwork | Add-Member -MemberType NoteProperty -Name "NetProfileName" -Value "$ComputerNetProfileName" -Force
    $tempnetwork | Add-Member -MemberType NoteProperty -Name "NetIPv4Adress" -Value "$ComputerNetIPv4Adress" -Force
    $tempnetwork | Add-Member -MemberType NoteProperty -Name "NetInterfaceAlias" -Value "$ComputerNetInterfaceAlias" -Force
    $tempnetwork | Add-Member -MemberType NoteProperty -Name "NetIPv4DefaultGateway" -Value "$ComputerNetIPv4DefaultGateway" -Force
    $tempnetwork | Add-Member -MemberType NoteProperty -Name "MacAddress" -Value "$ComputerNetMacAddress" -Force
    $NetWorkArray += $tempnetwork
}
[System.Collections.ArrayList]$NetWorkArrayList = $NetWorkArray
#endregion
######################################################################




#Region Script
if ($collectEvents) {
#Build our XML query - Don't tab this in.
$SearchXML = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
    *[System[(EventID=4779) and TimeCreated[@SystemTime&gt;='$MarkerFileTimeUTC' and @SystemTime&lt;='$DateCurrentUTC']]]
    </Select>
  </Query>
</QueryList>
'@

#Expand Variables inside the query
$SearchXML = $ExecutionContext.InvokeCommand.ExpandString($SearchXML)

    #Search events and write them into variable
    $SecurityEventsForUpload = Get-WinEvent -FilterXML $SearchXML
    $SecutiyLogInventory = $SecurityEventsForUpload


    $SecurityLogArray = @()
    $SecutiyLogInventory | ForEach-Object -Process {
        $SecurityTempLogArray = New-Object System.Object


        
      
        ###Create our table for RDP disconnect events###
         if ($_.ID -eq 4779) {
            #Convert log times from local time to UTC
            $TimeOfLogUTC = $_.TimeCreated.ToUniversalTime()

            $User = $_.properties | Select-Object -Index 0
            $User = $User.value
            
            
            #We only care about non-system logons
            if ($user -ne "SYSTEM") {
                write-host "RDP-Disconnect event found"
                
                #Trim the generic RDP disconnect message to save $
                $Message = $_.Message | Out-String
                $Message = $Message.trimend("")
                $Message = $Message.trimend("This event is generated when a user disconnects from an existing Terminal Services session, or when a user switches away from an existing desktop using Fast User Switching.")

                            #If we are here, an event is being added.
                            $EventCount = $EventCount + 1
            #These are our log columns that we add, and what value we give that column
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "RDP-Disconnect" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($Message)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
            
            $SecurityLogArray += $SecurityTempLogArray
            }
            
            }
        }



            #While it is possible to query just the most recent startup event, that relies on there even being a log of it. Rather than look for the most recent log, just use the system value. In testing it's off by less than 10 seconds.
               ### #Create our table for startup###
                $SystemStartLogArray = @()
                $SystemStartTempLogArray = New-Object System.Object
                $ComputerOSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
                $ComputerLastBoot = $ComputerOSInfo.LastBootUpTime
                $ComputerLastBoot =  $ComputerLastBoot.ToUniversalTime()
                write-host "Startup Logged"
            
                #These are our log columns that we add, and what value we give that column
                            #If we are here, an event is being added.
                            if ($AlwaysReportStartup -eq $true){
                                $EventCount = $EventCount + 1
                            }
                            
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force 
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force   
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($ComputerLastBoot)" -Force
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Startup" -Force
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "The operating system started at system time $($ComputerLastBoot)Z" -Force
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
                $SystemStartLogArray += $SystemStartTempLogArray
                
                




#ShortPath
$ShortPathXML = @'
<QueryList>
    <Query Id="0" Path="Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational">
        <Select Path="Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational">
            *[System[(EventID=135) and TimeCreated[@SystemTime&gt;='$MarkerFileTimeUTC' and @SystemTime&lt;='$DateCurrentUTC']]]</Select>
    </Query>
</QueryList>
'@

#Expand Variables inside the query
$ShortPathXML = $ExecutionContext.InvokeCommand.ExpandString($ShortPathXML)
            
        $ShortPathEvents = Get-WinEvent -FilterXML $ShortPathXML


        $ShortPathLogArray = @()
        $ShortPathEvents | ForEach-Object -Process {
        $ShortPathTempLogArray = New-Object System.Object
    
    
        #Convert all log times from local time to UTC
        $TimeOfLogUTC = $_.TimeCreated.ToUniversalTime()
        
               ### #Create our table for TCP UDP###
               if ($_.message -like "*Tunnel: 1*"){
                write-host "Tunnel 1 RDP-Core event found"
            
                #Null it each time
                $EventType = $null
                if ($_.Message -like "*transport type set to TCP*"){
                    $EventType = "TCP Connection"
                }
                if ($_.Message -like "*transport type set to UDP*"){
                    $EventType = "UDP Connection"
                }
                

                #These are our log columns that we add, and what value we give that column
                            #If we are here, an event is being added.
                            $EventCount = $EventCount + 1
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force 
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force   
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "$EventType" -Force
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "" -Force
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
                $ShortPathTempLogArray | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
                $ShortPathLogArray += $ShortPathTempLogArray
                }
        }

    }#End our $collectEvents
    




######################################################  
#Combine all logs
$FinalLog += $SecurityLogArray += $SystemStartLogArray += $ShortPathLogArray
######################################################


######################################################
#Prepare Array for Upload via Azure Function App
######################################################


$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

$RawEvents = $FinalLog
$FinalLog = $FinalLog | ConvertTo-Json -Depth 3
$FinalLog = "[" + "
$($FinalLog)
" + "]"

$LogPayLoad = New-Object -TypeName PSObject 
$LogPayLoad | Add-Member -NotePropertyMembers @{$LogName = $FinalLog }


# Create body for Function App request
$BodyTable = New-AADDeviceTrustBody

# Optional - extend body table with additional data
$BodyTable.Add("Table", "$($Table)")
$BodyTable.Add("DcrImmutableId", "$($DcrImmutableId)")
$BodyTable.Add("LogPayloads", $LogPayLoad) # NOTE THE DIFFERENT FORMATTING FOR THIS FIELD!!!! 





#Start sending logs
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "




# Sending data to API

    if ($EventCount -ge 1) {

        if ($WriteLogFile){
        write-host "NOT UPLOADING - writting local log file(s)!"
        New-Item C:\Temp -ItemType Directory -ErrorAction SilentlyContinue > $null 
        New-Item C:\Temp\LogAnalytics -ItemType Directory -ErrorAction SilentlyContinue > $null 
        $BodyTable | ConvertTo-Json -Depth 3 | Out-File "C:\Temp\LogAnalytics\$($LogName)-Full.json"
        $RawEvents | ConvertTo-Json -Depth 3 | Out-File "C:\Temp\LogAnalytics\$($LogName)-RAW.json"
        $ResponseInventory = "Log File Enabled - Not sending!"
        exit 1
        }
        
        if ($WriteLogFile -eq $false){    
        # Submit the data to the API endpoint
        write-host "$($EventCount) - number of logs found"

        #Randomize over 50 minutes to spread load on Azure Function - disabled on date of enrollment 
        $JoinDate = Get-AzureADJoinDate
        $DelayDate = $JoinDate.AddDays(1)
        $CompareDate = ($DelayDate - $JoinDate)
        if ($CompareDate.Days -ge 1){
            if($Delay -eq $true){
            $ExecuteInSeconds = (Get-Random -Maximum 3000 -Minimum 1)
            Write-Output "Delay enabled - Randomzing execution time by $($ExecuteInSeconds)"
            Start-Sleep -Seconds $ExecuteInSeconds
            }
        }

        write-host "Sending Logs!"
        #Upload Data
        $ResponseInventory = Invoke-RestMethod -Method "POST" -Uri $AzureFunctionURL -Body ($BodyTable | ConvertTo-Json -depth 9) -ContentType "application/json" -ErrorAction Stop
        }




    } else {
        #If the events were not greater than or equal to 1, log an output
        $ResponseInventory = "No events to send!"
        write-warning "No Events found, updating time range from $($MarkerFileTimeUTC) to $($DateCurrentUTC)"
        Set-Content "C:\Windows\LogAnalytics\windows365EventCollector.txt" "$($DateCurrentUTC)" -Force
        $EventCount = "0"
    }




#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

#write Response
write-host "Value of Response for $($LogName) is $($ResponseInventory)"

if ($collectEvents) {
    if ($ResponseInventory -match "204:") {
        
        $OutputMessage = $OutPutMessage + " $($LogName):OK " 
        #Update our last run file only if success is logged
        Set-Content "C:\Windows\LogAnalytics\windows365EventCollector.txt" "$($DateCurrentUTC)" -Force
    
    }
    else {
        $OutputMessage = $OutPutMessage + " $($LogName):Fail "
    }
}
Write-Output "Output: $($OutputMessage) *** Response: $($ResponseInventory) *** Number of logs found: $($EventCount)"

Exit 0

#Endregion
######################################################################
