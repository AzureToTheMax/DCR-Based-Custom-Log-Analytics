#Sample Data Script

<#
.SYNOPSIS
Sample Data Collector for use with the generic Log Analytics DCR ingestion guide.
            
.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2023-02-28
Updated:     2023-02-28

            
Version history:
1 - 2023-02-28 Created
2 - 2023-05-27 Updated to use AADDeviceTrust

#>


######################################################################
#Region Variables
#Controls various Script customizeable Variables

#Script Version - Used for update tracking and version specific queries.
$ScriptVersion = "3"

#FunctionAppURI for Log Upload
$AzureFunctionURL = "Your Function App URI"

#Custom table name including _CL
$Table = "Your Table Name_CL"

#DCR to reach that table
$DcrImmutableId = "Your DCR ID"

#Enable data collection. Default is True.
$CollectData = $true

#Friendly log name. Name it what you want. Just used for logging, local JSON export, and the name the data is referenced by inside the JSON.
$LogName = "SampleCollection"

$Date = (Get-Date)

#Leave it blank
$TimeStampField = ""

#Export to JSON for DCR Creation - Should be false
$WriteLogFile = $false

#Enable or disable the log upload delay. True/False. Default is $True.
$Delay = $true

#Endregion
######################################################################




######################################################################
#region functions
#Azure Function App Functions - Updated by Max Allen to account for proper locating of cert for ID and Time
#Get-AzureADDeviceID
#Get-AzureADJoinDate
#Get-AzureADTenantID
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

function Get-AzureADTenantID {
    # Cloud Join information registry path
    $AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
    # Retrieve the child key name that is the tenant id for AzureAD
    $AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
    return $AzureADTenantID
} #endfunction       


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
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
        1.0.1 - (2022-10-20) @AzureToTheMax - Fixed issue pertaining to Cloud PCs (Windows 365) devices ability to locate their AzureADDeviceID.
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

                # Handle return value
                return $AzureADDeviceID

            } else {

                #If no certificate was found, locate it by Common Name instead of Thumbprint. This is likely a CPC or similar.
                $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=($AzureADJoinInfoThumbprint)" }

                    if ($AzureADJoinCertificate -ne $null){
                    # Cert is now found, extract Device ID from Common Name
                    $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                    # Handle return value
                    return $AzureADDeviceID

                    } else {
                    # Last ditch effort, try and use the ThumbPrint (reg key) itself.
                    $AzureADDeviceID=$AzureADJoinInfoThumbprint
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
 



#Enable TLS 1.2 Support
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                   
######################################################################








#Get Common Data
#Get Intune DeviceID and ManagedDeviceName

if(@(Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
    $MSDMServerInfo = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
    $ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
}

$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

#Get computer info
$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name

#region Collect Data
if($CollectData) {
   
	#Get network adapters
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

	$users = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $_.GetOwner() } | Select-Object -Unique -Expand User
	$ComputerOSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
	$ComputerLastBoot = $ComputerOSInfo.LastBootUpTime
    $ComputerUpTime = [int](New-TimeSpan -Start $ComputerLastBoot -End $Date).Days
	
	
	# Create JSON to Upload to Log Analytics
	$Inventory = New-Object System.Object
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ActiveUser" -Value "$users" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerUpTime" -Value "$ComputerUptime" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force

	$DevicePayLoad = $Inventory
	
}
#endregion DEVICEINVENTORY







######################################################
#Prepare Array for Upload via Azure Function App
######################################################
#Get Common data for validation in Azure Function: 
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")



#Format Data for Submission to DCR
$RawEvents = $DevicePayLoad 
$DevicePayLoad =  $DevicePayLoad | ConvertTo-Json
$DevicePayLoad = "[" + "
$($DevicePayLoad)
" + "]"


#Format data for Function App
$LogPayLoadApp = New-Object -TypeName PSObject 
$LogPayLoadApp | Add-Member -NotePropertyMembers @{$LogName = $DevicePayLoad }

# Create body for Function App request
$BodyTable = New-AADDeviceTrustBody

# Optional - extend body table with additional data
$BodyTable.Add("Table", "$($Table)")
$BodyTable.Add("DcrImmutableId", "$($DcrImmutableId)")
$BodyTable.Add("LogPayloads", $LogPayLoadApp) # NOTE THE DIFFERENT FORMATTING FOR THIS FIELD!!!! 

    if ($WriteLogFile){
    write-host "writing log file"
    New-Item C:\Temp -ItemType Directory -ErrorAction SilentlyContinue > $null 
    New-Item C:\Temp\LogAnalytics -ItemType Directory -ErrorAction SilentlyContinue > $null 
	$BodyTable | ConvertTo-Json -depth 9 | Out-File "C:\Temp\LogAnalytics\$($LogName)-Full.json"
	$RawEvents | ConvertTo-Json | Out-File "C:\Temp\LogAnalytics\$($LogName)-RAW.json"
	write-host "Log File Enabled - Not sending!"
	exit 1

	} else {

	# Submit the data to the API endpoint
    #Write upload intent to console
    Write-Output "Sending Payload..."
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
        
		
		#Function App Upload Commands - Send the data! 
        $ResponseSampleCollector = Invoke-RestMethod -Method "POST" -Uri $AzureFunctionURL -Body ($BodyTable | ConvertTo-Json -depth 9) -ContentType "application/json" -ErrorAction Stop

       

    }






#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

if ($CollectData) {
    if ($ResponseSampleCollector -match "204:") {
        
        $OutputMessage = $OutPutMessage + " SampleCollector:OK " + $ResponseSampleCollector
    }
    else {
        $OutputMessage = $OutPutMessage + " SampleCollector:Fail "
    }
}
Write-Output $OutputMessage
Exit 0
