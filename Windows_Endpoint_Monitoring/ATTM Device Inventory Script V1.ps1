#Windows Endpoint Device Inventory Script.

<#
.SYNOPSIS
Windows Endpoint Device Inventory Script

This script collects information regarding various aspects of the device including hardware information, software information, and local admin accounts. 
This information is then sent to an Azure Function App in a DCR format. This script is designed to use the Function App created by AzureToTheMax which uses the latest certificate-based authentication.

For information regarding this collector, see the "PowerShell DCR Log Analytics for Windows Endpoints" series...
https://azuretothemax.net/2023/07/27/powershell-dcr-log-analytics-for-windows-endpoints-part-1-0-device-inventory-overview/

            
.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2023-07-30
Updated:     2023-07-30
Based on the work of Nickolaj Andersen - @NickolajA, and the MSEndpointMGR team. 
This is based on their original device inventory.


   
Version history:
1 - 2023-07-27 Created
Improvements over original script from MSEndpointMGR team...
	1. Added PrimaryUserUPN field
		- Value is very difficult to locate sometimes depending on how/when the machine is fully/partially Azure Joined.
	2. Corrected CPC- ability to determine current user as well as for RDP connections. This effects app inventory’s ability to 
	3. Added Drive Remaining Space Values
	4. Added Script Version field
	5. Corrected Output Message Creation
	6. $ComputerInstalledDate - this value was being collected by the script however the actual XML building used the variable named $ComputerInstallDate (install versus installed) and thus no data was being uploaded to this field.
	7. Corrected typo in HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings\).AllowAutoWindowsUpdateDownloadOverMeteredNetwork (note the ")" )
		- Despite this new code working in a PowerShell running as my admin-, it does not work in my VS.
		- later removed this entirely as it's better served in the patching collector.
	8. Corrected gathering AppInstallDate. Data was not being collected nor converted. 
		- Corrected app install date issue where Null values inherited the date of the previous app
	9. Corrected TPM info
		- Added TPMEnabled from formerly line 252
	10. Corrected Bitlocker Info
		- Remove "-property *" from formerly line 265
	11. Fixed function Get-AzureADDeviceID
	12. Fixed the output message determination. Original code made little sense. The status code is returned in the output message so why they defaulted to success and then re-determined from the status code was very odd.
	13. Added SMBv1 detection
	14. Compacted HDD space into single array for better query compatibility.
	15. Changed App Inventory to use a GUID for query comparisons. This is superior over single-array and time-based comparisons. 
	17. Fixed issue in BIOS version gathering (alternate query for better compatibility)
	18. Added SecureBoot
		- Added Null check for Secure Boot
		- Made SecureBoot use Enabled/Disabled rather than True/False
	19. Compacted AdminInventory into a single array for quickly determining the latest accurate information
	20. Added a null check to the Install Date Conversions to avoid the annoying warnings whenever we try to convert an app with a null value. 
	21. Updated to a DCR Function App
		- Updated to use latest authentication
	
	

#>




######################################################################


#Region Variables
#Controls various Script customizable Variables

#Script Version
$ScriptVersion = "1"

#Function App URL for Log Upload
$AzureFunctionURL = "Your Function App URI"

#Custom table name including _CL
$DeviceInventory_Table = "DeviceInventory_CL"
$AppInventory_Table = "AppInventory_CL"
$AdminInventory_Table = "AdminInventory_CL"

#DCR to reach that table
$DeviceInventory_DcrImmutableId = "Your Immutable ID"
$AppInventory_DcrImmutableId = "Your Immutable ID"
$AdminInventory_DcrImmutableId = "Your Immutable ID"

#Enable/disable various inventory collections
$CollectDeviceInventory = $true
$CollectAppInventory = $true
$collectAdminInventory = $true

#Friendly log name. Name it what you want. Just used for logging, local JSON export, the name the data is referenced by inside the JSON, and log control on the function app.
$DeviceLogName = "DeviceInventory"
$AppLogName = "AppInventory"
$adminLogName = "AdminInventory"
$Date = (Get-Date)

#Export to JSON for DCR Creation - Should be false
$WriteLogFile = $false

#Enable or disable the log upload delay. True/False. Default is $True.
$Delay = $true

#Set FooUser Values
$TenantDomain = "fooUser@YOURTENANT.onmicrosoft.com"
$CustomTenantDomain = "fooUser@YourDomain.net"

#Leave it blank
$TimeStampField = ""

#Endregion
######################################################################


#Enable TLS 1.2 Support
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#We need to get the SID via the below only if the device is NOT a CPC
$ComputerNameForSID = $env:COMPUTERNAME


######################################################################
#region functions
#Get-AzureADJoinDate
#Get-AzureADTenantID
#Get-InstalledApplications 
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

#Function to get AzureAD TenantID
function Get-AzureADTenantID {
    # Cloud Join information registry path
    $AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
    # Retrieve the child key name that is the tenant id for AzureAD
    $AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
    return $AzureADTenantID
} #endfunction       


#Get Installed Applications
function Get-InstalledApplications {
    param(
        [string]$UserSid
    )

    New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
    $regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    if(-not ([IntPtr]::Size -eq 4)){
        $regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString', 'InstallDate'
    $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process {if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, InstallDate, PSPath | Sort-Object DisplayName
    Remove-PSDrive -Name "HKU" | Out-Null
    Return $Apps
}#endfunction 


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
        1.0.1 - (2023-05-10) Max - Updated to no longer use Thumbprint field, no redundant.
        1.0.2 - (2023-05-14) Max - Updating to pull the Azure AD Device ID from the certificate itself.
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
        1.0.1 - (2022-10-20) Max - Fixed issue pertaining to Cloud PCs (Windows 365) devices ability to locate their AzureADDeviceID.
        1.0.2 - (2023-06-20) Max - Fixed issue pertaining to Cloud PCs (Windows 365) devices where the reported AzureADDeviceID was in all capitals, breaking signature creation.

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
        1.0.1 - (2023-05-10) Max Updated for Cloud PCs which don't have their thumbprint as their JoinInfo key name.
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
        1.0.1 - (2023-05-10) Max - Updated to use X509 for the full public key with extended properties in the PEM format

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

#endregion
######################################################################


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
$ComputerManufacturer = $ComputerInfo.Manufacturer

if($ComputerManufacturer -match "HP|Hewlett-Packard"){
    $ComputerManufacturer = "HP"
}

if($CollectDeviceInventory) {
    $DefaultAUService = (New-Object -ComObject "Microsoft.Update.ServiceManager").Services | Where-Object { $_.isDefaultAUService -eq $True }

    $ComputerOSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $ComputerBiosInfo = Get-CimInstance -ClassName Win32_Bios
    $ComputerModel = $ComputerInfo.Model
    $ComputerLastBoot = $ComputerOSInfo.LastBootUpTime
    $ComputerUpTime = [int](New-TimeSpan -Start $ComputerLastBoot -End $Date).Days
    $ComputerInstalledDate = $ComputerOSInfo.InstallDate
    $DisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
    if([string]::IsNullOrEmpty($DisplayVersion)){
        $ComputerWindowsVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
    } else {
        $ComputerWindowsVersion = $DisplayVersion
    }
    $ComputerOSName = $ComputerOSInfo.Caption
	$ComputerSystemSkuNumber = $ComputerInfo.SystemSKUNumber
	$ComputerSerialNr = $ComputerBiosInfo.SerialNumber
	$ComputerBiosUUID = Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
	$ComputerBiosVersion = $ComputerBiosInfo.SMBIOSBIOSVersion
	$ComputerBiosDate = $ComputerBiosInfo.ReleaseDate
	$ComputerFirmwareType = $env:firmware_type
	$PCSystemType = $ComputerInfo.PCSystemType
		switch ($PCSystemType){
			0 {$ComputerPCSystemType = "Unspecified"}
			1 {$ComputerPCSystemType = "Desktop"}
			2 {$ComputerPCSystemType = "Laptop"}
			3 {$ComputerPCSystemType = "Workstation"}
			4 {$ComputerPCSystemType = "EnterpriseServer"}
			5 {$ComputerPCSystemType = "SOHOServer"}
			6 {$ComputerPCSystemType = "AppliancePC"}
			7 {$ComputerPCSystemType = "PerformanceServer"}
			8 {$ComputerPCSystemType = "Maximum"}
			default {$ComputerPCSystemType = "Unspecified"}
		}
	$PCSystemTypeEx = $ComputerInfo.PCSystemTypeEx
		switch ($PCSystemTypeEx){
			0 {$ComputerPCSystemTypeEx = "Unspecified"}
			1 {$ComputerPCSystemTypeEx = "Desktop"}
			2 {$ComputerPCSystemTypeEx = "Laptop"}
			3 {$ComputerPCSystemTypeEx = "Workstation"}
			4 {$ComputerPCSystemTypeEx = "EnterpriseServer"}
			5 {$ComputerPCSystemTypeEx = "SOHOServer"}
			6 {$ComputerPCSystemTypeEx = "AppliancePC"}
			7 {$ComputerPCSystemTypeEx = "PerformanceServer"}
			8 {$ComputerPCSystemTypeEx = "Slate"}
			9 {$ComputerPCSystemTypeEx = "Maximum"}
			default {$ComputerPCSystemTypeEx = "Unspecified"}
		}
		
	$ComputerPhysicalMemory = [Math]::Round(($ComputerInfo.TotalPhysicalMemory / 1GB))
	$ComputerOSBuild = $ComputerOSInfo.BuildNumber
	$ComputerOSRevision = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	$ComputerCPU = Get-CimInstance win32_processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors
	$ComputerProcessorManufacturer = $ComputerCPU.Manufacturer | Get-Unique
	$ComputerProcessorName = $ComputerCPU.Name | Get-Unique
	$ComputerNumberOfCores = $ComputerCPU.NumberOfCores | Get-Unique
	$ComputerNumberOfLogicalProcessors = $ComputerCPU.NumberOfLogicalProcessors | Get-Unique
	$ComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()

    try {
        $TPMValues = Get-Tpm -ErrorAction SilentlyContinue | Select-Object -Property TPMReady, TPMPresent, TPMActivated, TPMEnabled, ManagedAuthLevel
    }  catch {
        $TPMValues = $null
    }
    try {
        $ComputerTPMThumbprint = (Get-TpmEndorsementKeyInfo).AdditionalCertificates.Thumbprint
    } catch {
        $ComputerTPMThumbprint = $null
    }
    try {
        $BitLockerInfo = Get-BitLockerVolume -MountPoint $env:SystemDrive
    }
    catch {
        $BitLockerInfo = $null
    }
	try {
		$ComputerTPMVersion = Get-WmiObject -NameSpace 'root\cimv2\security\microsofttpm' -Class Win32_tpm | Select-Object -ExpandProperty specVersion
	}
	catch {
		$ComputerTPMVersion = $null
	}

    $ComputerTPMReady = $TPMValues.TPMReady
	$ComputerTPMPresent = $TPMValues.TPMPresent
	$ComputerTPMEnabled = $TPMValues.TPMEnabled
	$ComputerTPMActivated = $TPMValues.TPMActivated
	
	
	$ComputerBitlockerCipher = $BitLockerInfo.EncryptionMethod
	$ComputerBitlockerStatus = $BitLockerInfo.VolumeStatus
	$ComputerBitlockerProtection = $BitLockerInfo.ProtectionStatus
	$ComputerDefaultAUService = $DefaultAUService.Name


    # Get BIOS information
	# Determine manufacturer specific information
	switch -Wildcard ($ComputerManufacturer) {
		"*Microsoft*" {
			$ComputerManufacturer = "Microsoft"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$ComputerSystemSKU = Get-WmiObject -Namespace root\wmi -Class MS_SystemInformation | Select-Object -ExpandProperty SystemSKU
		}
		"*HP*" {
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$ComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct.Trim()
			
			# Obtain current BIOS release
			$CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
			
			# Detect new versus old BIOS formats
			switch -wildcard ($($CurrentBIOSProperties.SMBIOSBIOSVersion)) {
				"*ver*" {
					if ($CurrentBIOSProperties.SMBIOSBIOSVersion -match '.F.\d+$') {
						$ComputerBiosVersion = ($CurrentBIOSProperties.SMBIOSBIOSVersion -split "Ver.")[1].Trim()
					} else {
						$ComputerBiosVersion = [System.Version]::Parse(($CurrentBIOSProperties.SMBIOSBIOSVersion).TrimStart($CurrentBIOSProperties.SMBIOSBIOSVersion.Split(".")[0]).TrimStart(".").Trim().Split(" ")[0])
					}
				}
				default {
					$ComputerBiosVersion = "$($CurrentBIOSProperties.SystemBiosMajorVersion).$($CurrentBIOSProperties.SystemBiosMinorVersion)"
				}
			}
		}
		"*Dell*" {
			$ComputerManufacturer = "Dell"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$ComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()
			
			# Obtain current BIOS release
			$ComputerBiosVersion = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
			
		}
		"*Lenovo*" {
			$ComputerManufacturer = "Lenovo"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version).Trim()
			$ComputerSystemSKU = ((Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).SubString(0, 4)).Trim()
			
			# Obtain current BIOS release
			$CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
			
			# Obtain current BIOS release
			#$ComputerBiosVersion = ((Get-WmiObject -Class Win32_BIOS | Select-Object -Property *).SMBIOSBIOSVersion).SubString(0, 8)
			$ComputerBiosVersion = "$($CurrentBIOSProperties.SystemBiosMajorVersion).$($CurrentBIOSProperties.SystemBiosMinorVersion)"
		}
	}
	
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
	
	# Get Disk Health
	$DiskArray = @()
	$Disks = Get-PhysicalDisk | Where-Object { $_.BusType -match "NVMe|SATA|SAS|ATAPI|RAID" }
	
	# Loop through each disk
	foreach ($Disk in ($Disks | Sort-Object DeviceID)) {
		# Obtain disk health information from current disk
		$DiskHealth = Get-PhysicalDisk -UniqueId $($Disk.UniqueId) | Get-StorageReliabilityCounter | Select-Object -Property Wear, ReadErrorsTotal, ReadErrorsUncorrected, WriteErrorsTotal, WriteErrorsUncorrected, Temperature, TemperatureMax
		
		# Obtain media type
		$DriveDetails = Get-PhysicalDisk -UniqueId $($Disk.UniqueId) | Select-Object MediaType, HealthStatus
		$DriveMediaType = $DriveDetails.MediaType
		$DriveHealthState = $DriveDetails.HealthStatus
		$DiskTempDelta = [int]$($DiskHealth.Temperature) - [int]$($DiskHealth.TemperatureMax)
		
		# Create custom PSObject
		$DiskHealthState = new-object -TypeName PSObject
		
		
		# Create disk entry
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk Number" -Value $Disk.DeviceID
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $($Disk.FriendlyName)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "HealthStatus" -Value $DriveHealthState
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "MediaType" -Value $DriveMediaType
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk Wear" -Value $([int]($DiskHealth.Wear))
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) Read Errors" -Value $([int]($DiskHealth.ReadErrorsTotal))
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) Temperature Delta" -Value $DiskTempDelta
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) ReadErrorsUncorrected" -Value $($Disk.ReadErrorsUncorrected)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) ReadErrorsTotal" -Value $($Disk.ReadErrorsTotal)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) WriteErrorsUncorrected" -Value $($Disk.WriteErrorsUncorrected)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) WriteErrorsTotal" -Value $($Disk.WriteErrorsTotal)




		
		$DiskArray += $DiskHealthState
		[System.Collections.ArrayList]$DiskHealthArrayList = $DiskArray

	}
	

	#Get UPN
	$EnrollmentRegisty = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments\*') | Get-ItemProperty -name 'UPN' -ErrorAction SilentlyContinue
	$EnrollmentUPN = $EnrollmentRegisty.UPN
	$EnrollmentRegistyPath = $EnrollmentRegisty | Select-Object PSChildName -ErrorAction SilentlyContinue
	$EnrollmentRegistyPath = $EnrollmentRegistyPath.PSChildName
	
	
	if ($EnrollmentUPN -ne $CustomTenantDomain -and $EnrollmentUPN -ne $TenantDomain) {
		$UPN = $EnrollmentUPN
		}
	
	
	If ($EnrollmentUPN -eq $CustomTenantDomain -or $EnrollmentUPN -eq $TenantDomain) {
		$SIDQuery = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments\$($EnrollmentRegistyPath)\FirstSync" | Select-Object PSChildName
		$SIDQuery = $SIDQuery.PSChildName
		New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
		$UPN = Get-ChildItem "HKU:\$SIDQuery" | Get-ItemProperty -name 'USERNAME'
		$UPN = $UPN.USERNAME
		
			if ($UPN -eq $Null){
			$UPN = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments\$($EnrollmentRegistyPath)\DMClient" | Get-ItemProperty -name 'EntDeviceName' -ErrorAction SilentlyContinue
			$UPN = $UPN.EntDeviceName
			$UPN = $UPN.Substring(0, $UPN.IndexOf('_'))
			}
	}



	#Check SMBv1 Status
	$SMBv1Status = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).state

	#Check Secure Boot
	$SecureBoot = Confirm-SecureBootUEFI

	#If not Null, change True/False to Enabled/Disabled
	if ($SecureBoot -ne $Null){
			if ($SecureBoot -eq $True){
				$SecureBoot = "Enabled"
	
			}
			if ($SecureBoot -eq $False){
				$SecureBoot = "Disabled"
			}
	}

	#Apparently Secure Boot can, in addition to true/false, return a "not supported on this platform" error.
	#Since this is likely to be true of some other platforms, I am adding this check for if the result is "null" and if so, set to not supported.
	if ($SecureBoot -eq $null){
		$secureboot = "Not Supported"
	}


	#Get and add disk free space
	$DiskArray2 = @()
	$DiskSpaceArray = new-object -TypeName PSObject
		$DriveStorage = get-volume 
		$DriveStorage | ForEach-Object -Process {
			if ($_.DriveLetter -ne $null -and $_.DriveType -ne "CD-ROM" -and $_.DriveType -ne "Removable"){
				$SizeRemaining =  $_.SizeRemaining
				$SizeRemaining = [math]::round($SizeRemaining /1Gb, 2)
				$DiskSpaceArray | Add-Member -MemberType NoteProperty -Name "Disk_$($_.DriveLetter)_FreeSpaceGB" -Value $($SizeRemaining)
				
			}
		}
		
		$DiskArray2 += $DiskSpaceArray
		[System.Collections.ArrayList]$DiskSpaceArrayList = $DiskArray2


	
	# Create JSON to Upload to Log Analytics
	$Inventory = New-Object System.Object
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Model" -Value "$ComputerModel" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value "$ComputerManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "PCSystemType" -Value "$ComputerPCSystemType" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "PCSystemTypeEx" -Value "$ComputerPCSystemTypeEx" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerUpTime" -Value "$ComputerUptime" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "PrimaryUserUPN" -Value "$UPN" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "LastBoot" -Value "$ComputerLastBoot" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value "$ComputerInstalledDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "WindowsVersion" -Value "$ComputerWindowsVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DefaultAUService" -Value "$ComputerDefaultAUService" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SystemSkuNumber" -Value "$ComputerSystemSkuNumber" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value "$ComputerSerialNr" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SMBIOSUUID" -Value "$ComputerBiosUUID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosVersion" -Value "$ComputerBiosVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosDate" -Value "$ComputerBiosDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SystemSKU" -Value "$ComputerSystemSKU" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "FirmwareType" -Value "$ComputerFirmwareType" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Memory" -Value "$ComputerPhysicalMemory" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSBuild" -Value "$ComputerOSBuild" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSRevision" -Value "$ComputerOSRevision" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSName" -Value "$ComputerOSName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUManufacturer" -Value "$ComputerProcessorManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUName" -Value "$ComputerProcessorName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUCores" -Value "$ComputerNumberOfCores" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPULogical" -Value "$ComputerNumberOfLogicalProcessors" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMReady" -Value "$ComputerTPMReady" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMPresent" -Value "$ComputerTPMPresent" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMEnabled" -Value "$ComputerTPMEnabled" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMActived" -Value "$ComputerTPMActivated" -Force
	$Inventory | Add-Member -MemberType NoteProperty -name "TPMVersion" -Value "$ComputerTPMVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMThumbprint" -Value "$ComputerTPMThumbprint" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerCipher" -Value "$ComputerBitlockerCipher" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerVolumeStatus" -Value "$ComputerBitlockerStatus" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerProtectionStatus" -Value "$ComputerBitlockerProtection" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DiskHealth" -Value $DiskHealthArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DiskSpace" -Value $DiskSpaceArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SMBv1Status" -Value "$SMBv1Status" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SecureBoot" -Value "$SecureBoot" -Force
	
			


	$DevicePayLoad = $Inventory
	
}
#endregion DEVICEINVENTORY






#region APPINVENTORY
if ($CollectAppInventory) {
	
	#Get SID of current interactive users
	If ($ComputerNameForSID -notlike "*CPC-*") {
			#write-host "not CPC"
			$CurrentLoggedOnUser = (Get-CimInstance win32_computersystem).UserName
		if (-not ([string]::IsNullOrEmpty($CurrentLoggedOnUser))) {
			$AdObj = New-Object System.Security.Principal.NTAccount($CurrentLoggedOnUser)
			$strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
			$UserSid = $strSID.Value
		} else {

			#If it is null, this may be an RDP connection, try using Explorer.exe owner
			$users = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $_.GetOwner() } | Select-Object -Unique -Expand User

			if ($users -ne $null) {
				#Set HKU drive if not set
				New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
				#Find the username values in SID path
				$value1 = (Get-ChildItem 'HKU:\*\Volatile Environment\') | Get-ItemProperty -name 'USERNAME' 
				#Get the path to that matching key
				$value2 = $value1 | Where-Object {$_."USERNAME" -like "$($users)"} | Select-Object PSParentPath
				#pull the string not the full values
				$value2 = $value2.PSParentPath
				#Remove first 47 characters before the SID "Microsoft.PowerShell.Core\Registry::HKEY_USERS\"
				$value3 = $value2.substring(47)
				$UserSid = $value3
			} else {
			$UserSid = $null
			}
		}
	}
	
	If ($ComputerNameForSID -like "*CPC-*") {
		#This is a CPC - we NEED to use Explorer.exe now. This is slightly redundant as it's included above although, both sections shouldn't run.
		#write-host "CPC"
		$users = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $_.GetOwner() } | Select-Object -Unique -Expand User

		if ($users -ne $null) {
			#Set HKU drive if not set
			New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
			#Find the username values in SID path
			$value1 = (Get-ChildItem 'HKU:\*\Volatile Environment\') | Get-ItemProperty -name 'USERNAME' 
			#Get the path to that matching key
			$value2 = $value1 | Where-Object {$_."USERNAME" -like "$($users)"} | Select-Object PSParentPath
			#pull the string not the full values
			$value2 = $value2.PSParentPath
			#Remove first 47 characters before the SID "Microsoft.PowerShell.Core\Registry::HKEY_USERS\"
			$value3 = $value2.substring(47)
			$UserSid = $value3
		} else {
		$UserSid = $null

		}
	}
		
	
	#Get Apps for system and current user
	$MyApps = Get-InstalledApplications -UserSid $UserSid
	$UniqueApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateApp = ($DuplicatedApps | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppList = $UniqueApps + $NewestDuplicateApp | Sort-Object DisplayName
	
	#GUID generation for Log Analytics Queries
	$UploadGUIDGUID = New-Guid

	$AppArray = @()
	foreach ($App in $CleanAppList) {
		$tempapp = New-Object -TypeName PSObject
		
		#Null check to avoid annoying warnings due to failures to convert null values.
		if ($App.InstallDate -ne $null){
		$AppInstallDate = [Datetime]::ParseExact($($App.InstallDate), 'yyyymmdd', $null).ToString('mm-dd-yyyy')
		}
		
		$tempapp | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppName" -Value $App.DisplayName -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $App.DisplayVersion -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppInstallDate" -Value $AppInstallDate -Force -ErrorAction SilentlyContinue
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppPublisher" -Value $App.Publisher -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallString" -Value $App.UninstallString -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallRegPath" -Value $app.PSPath.Split("::")[-1]
		$tempapp | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "UploadGUID" -Value $UploadGUIDGUID.guid -Force

		$AppArray += $tempapp
	}
	
	
	$AppPayLoad = $AppArray
}
#endregion APPINVENTORY


#Region LocalAdminInventory
if ($collectAdminInventory) {

    $localAdministratorArray = @()

    $administratorsGroup = ([ADSI]"WinNT://$env:COMPUTERNAME").psbase.children.find("Administrators")
    $administratorsGroupMembers= $administratorsGroup.psbase.invoke("Members")

    foreach ($administrator in $administratorsGroupMembers) { 
		$TempAdmin = new-object -TypeName PSObject
		$localAdmin = $administrator.GetType().InvokeMember('Name','GetProperty',$null,$administrator,$null)
		$TempAdmin | Add-Member -MemberType NoteProperty -Name "Admin" -Value "$localAdmin" -force
		$localAdministratorArray += $TempAdmin 
    }
	
	[System.Collections.ArrayList]$localAdministratorsArrayList =  $localAdministratorArray

	$adminArray = @()
        $tempAdminArray = New-Object System.Object
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
		$tempAdminArray  | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "LocalAdministrators" -Value $localAdministratorsArrayList -Force
        $adminArray += $tempAdminArray

		$AdminPayLoad = $adminArray
     

}
#Endregion LocalAdminInventory







######################################################
#Prepare Array for Upload via Azure Function App
######################################################
#Get Common data for validation in Azure Function: 
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")


#Format Data for Submission to DCR
$HardwareInventory_RawEvents = $DevicePayLoad
$DevicePayLoad =  $DevicePayLoad | ConvertTo-Json
$DevicePayLoad = "[" + "
$($DevicePayLoad)
" + "]"

$AppInventory_RawEvents = $AppPayLoad 
$AppPayLoad =  $AppPayLoad | ConvertTo-Json
$AppPayLoad = "[" + "
$($AppPayLoad)
" + "]"

$AdminInventory_RawEvents = $AdminPayLoad
$AdminPayLoad =  $AdminPayLoad | ConvertTo-Json
$AdminPayLoad = "[" + "
$($AdminPayLoad)
" + "]"


#Format data for Function App
$LogPayLoadDevice = New-Object -TypeName PSObject 
$LogPayLoadDevice | Add-Member -NotePropertyMembers @{$DeviceLogName = $DevicePayLoad }

$LogPayLoadApp = New-Object -TypeName PSObject 
$LogPayLoadApp | Add-Member -NotePropertyMembers @{$AppLogName = $AppPayLoad }

$LogPayLoadAdmin = New-Object -TypeName PSObject 
$LogPayLoadAdmin | Add-Member -NotePropertyMembers @{$adminLogName = $AdminPayLoad }


#Create body for Function App request
$HardwareInventory_BodyTable = New-AADDeviceTrustBody
$AppInventory_BodyTable = New-AADDeviceTrustBody
$AdminInventory_BodyTable = New-AADDeviceTrustBody

#Extend body table with additional data
#Hardware Inventory
$HardwareInventory_BodyTable.Add("Table", "$($DeviceInventory_Table)")
$HardwareInventory_BodyTable.Add("DcrImmutableId", "$($DeviceInventory_DcrImmutableId)")
$HardwareInventory_BodyTable.Add("LogPayloads", $LogPayLoadDevice) # NOTE THE DIFFERENT FORMATTING FOR THIS FIELD!!!! 
#App Inventory
$AppInventory_BodyTable.Add("Table", "$($AppInventory_Table)")
$AppInventory_BodyTable.Add("DcrImmutableId", "$($AppInventory_DcrImmutableId)")
$AppInventory_BodyTable.Add("LogPayloads", $LogPayLoadApp) # NOTE THE DIFFERENT FORMATTING FOR THIS FIELD!!!! 
#Hardware Inventory
$AdminInventory_BodyTable.Add("Table", "$($AdminInventory_Table)")
$AdminInventory_BodyTable.Add("DcrImmutableId", "$($AdminInventory_DcrImmutableId)")
$AdminInventory_BodyTable.Add("LogPayloads", $LogPayLoadAdmin) # NOTE THE DIFFERENT FORMATTING FOR THIS FIELD!!!! 





if ($WriteLogFile){
	write-host "Log File Enabled - Not sending!"
    write-host "writing log files..."
    New-Item C:\Temp -ItemType Directory -ErrorAction SilentlyContinue > $null 
    New-Item C:\Temp\LogAnalytics -ItemType Directory -ErrorAction SilentlyContinue > $null 
	#Full Body
	$HardwareInventory_BodyTable | ConvertTo-Json -Depth 3 | Out-File "C:\Temp\LogAnalytics\$($DeviceLogName)-Full.json"
	$AppInventory_BodyTable | ConvertTo-Json -Depth 3 | Out-File "C:\Temp\LogAnalytics\$($AppLogName)-Full.json"
	$AdminInventory_BodyTable | ConvertTo-Json -Depth 3 | Out-File "C:\Temp\LogAnalytics\$($adminLogName)-Full.json"
	#Data Only
	$HardwareInventory_RawEvents | ConvertTo-Json | Out-File "C:\Temp\LogAnalytics\$($DeviceLogName)-RAW.json"
	$AppInventory_RawEvents | ConvertTo-Json | Out-File "C:\Temp\LogAnalytics\$($AppLogName)-RAW.json"
	$AdminInventory_RawEvents | ConvertTo-Json | Out-File "C:\Temp\LogAnalytics\$($adminLogName)-RAW.json"
	write-host "writing complete. Stopping!"
	exit 1

	} else {

	#Submit the data to the API endpoint
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
		$ResponseDeviceInventory = Invoke-RestMethod -Method "POST" -Uri $AzureFunctionURL -Body ($HardwareInventory_BodyTable | ConvertTo-Json -depth 9) -ContentType "application/json" -ErrorAction Stop
        $ResponseAppInventory = Invoke-RestMethod -Method "POST" -Uri $AzureFunctionURL -Body ($AppInventory_BodyTable | ConvertTo-Json -depth 9) -ContentType "application/json" -ErrorAction Stop
		$responseAdminInventory = Invoke-RestMethod -Method "POST" -Uri $AzureFunctionURL -Body ($AdminInventory_BodyTable | ConvertTo-Json -depth 9) -ContentType "application/json" -ErrorAction Stop


    }


#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "


if ($CollectDeviceInventory) {
    if ($ResponseDeviceInventory -match "204:") {
        
        $OutputMessage = $OutPutMessage + "DeviceInventory:OK " + $ResponseDeviceInventory
    }
    else {
        $OutputMessage = $OutPutMessage + "DeviceInventory:Fail "
    }
}
if ($CollectAppInventory) {
    if ($ResponseAppInventory -match "204:") {
        
        $OutputMessage = $OutPutMessage + " AppInventory:OK " + $ResponseAppInventory
    }
    else {
        $OutputMessage = $OutPutMessage + " AppInventory:Fail "
    }
}
if ($collectAdminInventory) {
    if ($responseAdminInventory -match "204:") {
        
        $OutputMessage = $OutPutMessage + " AdminInventory:OK " + $responseAdminInventory
    }
    else {
        $OutputMessage = $OutPutMessage + " AdminInventory:Fail "
    }
}
Write-Output $OutputMessage
Exit 0
