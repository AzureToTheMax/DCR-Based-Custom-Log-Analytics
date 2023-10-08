$DateCurrentUTC = (Get-Date).ToUniversalTime()
#This stays at the top!

#Windows Endpoint System Usage Collection Script.


<#
    .SYNOPSIS
    Windows Endpoint System Usage & Authentication Collection Script.

    This script collects a multitude of Windows Events related to system usage. This includes the following Event IDs. Please see my blog for detailed information on the filtering, or scroll down and see for yourself.

        Security Event ID 4800 - lock
        Security Event ID 4801 - Unlock
        Security Event ID 4624 - logon
        Security Event ID 4625 - logon failure
        Security Event ID 4634 - logoff
        Security Event ID 4779 - RDP Disconnect
        Security Event ID 4802 - Screensaver Invoked
        Security Event ID 4803 - Screensaver dismissed
        System Event ID 1074 - Shutdown
        System Event ID 12 - Startup

    This information is then sent to an Azure Function App via a JSON which is formatted for submission to a DCR. 
    This script is designed to use the Function App created by AzureToTheMax which uses the latest certificate-based authentication is designed for use with DCR based tables.

    For information regarding this collector, see the "LA for System Usage & Authentication Monitoring" section here: https://azuretothemax.net/log-analytics-index/


                
    .NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Created:     2023-08-26
    Updated:     2023-10-08


   
Version history:
1.0:
    - Updated for use with a dynamic/customizable storage marker directory and file
    - Updated to include 4625 logon failures
    - Updated to the time tracking from the W365 series, then updated that to use millisecond tracking. 
        This involves a lot of specific formatting and changes to get around UTC translation issues. All testing has been passed including simulating various timezones.

1.1: 2023-10-08
- Updated the pull for ComputerName to use $ENV:COMPUTERNAME instead of Get-CimInstance class as this was failing on a very small set (.001%) of devices.


#>



######################################################################


#Region Variables
#Controls various Script customizable Variables

#Script Version. Used for denoting updates / tracking.
$ScriptVersion = "1"

#Function URL for Log Upload
$AzureFunctionURL = "Your Function App URL"

#Table name - must be exact
$Table = "SystemUsage_CL"

#DCR Immutable ID
$DcrImmutableId = "Your Immutable ID"

#Friendly log name. Name it what you want. Used for logging, local JSON export, and the name the data is referenced by inside the JSON.
$LogName = "SystemUsage"

#The path to store our time marker file and the name of the time marker file. Leave it as a TXT.
$StorageDirectory = "C:\Windows\LogAnalytics"
$MarkerFile = "SystemUsage.txt"

#How Many Days worth of data should be back-scanned on the very first run (as determined by the existence or lack thereof for the time marker file). Should be a negative value. Default is "-7" to collect the previous 7 days.
$InitialCollectionDays = "-7"

#Max Collection Interval in milliseconds. 
#This controls the maximum time range a device can try and collect logs from. This does not override/effect the initial data collection interval. 
#If a device tries to perform a collection on a range of time that exceeds this maximum, the maximum interval is used instead.
$MaxCollectionInterval = 1209600000 #value in milliseconds.
#Default is two weeks or 1209600000
#Three weeks 3628800000
#One Week 604800000
#24 hours 86400000 

#Used to export to JSON for DCR creation sample data - Should be false for deployment.
$WriteLogFile = $false
$ScanBackValue = "-14" #How many days to ALWAYS go back when writelogfile is set to true. Only effects when WriteLogFile is on.

#Enable or disable the log upload delay. True/False. Default is $True which saves money by staggering executions calls.
$Delay = $true

#Turn on/off collection
$collectSystemUsage = $true

#misc
$Date = (Get-Date)


#Clear variables
$FinalLog = $null
$SecurityLogArray = $null
$SystemLogArray = $null
$SecurityEventSearch = $null
$SystemEventSearch = $null
$SystemStartEventSearch = $null 
$SecurityLogInventory = $null
$SystemLogInventory = $null

#Null our event count
$EventCount = $null






######################################################################
#region functions
<#
Get-AzureADJoinDate
Get-AzureADTenantID
New-AADDeviceTrustBody
Test-AzureADDeviceRegistration
Get-AzureADRegistrationCertificateThumbprint
Get-PublicKeyBytesEncodedString
New-RSACertificateSignature
Get-AzureADDeviceID
New-StorageDirectory
Get-EventCollectionTimeRange
#>
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
        Construct the body with the elements for a successful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.

    .DESCRIPTION
        Construct the body with the elements for a successful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.

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



function New-StorageDirectory {
    #Used to create & hide the storage directory if it does not exist already
    param(
        [parameter(Mandatory = $true, HelpMessage = "Full path to the storage directory to store the marker file in.")]
        $StorageDirectory
    )


    $TestFolder = Test-Path $StorageDirectory
    if ($TestFolder -eq $false) {
    New-Item $StorageDirectory -ItemType Directory -ErrorAction SilentlyContinue > $null 
    #Set dirs as hidden
    $folder = Get-Item $StorageDirectory
    $folder.Attributes = 'Directory','Hidden' 
    }

}



function Get-EventCollectionTimeRange {

        <#
    .SYNOPSIS
        Calculates the time difference since log collection last ran based on the parameter provided of current UTC-time and the time set in the marker file.

    .DESCRIPTION
        This function will validate the information in the marker file as functional and restore it if not. The global "$($StorageDirectory)\$($MarkerFile)" location is used.
        It will then calculate the time difference since the script was last ran and validate that it does not exceed the max interval.
        The calculated time range will be used if it does not exceed the max interval. If it does, the max interval will be used.

        The specific time formatting needed for Event Viewer is a recognized time format to PowerShell as calculations work however, it does not seem to be one which can be easily exported / automatically formatted. 
        This will lead to several instances of me manually formatting the time.

    .PARAMETER DateCurrentUTC
        Specify the current date time in UTC.

    .NOTES
        Author:      Maxton Allen
        Contact:     @AzureToTheMax
        Created:     2023-08-25
        Updated:     2023-08-25

        Version history:
        1.0.0 - (2023-08-25) Official V1 of the Function Created

    #>



    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the current date time in UTC.")]
        [datetime]$DateCurrentUTC
    )


    #Set our tracking variable
    $SkipUTC = $false

    #Check to see if our marker file exists
    $TestFolder = Test-Path "$($StorageDirectory)\$($MarkerFile)"

        #If not, we need to create the file (the directory should have already been made) and create our file
        if ($TestFolder -eq $false) {
        #Create the file
        New-Item "$($StorageDirectory)\$($MarkerFile)" -ItemType file -ErrorAction SilentlyContinue > $null 
        #Hide the file
        $folder = Get-Item "$($StorageDirectory)\$($MarkerFile)" 
        $folder.Attributes = 'Directory','Hidden' 

        #Supply our scripts start collection time with the current time minus the initial range in days
        $MarkerFileTimeUTC = [datetime]$DateCurrentUTC.AddDays($InitialCollectionDays)

        #Mark our marker file with the time of script start. This will then be used next time the script runs.
        Set-Content "$($StorageDirectory)\$($MarkerFile)" $(([datetime]$DateCurrentUTC).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z")

        #Warn that the marker file did not exist, this must be the first run.
        Write-Warning "First run! Using Default $($InitialCollectionDays) Day(s) scan!"

        } else {
        #If the file exists, read it to determine the duration
        $MarkerFileTimeUTC = Get-Content "$($StorageDirectory)\$($MarkerFile)"
        }

            #Check to make sure the content of the file was not null or a blank space (very specific circumstance)
            if ($MarkerFileTimeUTC -ne $null -and $MarkerFileTimeUTC -ne " ") {

                #If the marker file content is not null, do the math to find our time range.
                try {
                    #PowerShell is about to make the mistake of assuming our marker file is not UTC. So, we will calculate our UTC offset and use it to fix that failure.
                    $UTCOffset = NEW-TIMESPAN -start $(([datetime]$MarkerFileTimeUTC).ToUniversalTime()) -end $([datetime]$MarkerFileTimeUTC)

                    $Difference = NEW-TIMESPAN -Start $([datetime]$MarkerFileTimeUTC).AddHours(-1*$($UTCOffset.Hours)) -End $DateCurrentUTC
                }
                catch {
                    #If the above fails (an error was caught), something was likely wrong with the marker file content and thus $MarkerFileTimeUTC. This would be due to a corrupt value, rather than a null one.
                    #Write a warning, use the max collectible range, and write a good value to our marker file to prevent this from happening again.
                    write-warning "Something was wrong with the marker file content - force setting file content.
                    Using default max range and thus date/time $($DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval))"
                    Set-Content "$($StorageDirectory)\$($MarkerFile)" $(([datetime]$DateCurrentUTC).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z")
                    $MarkerFileTimeUTC = $DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval)
                }
            
                #At this point the difference has been calculated either via the range or failed and it's using our max range.

                #pull out our values for logging and comparison
                $Minutes = $Difference.TotalMinutes
                $DifferenceMiliseconds = $Difference.TotalMilliseconds
                $DifferenceMiliseconds = [math]::Round($DifferenceMiliseconds)

                #Write out the difference as an FYI
                write-host "Time difference since the last run in milliseconds is roughly $($DifferenceMiliseconds) milliseconds or roughly $($Minutes) minutes."

                        #If the time since the last collection is over the max range, use the max interval and update our marker file to now to prevent further issue.
                        if ($DifferenceMiliseconds -gt $MaxCollectionInterval) {
                            
                            $MarkerFileTimeUTC = $DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval)
                            Write-Warning "Range exceeded the maximum range of $($MaxCollectionInterval) milliseconds. Using $($DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval))"

                            #Set content so it's not a problem next time.
                            Set-Content "$($StorageDirectory)\$($MarkerFile)" $(([datetime]$DateCurrentUTC).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z")
                            $SkipUTC = $true

                        } else {
                            #If the time since the last collection is not over the max range, note that it's within range and note that value.
                            write-host "Last scan is within range - Using $MarkerFileTimeUTC as start time"
                        
                        }

            }  else {
                #If the marker file content is null, set it's value to prevent further issue and use our max interval
                $MarkerFileTimeUTC = $DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval)

                #Set our marker file content so it's not a problem next time.
                Set-Content "$($StorageDirectory)\$($MarkerFile)" $(([datetime]$DateCurrentUTC).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z")
                write-warning "MarkerFileTimeUTC was somehow null! Using default max range and thus date/time $($DateCurrentUTC.AddMilliseconds(-1*$MaxCollectionInterval))"
                $SkipUTC = $true
            }



    #If $writelogfile is true, override the time range with the range specific to this circumstance and notate this action.
        if ($WriteLogFile) {
        write-warning "Write Log File is on! Automatically pulling $($ScanBackValue) days worth of logs! Ignoring time file!"

        $MarkerFileTimeUTC = [datetime]$DateCurrentUTC.AddDays($ScanBackValue)
        }

    #Final Time Conversion to sortable format

    #Due to needing to work with $MarkerFileTimeUTC sometimes as UTC and sometimes not, we may need to convert it now. This is tracked via $SkipUTC getting set.
    if ($SkipUTC -eq $false){
    #Do convert to UTC
    [System.string]$MarkerFileTimeUTC = ([datetime]$MarkerFileTimeUTC).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z"
    [System.string]$DateCurrentUTC = ([datetime]$DateCurrentUTC).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z"
    } else {
    #Do NOT convert to UTC (it is already UTC)
    [System.string]$MarkerFileTimeUTC = ([datetime]$MarkerFileTimeUTC).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z"
    [System.string]$DateCurrentUTC = ([datetime]$DateCurrentUTC).ToString("yyyy-MM-ddTHH:mm:ss.fff") + "Z"
    }

    #Compile our two values into an array for easy return
    $TimeCollectionArray = New-Object System.Object
    $TimeCollectionArray | Add-Member -MemberType NoteProperty -Name "Start" -Value "$MarkerFileTimeUTC" -Force
    $TimeCollectionArray | Add-Member -MemberType NoteProperty -Name "Stop" -Value "$DateCurrentUTC" -Force

    #Return our stop and start values
    return $TimeCollectionArray

}




######################################################################
#EndRegion
######################################################################







#Start script

#Enable TLS 1.2 Support
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Create our storage Directory using the global $StorageDirectory
New-StorageDirectory -StorageDirectory $StorageDirectory

#Get our time range to collect
$TimeRange = Get-EventCollectionTimeRange -DateCurrentUTC $DateCurrentUTC
#Extrude values
$TimeStart = $TimeRange.Start
$TimeStop = $TimeRange.Stop
#Notate values
write-host "Time Duration to collect is from $($TimeStart) to $($TimeStop)"


#Get Common Data
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
$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
#$ComputerName = $ComputerInfo.Name - fails on literally .001% of devices. $ENV:Computername seems consistent. Correction below.
$ComputerName = $env:COMPUTERNAME





if ($collectSystemUsage) {

#DO NOT INDENT THIS!
$SearchXML = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4800 or EventID=4801 or EventID=4624  or EventID=4625 or EventID=4634 or EventID=4779 or EventID=4802 or EventID=4803) and TimeCreated[@SystemTime&gt;='$TimeStart' and @SystemTime&lt;='$TimeStop']]]</Select>
  </Query>
</QueryList>
'@

#compile the above XML- yes, it must be done this way.
$SearchXML = $ExecutionContext.InvokeCommand.ExpandString($SearchXML)

    #Search events and pull them into a variable
    $SecurityEventSearch = Get-WinEvent -FilterXML $SearchXML
    $SecurityLogInventory = $SecurityEventSearch

    #Create our array and begin adding values
    $SecurityLogArray = @()

    #Process each event one by one.
    $SecurityLogInventory | ForEach-Object -Process {

        #Reset our temp array
        $SecurityTempLogArray = New-Object System.Object

        #On each event, convert all log times from local time to UTC
        $TimeOfLogUTC = $_.TimeCreated.ToUniversalTime()

        #If the event ID is a 4800 lock event, process it here and add its values to our array.
        if ($_.ID -eq 4800) {
        $User = $_.properties | Select-Object -Index 1
        $User = $User.value

                    #If we are here, an event is being added.
                    $EventCount = $EventCount + 1
        
        write-host "lock event found"
        
        #Add members and values to our array
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force  
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Lock" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
        $SecurityLogArray += $SecurityTempLogArray
        }
        


        #If the event ID is a 4801 unlock event, process it here and add its values to our array.
        if ($_.ID -eq 4801) {
        $User = $_.properties | Select-Object -Index 1
        $User = $User.value
        write-host "unlock event found"

                    #If we are here, an event is being added.
                    $EventCount = $EventCount + 1
            
        #Add members and values to our array
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force  
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force 
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Unlock" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
        $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
        $SecurityLogArray += $SecurityTempLogArray
        }




        #If the event ID is a 4624 logon event, process it here and add its values to our array.
        if ($_.ID -eq 4624) {
            $User = $_.properties | Select-Object -Index 5
            $User = $User.value
            $user = $user.TrimStart(".\AzureAD\")
            $user = $user.TrimStart("AzureAD\")
           
    
            #Pull and translate the logon type to a human readable value
            $LogonType = $_.properties | Select-Object -Index 8
            $LogonType = $LogonType.Value
            if ($LogonType -eq 2) {$LogonType = "Interactive"}
            if ($LogonType -eq 3) {$LogonType = "Network"}
            if ($LogonType -eq 4) {$LogonType = "Batch"}
            if ($LogonType -eq 5) {$LogonType = "Service"}
            if ($LogonType -eq 7) {$LogonType = "Unlock"}
            if ($LogonType -eq 8) {$LogonType = "NetworkCleartext"}
            if ($LogonType -eq 9) {$LogonType = "NewCredentials"}
            if ($LogonType -eq 10) {$LogonType = "RemoteInteractive"}
            if ($LogonType -eq 11) {$LogonType = "CachedInteractive"}
            
            
    
            #Filter out certain logons we do not want to collect such as those from system accounts, services, and the machine account.
            #Note, we do not collect unlock type logon events because those are collected separately already.
            if ($user -ne "SYSTEM" -and $user -ne "NETWORK SERVICE" -and $user -ne "defaultuser0" -and $LogonType -ne "Service" -and $_.message -notlike "*Window Manager*" -and $_.message -notlike "*Font Driver Host*" -and $user -ne "$($env:COMPUTERNAME)$"  -and $LogonType -ne "Unlock") {
                write-host "Logon event found"
    
                            #If we are here, an event is being added.
                            $EventCount = $EventCount + 1
  
  
            #Remote logon and possibly network logons will try to notate the far end IP
                    #I don't see a reason to not always try and pull this, but this loop could work to contain that if needed.
                    #if ($LogonType -eq "RemoteInteractive" -or $LogonType -eq "Network"){}
                    #Make sure to null our values to prevent flow from one loop to another.
                    $FarMachineIP = $null
                    $FarMachineIP = $_.properties | Select-Object -Index 18
                    $FarMachineIP = $FarMachineIP.value
                    $ExtendedInformationArray = @()
                    $TempExtendedArray = New-Object -TypeName psobject
                    $TempExtendedArray | Add-Member -MemberType NoteProperty -Name "FarMachineIP" -Value "$FarMachineIP" -Force
                    $ExtendedInformationArray += $TempExtendedArray
                    [System.Collections.ArrayList]$ExtendedInformationArrayList = $ExtendedInformationArray
            
  
    
            #Remove logon message Bloat
            #I hate how this looks but out of all the methods I tried it's the only one that worked.
    
            $Message = $_.Message | Out-String
            $Message = $Message.trimend("")
            $Message = $Message.trimend("- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("- Package name indicates which sub-protocol was used among the NTLM protocols.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("- Transited services indicate which intermediate services have participated in this logon request.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("The authentication information fields provide detailed information about this specific logon request.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("The impersonation level field indicates the extent to which a process in the logon session can impersonate.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.")
            $Message = $Message.trimend("")
            $Message = $Message.trimend("This event is generated when a logon session is created. It is generated on the computer that was accessed.")
            $Message = $Message.trimend("")
            
    
            #Add members and values to our array
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Logon" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "LogonType" -Value "$($LogonType)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ExtendedInformation" -Value $ExtendedInformationArrayList -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$Message" -Force
            $SecurityLogArray += $SecurityTempLogArray
        }
        
        }

        #If the event ID is a 4634 logoff event, process it here and add its values to our array.
         if ($_.ID -eq 4634) {
            $User = $_.properties | Select-Object -Index 1
            $User = $User.value
            

            #Pull and translate the logoff type to a human readable value
            $LogonType = $_.properties | Select-Object -Index 4
            $LogonType = $LogonType.Value
            if ($LogonType -eq 2) {$LogonType = "Interactive"}
            if ($LogonType -eq 3) {$LogonType = "Network"}
            if ($LogonType -eq 4) {$LogonType = "Batch"}
            if ($LogonType -eq 5) {$LogonType = "Service"}
            if ($LogonType -eq 7) {$LogonType = "Unlock"}
            if ($LogonType -eq 8) {$LogonType = "NetworkCleartext"}
            if ($LogonType -eq 9) {$LogonType = "NewCredentials"}
            if ($LogonType -eq 10) {$LogonType = "RemoteInteractive"}
            if ($LogonType -eq 11) {$LogonType = "CachedInteractive"}
            
            
    
            #Filter out certain logoffs we do not want to collect such as those from system accounts, services, and the machine account.
            #Note, we do not collect unlock type logon/logoff events because those are collected separately already.
            if ($user -ne "SYSTEM" -and $user -ne "NETWORK SERVICE" -and $LogonType -ne "Service" -and $_.message -notlike "*Window Manager*" -and $_.message -notlike "*Font Driver Host*" -and $user -ne "$($env:COMPUTERNAME)$"  -and $LogonType -ne "Unlock") {
                write-host "Logoff event found"

            #If we are here, an event is being added.
            $EventCount = $EventCount + 1

            #Trim the generic text on the end of logoff messages to avoid cost.
            $Message = $_.Message.trimend("This event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.")

            #Add members and values to our array
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force  
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Logoff" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "LogonType" -Value "$($LogonType)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$Message" -Force
            $SecurityLogArray += $SecurityTempLogArray
            }
            
            }

            
            #If the event ID is a 4625 logon failure event, process it here and add its values to our array.
            if ($_.ID -eq 4625) {
                $User = $_.properties | Select-Object -Index 5
                $User = $User.value
                #Trim Azure AD possible starting characters
                $user = $user.TrimStart(".\AzureAD\")
                $user = $user.TrimStart("AzureAD\")
      
      
                #Pull and translate the logon type to a human readable value
                $LogonType = $_.properties | Select-Object -Index 10
                $LogonType = $LogonType.Value
                if ($LogonType -eq 2) {$LogonType = "Interactive"}
                if ($LogonType -eq 3) {$LogonType = "Network"}
                if ($LogonType -eq 4) {$LogonType = "Batch"}
                if ($LogonType -eq 5) {$LogonType = "Service"}
                if ($LogonType -eq 7) {$LogonType = "Unlock"}
                if ($LogonType -eq 8) {$LogonType = "NetworkCleartext"}
                if ($LogonType -eq 9) {$LogonType = "NewCredentials"}
                if ($LogonType -eq 10) {$LogonType = "RemoteInteractive"}
                if ($LogonType -eq 11) {$LogonType = "CachedInteractive"}
                
                
        
                #Filter out certain logons we do not want to collect such as those from system accounts, services, and the machine account.
                if ($user -ne "SYSTEM" -and $user -ne "NETWORK SERVICE" -and $user -ne "defaultuser0" -and $user -ne "-" -and $LogonType -ne "Service" -and $_.message -notlike "*Window Manager*" -and $_.message -notlike "*Font Driver Host*" -and $user -ne "$($env:COMPUTERNAME)$"  -and $LogonType -ne "Unlock") {
                    write-host "Logon Failure event found"
        
                    #If we are here, an event is being added.
                    $EventCount = $EventCount + 1
      
                #Remote logon failure and possibly network logon failures will try to notate the far end IP
                #Null our values to prevent flow from one loop to another.
                $FarMachineName = $null
                $FarMachineIP = $null
                $FailureReason = $null
                #Pull out Far Machine Name
                $FarMachineName = $_.properties | Select-Object -Index 13
                $FarMachineName = $FarMachineName.Value
                #Pull out Far Machine IP
                $FarMachineIP = $_.properties | Select-Object -Index 19
                $FarMachineIP = $FarMachineIP.value
      
                #Failure codes are fun. Need to translate the hex to decimal then translate that to a real value.
                # https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
                #pull the failure reason
                $FailureReason = $_.properties | Select-Object -Index 7
                $FailureReason = $FailureReason.Value
                #Convert failure reason hex to decimal.
                $FailureReason = [System.Convert]::ToString($FailureReason,16)
                #Convert failure reason decimal to human readable value
                if ($FailureReason -eq "C000005E") {$FailureReason = "There are currently no logon servers available to service the logon request."}
                if ($FailureReason -eq "C0000064") {$FailureReason = "User logon with misspelled or bad user account"}
                if ($FailureReason -eq "C000006A") {$FailureReason = "User logon with misspelled or bad password"}
                if ($FailureReason -eq "C000006D") {$FailureReason = "Unknown user name or bad password"}
                if ($FailureReason -eq "C000006E") {$FailureReason = "Account currently disabled"} #This one wasn't documented...
                if ($FailureReason -eq "C000006F") {$FailureReason = "User logon outside authorized hours"}
                if ($FailureReason -eq "C0000070") {$FailureReason = "User logon from unauthorized workstation"}
                if ($FailureReason -eq "C0000072") {$FailureReason = "User logon to account disabled by administrator"}
                if ($FailureReason -eq "C000015B") {$FailureReason = "The user has not been granted the requested logon type (aka logon right) at this machine"}
                if ($FailureReason -eq "C0000192") {$FailureReason = "An attempt was made to logon, but the Netlogon service was not started"}
                if ($FailureReason -eq "C0000193") {$FailureReason = "User logon with expired account"}
                if ($FailureReason -eq "C0000413") {$FailureReason = "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine"}
      
                #Put our new values into our sub-array.
                $ExtendedInformationArray = @()
                $TempExtendedArray = New-Object -TypeName psobject
                $TempExtendedArray | Add-Member -MemberType NoteProperty -Name "FarMachineName" -Value "$FarMachineName" -Force
                $TempExtendedArray | Add-Member -MemberType NoteProperty -Name "FarMachineIP" -Value "$FarMachineIP" -Force
                $TempExtendedArray | Add-Member -MemberType NoteProperty -Name "FailureReason" -Value "$FailureReason" -Force
                $ExtendedInformationArray += $TempExtendedArray
                [System.Collections.ArrayList]$ExtendedInformationArrayList = $ExtendedInformationArray
              
        
                #Remove logon message Bloat
                #I hate how this looks but out of all the methods I tried it's the only one that worked.
                $Message = $_.Message | Out-String
                $Message = $Message.trimend("")
                $Message = $Message.trimend("- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("- Package name indicates which sub-protocol was used among the NTLM protocols.")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("- Transited services indicate which intermediate services have participated in this logon request.")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("The authentication information fields provide detailed information about this specific logon request.")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("The Process Information fields indicate which account and process on the system requested the logon.")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.")
                $Message = $Message.trimend("")
                $Message = $Message.trimend("This event is generated when a logon request fails. It is generated on the computer where access was attempted.")
                $Message = $Message.trimend("")
                
        
      
                #Add members and values to our array
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Logon Failure" -Force
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "LogonType" -Value "$($LogonType)" -Force
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ExtendedInformation" -Value $ExtendedInformationArrayList -Force
                $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$Message" -Force
                $SecurityLogArray += $SecurityTempLogArray
                }
                
                }
      




        #If the event ID is a 4779 RDP Disconnect event, process it here and add its values to our array.
        if ($_.ID -eq 4779) {
            $User = $_.properties | Select-Object -Index 0
            $User = $User.value
            
            
            #Filter out certain logoffs we do not want to collect such as those from system accounts, services, and the machine account.
            if ($user -ne "SYSTEM") {
  
                write-host "RDP-Disconnect event found"
  
                            #If we are here, an event is being added.
                            $EventCount = $EventCount + 1
  
            #Trim the generic text on the end of logoff messages to avoid cost.
            $Message = $_.Message.trimend("This event is generated when a user disconnects from an existing Terminal Services session, or when a user switches away from an existing desktop using Fast User Switching.")
  
            $FarMachineName = $null
            $FarMachineIP = $null
            #Pull out Far Machine Name
            $FarMachineName = $_.properties | Select-Object -Index 4
            $FarMachineName = $FarMachineName.Value
            #Pull out Far Machine IP
            $FarMachineIP = $_.properties | Select-Object -Index 5
            $FarMachineIP = $FarMachineIP.value
  
            #Put it into our sub-array.
            $ExtendedInformationArray = @()
            $TempExtendedArray = New-Object -TypeName psobject
            $TempExtendedArray | Add-Member -MemberType NoteProperty -Name "FarMachineName" -Value "$FarMachineName" -Force
            $TempExtendedArray | Add-Member -MemberType NoteProperty -Name "FarMachineIP" -Value "$FarMachineIP" -Force
            $ExtendedInformationArray += $TempExtendedArray
            [System.Collections.ArrayList]$ExtendedInformationArrayList = $ExtendedInformationArray
  
  
            #Add members and values to our array
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "RDP-Disconnect" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ExtendedInformation" -Value $ExtendedInformationArrayList -Forc
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($Message)" -Force
            
            $SecurityLogArray += $SecurityTempLogArray
            }
            
            }




        #If the event ID is a 4802 Screensaver start event, process it here and add its values to our array.
         if ($_.ID -eq 4802) {
            $User = $_.properties | Select-Object -Index 1
            $User = $User.value
            
            
            #We only care about non-system events
            if ($user -ne "SYSTEM") {
                write-host "Screen saver invoked event found"

            #If we are here, an event is being added.
            $EventCount = $EventCount + 1

            #Add members and values to our array
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force  
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "screen saver was invoked" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
            
            $SecurityLogArray += $SecurityTempLogArray
            }
            
            }





        #If the event ID is a 4803 Screensaver dismiss event, process it here and add its values to our array.
         if ($_.ID -eq 4803) {
            $User = $_.properties | Select-Object -Index 1
            $User = $User.value
            
            
            #We only care about non-system events
            if ($user -ne "SYSTEM") {
                write-host "Screen saver dismissed event found"

            #If we are here, an event is being added.
            $EventCount = $EventCount + 1

            #Add members and values to our array
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "screen saver was dismissed" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
            $SecurityTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
            
            $SecurityLogArray += $SecurityTempLogArray
            }
            
            }
}
#End Security Log Search            





#Run our System Event Search for shutdown events

#DO NOT INDENT THIS!
$SearchSystemXML = @'
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=1074) and TimeCreated[@SystemTime&gt;='$TimeStart' and @SystemTime&lt;='$TimeStop']]]</Select>
  </Query>
</QueryList>
'@
            
$SearchSystemXML = $ExecutionContext.InvokeCommand.ExpandString($SearchSystemXML)


        #Run our event search and pull it into a variable
        $SystemEventSearch = Get-WinEvent -FilterXML $SearchSystemXML
        $SystemLogInventory = $SystemEventSearch
        
        #Create our array and begin processing events to add to the array
        $SystemLogArray = @()
        $SystemLogInventory | ForEach-Object -Process {
        $SystemTempLogArray = New-Object System.Object
    
    
        #Convert all log times from local time to UTC
        $TimeOfLogUTC = $_.TimeCreated.ToUniversalTime()
        
               
            #If the event ID is a 1074 Shutdown event, process it here and add its values to our array.
            if ($_.ID -eq 1074) {

                write-host "Shutdown event found"

                #Pull out the user value
                $User = $_.properties | Select-Object -Index 6
                $User = $User.value

                #pull the shutdown type field (shutdown, restart, etc) and convert it to a simpler value as its own member.
                if ($_.message -like "*Shutdown Type: power off*") {
                    $ShutdownType = "Shutdown"

                }

                if ($_.message -like "*Shutdown Type: restart*") {
                    $ShutdownType = "Restart"

                }

                    #If we are here, an event is being added.
                    $EventCount = $EventCount + 1

                #Add members and values to our array
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force  
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force 
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "$ShutdownType" -Force
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
                $SystemTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
                $SystemLogArray += $SystemTempLogArray
                }
        
}
#End shutdown Log Search      
    



#Run our startup event search
#Startup requires a more specific search due to event ID 12 having multiple sources.

#DO NOT INDENT THIS!
$SearchSystemXMLStartup = @'
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12) and TimeCreated[@SystemTime&gt;='$TimeStart' and @SystemTime&lt;='$TimeStop']]]</Select>
  </Query>
</QueryList>
'@

$SearchSystemXMLStartup = $ExecutionContext.InvokeCommand.ExpandString($SearchSystemXMLStartup)
            

        #Run our event search and pull it into a variable
        $SystemStartEventSearch = Get-WinEvent -FilterXML $SearchSystemXMLStartup
        $SystemStartLogInventory = $SystemStartEventSearch
        
        #Create our array and begin processing events to add to the array
        $SystemStartLogArray = @()
        $SystemStartLogInventory | ForEach-Object -Process {
        $SystemStartTempLogArray = New-Object System.Object
    
        #Convert all log times from local time to UTC
        $TimeOfLogUTC = $_.TimeCreated.ToUniversalTime()
        

               #If the event ID is a 12 Startup event, process it here and add its values to our array.
               if ($_.ID -eq 12) {
                write-host "Startup event found"
            

                            #If we are here, an event is being added.
                            $EventCount = $EventCount + 1

                #Add members and values to our array
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force 
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force   
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Startup" -Force
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "User" -Value "" -Force
                $SystemStartTempLogArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
                $SystemStartLogArray += $SystemStartTempLogArray
                }
        }
}  
#End startup Log Search 
    



    #Combine all final arrays
    $FinalLog += $SecurityLogArray += $SystemLogArray += $SystemStartLogArray


    

######################################################
#Prepare Array for Upload via Azure Function App
######################################################

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

#store value now for writelogfile
$RawEvents = $FinalLog
#Convert for use with DCR
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


    #If there are events to send
    if ($EventCount -ge 1) {

        #If writelogfile is on - log but don't send.
        if ($WriteLogFile){

            #Notate how many events were found - this is done elsewhere if writelogfile is off.
            Write-host "$($EventCount) Events found."
            
            #Notate that writelogfile is on and export our values to JSONs.
            Write-Warning "NOT UPLOADING - writing local log file(s)!"
            New-Item C:\Temp -ItemType Directory -ErrorAction SilentlyContinue > $null 
            New-Item C:\Temp\LogAnalytics -ItemType Directory -ErrorAction SilentlyContinue > $null 
            $BodyTable | ConvertTo-Json -Depth 3 | Out-File "C:\Temp\LogAnalytics\$($LogName)-Full.json"
            $RawEvents | ConvertTo-Json -Depth 3 | Out-File "C:\Temp\LogAnalytics\$($LogName)-RAW.json"
            $ResponseInventory = "Log File Enabled - Not sending!"
            exit 1
            }
            
        #If writelogfile is off - Follow the delay and send
        if ($WriteLogFile -eq $false){    

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
        
        #If no events were found to upload
        #Mark our response message
        $ResponseInventory = "No events to send!"
        #Write this FYI
        Write-Warning "No Events found, updating time range from $($TimeStart) to $($TimeStop)"
        #Update tracking file as we will not need to rescan this period
        Set-Content "$($StorageDirectory)\$($MarkerFile)" "$($TimeStop)" -Force
        #Better establish our event count as zero, it's likely null currently.
        $EventCount = "0"
    }


	$OutputMessage = $OutPutMessage + "Inventory:OK " + $ResponseInventory



#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

#write Response
write-host "Value of Response for $($LogName) is $($ResponseInventory)"

#Validate the return code
if ($collectSystemUsage) {
    if ($ResponseInventory -match "204:") {
        
        $OutputMessage = $OutPutMessage + " $($LogName):OK " 
        #Update our last run file only if success is logged.
        Set-Content "$($StorageDirectory)\$($MarkerFile)" "$($TimeStop)" -Force
    
    }
    else {
        $OutputMessage = $OutPutMessage + " $($LogName):Fail "
    }
}
Write-Output "Output: $($OutputMessage) *** Response: $($ResponseInventory) *** Number of logs found: $($EventCount)"

Exit 0