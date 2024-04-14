$DateCurrentUTC = (Get-Date).ToUniversalTime()
#This stays at the top!

#Windows Endpoint Application Usage Collection Script.


<#
    .SYNOPSIS
    Windows Endpoint Application Usage Collection Script.

    This script collects a multitude of Windows Events related to Executable launching and termination. This includes the following Event IDs. Please see my blog for detailed information on the filtering, or scroll down and see for yourself.

        Security Event ID 4688 - A new process has been created
        Security Event ID 4689 - A process has exited

    This information is then sent to an Azure Function App via a JSON which is formatted for submission to a DCR. 
    This script is designed to use the Function App created by AzureToTheMax which uses the latest certificate-based authentication is designed for use with DCR based tables.

    For information regarding this collector, see the "LA for Application Usage Monitoring" section here: https://azuretothemax.net/log-analytics-index/


                
    .NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Created:     2023-08-26
    Updated:     2024-4-13

   
Version history:
1.0: 2024-4-13
    - Creation of Application Usage collector based on the System usage collector version 1.2 and all of it's improvements.


#>



######################################################################


#Region Variables
#Controls various Script customizable Variables

#Script Version. Used for denoting updates / tracking.
$ScriptVersion = "1"

#Function URL for Log Upload
$AzureFunctionURL = "Your Function App URL"

#Table name - must be exact including _CL
$Table = "AppUsage_CL"

#DCR Immutable ID
$DcrImmutableId = "Your Immutable ID"

#Friendly log name. Name it what you want. Used for logging, local JSON export, and the name the data is referenced by inside the JSON.
$LogName = "AppUsage"

#The path to store our time marker file and the name of the time marker file. Leave it as a TXT.
$StorageDirectory = "C:\Windows\LogAnalytics"
$MarkerFile = "AppUsage.txt"

#How Many Days worth of data should be back-scanned on the very first run (as determined by the existence or lack thereof for the time marker file). Should be a negative value. Default is "-7" to collect the previous 7 days on first script execution.
$InitialCollectionDays = "-7"

#Max Collection Interval in milliseconds. 
#This controls the maximum time range a device can try and collect logs from. This does not override/effect the initial data collection interval above.
#If a device tries to perform a collection on a range of time that exceeds this maximum, the maximum interval is used instead. For instance, if a device has been off for 2 months, turns on, and tries to run a collection, it will instead default to this range.
$MaxCollectionInterval = 1209600000 #value in milliseconds.
#Default is two weeks or 1209600000
#Three weeks 3628800000
#One Week 604800000
#24 hours 86400000 

#Used to export to JSON for DCR creation sample data - Should be false for deployment.
$WriteLogFile = $false
$ScanBackValue = "-14" #How many days to ALWAYS go back when writelogfile is set to true. Only effects when WriteLogFile is on. Default is -14.

#Enable or disable the log upload delay. True/False. Default is $True which saves money by staggering executions calls.
$Delay = $true

#Turn on/off collection
$collectAppUsage = $true

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

#zero our filter count
$FilteredEvents = 0
$FinalPercentage = $null





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
$ComputerName = $env:COMPUTERNAME




if ($collectAppUsage) {

}
#End Security Log Search            





    #The name of the log in Log Analytics
    $LogName= "AppUsage"

    
    #Search to look for create process 4688 and end process 4689 - DON'T TAB IT OVER
$SearchXML = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4688 or EventID=4689) and TimeCreated[@SystemTime&gt;='$TimeStart' and @SystemTime&lt;='$TimeStop']]]</Select>
  </Query>
</QueryList>
'@

$SearchXML = $ExecutionContext.InvokeCommand.ExpandString($SearchXML)

    #Search events and write them into variable
    $EventsForUpload = Get-WinEvent -FilterXML $SearchXML
    $ApplicationUsageInventory = $EventsForUpload
    
    $TempArrayAppListCreation = $null
    $TempArrayAppListTermination = $null
    $TempArrayAppListCreation = New-Object System.Object
    $TempArrayAppListTermination = New-Object System.Object
    $ApplicationUsageArray = @()
    $ApplicationUsageInventory | ForEach-Object -Process {
        $TempArray = New-Object System.Object
        #These are our log columns that we add, and what value we give that column

        #Change times to system time!
        $TimeOfLogUTC = $_.TimeCreated.ToUniversalTime()

            #Process creation
            if ($_.ID -eq 4688) {
                

            #pull our program value
            $ProgramPath = $_.properties | Select-Object -Index 5
            $ProgramPath = $ProgramPath.value
            $Program = ($ProgramPath -split '\\')[-1]

            #Pull our User value
            $User = $_.properties | Select-Object -Index 1
            $user = $user.value

            #Correct for local admins
            if ($user -eq "$($ComputerName)$"){
            $User = $_.properties | Select-Object -Index 10
            $user = $user.value
            }
            
            #This is where various users, programs, paths, etc, are filtered. 
            if ($User -ne "$($ComputerName)$" -and $user -ne "-" -and $user -ne "LOCAL SERVICE" -and $user -notlike "DWM-*" -and $user -notlike "UMFD-*" -and $ProgramPath -notlike "*RuntimeBroker.exe*" -and $ProgramPath -notlike "*backgroundTaskHost.exe*" -and $ProgramPath -notlike "*SearchProtocolHost.exe*" -and $ProgramPath -notlike "*AgentExecutor.exe*" -and $ProgramPath -notlike "*conhost.exe*" -and $ProgramPath -notlike "*dllhost.exe*" -and $ProgramPath -notlike "*taskhostw.exe*") {



                #This section builds an array of every program launched along with all the user(s) who launched it.
                #Ex: chrome.exe     : Tom
                #Ex: cmd.exe        : Bob,Tom
                #This could be used for more advanced filtering but as of current it has NO EFFECT on the events collected and could be disabled entirely if you want.

                #See if the array does NOT already contain the combination of user and program for the current event. If it does, this is skipped as we have nothing to add. If not, it is processed.
                if (($TempArrayAppListCreation.$Program -split ",") -notcontains "$($user)"){
                    #We currently know our current combination of user/program is not yet in the array. If the array doesn't have the current program in it at all, then add our current program and user.
                    if ($TempArrayAppListCreation.$Program -eq $null) { 
                      $TempArrayAppListCreation | Add-Member -MemberType NoteProperty -Name "$($Program)" -Value "$($user)" -Force
                    } else {
                    #else - if the array did have the program but not the current user meaning this is not the first user to execute that app, then add the current user to the existing app entry.
                      $TempArrayAppListCreation.$Program += ",$($user)"
                    }


                    Write-host "Creation $($Program) $($user) $($TimeOfLogUTC)"
                    
                  

                    #Remove Creation message bloat
                    #I hate how this looks but out of all the methods I tried it's the only one that worked.
                    $Message = $_.Message | Out-String
                    $Message = $Message.trimend("")
                    $Message = $Message.trimend("Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.")
                    $Message = $Message.trimend("")
                    $Message = $Message.trimend("Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.")
                    $Message = $Message.trimend("")
                    $Message = $Message.trimend("Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.")
                    $Message = $Message.trimend("")
                    $Message = $Message.trimend("Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.")
                    $Message = $Message.trimend("")
                    

                    #If we are here, an event is being added.
                    $EventCount = $EventCount + 1
                   
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force 
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
                    $TempArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Creation" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "Program" -Value "$($Program)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ProgramPath" -Value "$($ProgramPath)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($Message)" -Force
                    $ApplicationUsageArray += $TempArray

                    
                    }
            }  else {
            $FilteredEvents = $FilteredEvents + 1
            Write-host "Filtered Creation Event"
            }
            }



            #Process termination
            if ($_.ID -eq 4689) {
            #pull our program value
            $ProgramPath = $_.properties | Select-Object -Index 6
            $ProgramPath = $ProgramPath.value
            $Program = ($ProgramPath -split '\\')[-1]
    
            #Pull our User value
            $User = $_.properties | Select-Object -Index 1
            $user = $user.value
                
            #This is where various users, programs, paths, etc, are filtered.
            if ($User -ne "$($ComputerName)$" -and $user -ne "-" -and $user -ne "LOCAL SERVICE" -and $user -notlike "DWM-*" -and $user -notlike "UMFD-*" -and $ProgramPath -notlike "*RuntimeBroker.exe*" -and $ProgramPath -notlike "*backgroundTaskHost.exe*" -and $ProgramPath -notlike "*SearchProtocolHost.exe*" -and $ProgramPath -notlike "*AgentExecutor.exe*" -and $ProgramPath -notlike "*conhost.exe*" -and $ProgramPath -notlike "*dllhost.exe*" -and $ProgramPath -notlike "*taskhostw.exe*") {


                #This section builds an array of every program /terminated along with all the user(s) who terminated it.
                #Ex: chrome.exe     : Tom
                #Ex: cmd.exe        : Bob,Tom
                #This could be used for more advanced filtering but as of current it has NO EFFECT on the events collected and could be disabled entirely if you want.

                #See if the array does NOT already contain the combination of user and program for the current event. If it does, this is skipped as we have nothing to add. If not, it is processed.
                if (($TempArrayAppListTermination.$Program -split ",") -notcontains "$($user)"){
                    if ($TempArrayAppListTermination.$Program -eq $null) { 
                    #We currently know our current combination of user/program is not yet in the array. If the array doesn't have the current program in it at all, then add our current program and user.
                      $TempArrayAppListTermination | Add-Member -MemberType NoteProperty -Name "$($Program)" -Value "$($user)" -Force
                    } else {
                    #else - if the array did have the program but not the current user meaning this is not the first user to terminate that app, then add the current user to the existing app entry.
                      $TempArrayAppListTermination.$Program += ",$($user)"
                    }

                    Write-host "Termination $($Program) $($user) $($TimeOfLogUTC)"
                    
                    
                    
                    #If we are here, an event is being added.
                    $EventCount = $EventCount + 1

                    $TempArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force   
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
                    $TempArray | Add-Member -MemberType NoteProperty -Name "TimeOfLogUTC" -Value "$($TimeOfLogUTC)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "EventID" -Value "$($_.ID)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "EventType" -Value "Termination" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "Program" -Value "$($Program)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "ProgramPath" -Value "$($ProgramPath)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "User" -Value "$($User)" -Force
                    $TempArray | Add-Member -MemberType NoteProperty -Name "Message" -Value "$($_.Message)" -Force
                    $ApplicationUsageArray += $TempArray
                    }
            } else {
            $FilteredEvents = $FilteredEvents + 1
            Write-host "Filtered Termination Event"
            
            }  
            }

    }

    #Combine into final array
    $FinalLog = $ApplicationUsageArray


    

######################################################
#Prepare Array for Upload via Azure Function App
######################################################

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

#store value now for writelogfile
$RawEvents = $FinalLog

#Do final event count
if ($EventCount -ne $null){
$FinalPercentage = ($EventCount/$FilteredEvents).tostring("P")
Write-host "$($EventCount) Events found. $($FilteredEvents) events filtered out. $($FinalPercentage) of events not filtered out."
}

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
if ($collectAppUsage) {
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
