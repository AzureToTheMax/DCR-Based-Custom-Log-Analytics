#Windows 365 App Collector

<#
.SYNOPSIS
Windows 365 App Collector
Collects information regarding "Microsft Teams" and "Remote Desktop WebRTC Redirector Service"
            
.NOTES
Author:      Maxton Allen
Contact:     @AzureToTheMax
Created:     2023-02-15
Updated:     2023-06-17
Based on the work of Nickolaj Andersen, @NickolajA and the MSEndpointMGR team

            
Version history:
1 - 2023-02-15 Created
2 - 2023-06-17 updated to new HTTP auth
#>


######################################################################
#Region Variables
#Controls various Script customizeable Variables


#Script Version - Used for update tracking and version specific queries.
$ScriptVersion = "2"

#Function App URL for Log Upload
$AzureFunctionURL = ""

#Custom table name including _CL
$Table = "Windows365Apps_CL"

#DCR to reach that table
$DcrImmutableId = ""

#Turn on/off collection - Should be true. Automated to run off CPC name.
if ($ENV:COMPUTERNAME -like "*CPC-*"){
    $CollectAppInventory = $true
} else {
    $CollectAppInventory  = $false
    Write-Host "Not a Cloud PC"
    exit 0
}

#Friendly log name. Name it what you want. Just used for logging, local JSON export, the name the data is referenced by inside the JSON, and log control on the function app.
$AppLogName = "Win365AppInventory"

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
#Get-AzureADJoinDate
#Get-AzureADTenantID
#New-AADDeviceTrustBody
#Test-AzureADDeviceRegistration
#Get-AzureADRegistrationCertificateThumbprint
#Get-PublicKeyBytesEncodedString
#New-RSACertificateSignature
######################################################################

function Get-AzureADDeviceID {
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
            }
            if ($AzureADJoinCertificate -eq $null) {
                $AzureADDeviceID = $AzureADJoinInfoThumbprint
                return $AzureADDeviceID
            }
        }
    }
} #endfunction 
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

#endregion
######################################################################




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
$ComputerManufacturer = $ComputerInfo.Manufacturer

	#Get network adapters. Not sure when region based software may come into play, but better to have it.
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
	
	




#region APPINVENTORY



if ($CollectAppInventory) {

		#Gather the active user
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
	

	#Generate our App Array
	$AppArray = @()
	

	foreach ($App in $CleanAppList) {


		$tempapp = New-Object -TypeName PSObject

		if($App.DisplayName -eq "Microsoft Teams" -or $App.DisplayName -eq "Remote Desktop WebRTC Redirector Service" -or $App.DisplayName -eq "MsMmrHostMsi" -or $App.DisplayName -eq "Remote Desktop Multimedia Redirection Service") {
		
		
		#Clear the contents of the app install date each time through, otherwise a null value inherits the date of the previous app.
		$AppInstallDate = $null
		#Change our installdate key to a more user friendly date
		if ($app.InstallDate -ne $null){
		$AppInstallDate = [Datetime]::ParseExact($($App.InstallDate), 'yyyymmdd', $null).ToString('mm-dd-yyyy') 
		}
		
		
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppName" -Value $App.DisplayName -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $App.DisplayVersion -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppInstallDate" -Value $AppInstallDate -Force -ErrorAction SilentlyContinue
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppPublisher" -Value $App.Publisher -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallString" -Value $App.UninstallString -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallRegPath" -Value $app.PSPath.Split("::")[-1]

		$AppArray += $tempapp
		write-host "Adding App $($tempapp.AppName)"

		} else {
		#non approved apps
		#Write-host "App $($App.DisplayName) not on approved list!"

		}
		
	
	#Compile
	[System.Collections.ArrayList]$AppArrayList = $AppArray
	


	

	$AppInventory = New-Object System.Object
	$AppInventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
	$AppInventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
	$AppInventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
	$AppInventory | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value "$ScriptVersion" -Force
	$AppInventory | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
	$AppInventory | Add-Member -MemberType NoteProperty -Name "AppPayLoad" -Value $AppArrayList -Force


	$AppPayLoad = $AppInventory


}

#endregion APPINVENTORY




######################################################
#Prepare Array for Upload via Azure Function App
######################################################
#Get Common data for validation in Azure Function: 
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")



#Format Data for Submission to DCR
$RawEvents = $AppPayLoad 
$AppPayLoad =  $AppPayLoad | ConvertTo-Json
$AppPayLoad = "[" + "
$($AppPayLoad)
" + "]"


#Format data for Function App
$LogPayLoadApp = New-Object -TypeName PSObject 
$LogPayLoadApp | Add-Member -NotePropertyMembers @{$AppLogName = $AppPayLoad }

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
	$BodyTable  | Out-File "C:\Temp\LogAnalytics\$($AppLogName)-Full.json"
	$RawEvents | ConvertTo-Json | Out-File "C:\Temp\LogAnalytics\$($AppLogName)-RAW.json"
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
        $ResponseAppInventory = Invoke-RestMethod -Method "POST" -Uri $AzureFunctionURL -Body ($BodyTable | ConvertTo-Json -depth 9) -ContentType "application/json" -ErrorAction Stop


    }






#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

if ($CollectAppInventory) {
    if ($ResponseAppInventory -match "204:") {
        
        $OutputMessage = $OutPutMessage + " AppInventory:OK " + $ResponseAppInventory
    }
    else {
        $OutputMessage = $OutPutMessage + " AppInventory:Fail "
    }
}
Write-Output $OutputMessage
Exit 0
