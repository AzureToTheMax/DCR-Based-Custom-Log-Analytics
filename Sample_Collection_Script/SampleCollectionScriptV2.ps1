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

#>


######################################################################
#Region Variables
#Controls various Script customizeable Variables

#Script Version - Used for update tracking and version specific queries.
$ScriptVersion = "2"

#FunctionAppURI for Log Upload
$AzureFunctionURL = ""

#Custom table name including _CL
$Table = ""

#DCR to reach that table
$DcrImmutableId = ""

#Enable data collection. Default is True.
$CollectData = $true

#Friendly log name. Name it what you want. Just used for logging, local JSON export, the name the data is referenced by inside the JSON, and log control on the function app.
$LogName = ""

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
$ComputerModel = $ComputerInfo.Model

$ComputerBiosInfo = Get-CimInstance -ClassName Win32_Bios
$ComputerSerialNr = $ComputerBiosInfo.SerialNumber

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
    $Inventory | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value "$ComputerSerialNr" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "Model" -Value "$ComputerModel" -Force
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

# Construct main payload to send to LogCollectorAPI // IMPORTANT // KEEP AND DO NOT CHANGE THIS
$MainPayLoadApp = [PSCustomObject]@{
    AzureADTenantID = $AzureADTenantID
    AzureADDeviceID = $AzureADDeviceID
	Table = $Table
	DcrImmutableId = $DcrImmutableId
    LogPayloads     = $LogPayLoadApp
}
$MainPayLoadJson = $MainPayLoadApp | ConvertTo-Json -Depth 9	




    if ($WriteLogFile){
    write-host "writing log file"
    New-Item C:\Temp -ItemType Directory -ErrorAction SilentlyContinue > $null 
    New-Item C:\Temp\LogAnalytics -ItemType Directory -ErrorAction SilentlyContinue > $null 
	$MainPayLoadJson  | Out-File "C:\Temp\LogAnalytics\$($LogName)-Full.json"
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
        $ResponseSampleCollector = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson 
       

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
