#overall variables
    #subscription ID where the DCR is
    $Subscription = ""
    #Your Tenant ID
    $Tenantid = ""
    # Resource ID of the DCR to edit
    $ResourceId = ""
    #File path to store DCR temporarily
    $FilePath = “C:\Temp\LogAnalytics\DCR.json”


#Module and login commands
if($true -eq $false){
#Needed Module
install-Module -Name Az -Scope AllUsers -Repository PSGallery -Force

#Login commands
Update-AzConfig -DefaultSubscriptionForLogin $Subscription
Connect-AzAccount -TenantId $Tenantid

#If your subscription doesn't set correctly. 
Set-AzContext -Subscription $Subscription
}


#Get DCR
if($true -eq $false){
### you can also just put the DCR into JSON view AND MAKE SURE TO CHANGE THE API VERSION TO 2021-09-01-preview ###
$DCR = Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=2021-09-01-preview") -Method GET
$DCR.Content | ConvertFrom-Json | ConvertTo-Json -Depth 20 | Out-File -FilePath $FilePath
}


#Now edit the DCR as needed via NP++


#Upload the new DCR
if($true -eq $false){
$DCRContent = Get-Content $FilePath -Raw 
Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=2021-09-01-preview") -Method PUT -Payload $DCRContent 
#expect a 200 with a large content message - or an error telling you how you messed up. This is all case sensitive.
}