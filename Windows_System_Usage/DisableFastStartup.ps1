<#
    .SYNOPSIS
    This script is packaged into an app to disable fast startup.
    
    Path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power\HiberbootEnabled
    Value: 0

    The detection rule for the app looks to validate this registry key is configured as expected. 
                
    .NOTES
    Author:      Maxton Allen
    Contact:     @AzureToTheMax
    Updated:     2023-10-08
    Updated:     2023-10-08


   
Version history:
1.0: Script Created


#>

#Create and/or set the registry key
New-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -PropertyType DWord -Value 0 -Force
Set-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -Value 0 -Force

exit 0