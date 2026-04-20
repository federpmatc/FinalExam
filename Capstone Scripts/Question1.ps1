#Some of the commands used in the screencast for question 1

Get-NetIPConfiguration
Get-CimInstance -ClassName Win32_ComputerSystem
Get-ADGroupMember   -Identity  “Domain Admins”        
Get-ADGroupMember   -Identity  "Enterprise Admins”         
New-ADUser -Name "Admin" -SamAccountName "Admin" -AccountPassword (Read-Host -AsSecureString "Enter Password") -Enabled $true
Add-ADGroupMember -Identity "DOmain Admins" -Members "Admin"
Add-ADGroupMember -Identity "Enterprise Admins" -Members "Admin"

$response = Read-host "Enter yes to Reboot"
if ($response.ToLower() -eq "yes") {
    Restart-Computer
} 

