#The following script can be used to create bulk users
#Create 20 Users.ps1
#11/9/2021

#$DomainName set to your domain
$domainName = "ITNET-154.pri"

#$Path should be set to the distinguished name of the OU where users will be created
#The following will show Distinguished Names for all OUs
Get-ADOrganizationalUnit -Filter * | select-object name, distinguishedname

$path = "OU=TempEmployees,DC=ITNET-154,DC=pri"

#$total should be set to how many users you want to create
$total=20

#The following block of code will get executed multiple times (or whatever the value of $total is set to.
1..$total |foreach { 
$userName = "Employee$_"
Write-Host "Creating user $userName@$domainName.  User $_ of $total" 

New-ADUser -AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "$userName" `
-Enabled $true `
-Path $path `
-SamAccountName "$userName" `
-UserPrincipalName ($userName + "@" + $domainName)
}

Get-ADUser -Filter * -SearchBase $path



