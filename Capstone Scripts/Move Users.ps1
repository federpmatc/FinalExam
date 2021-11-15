#Move Users.ps1

$factory ="OU=Factory,OU=Employees,DC=ITNET-154,DC=pri"
$office = "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"

#Move Employee1..10 to $factory
for ($UserIndex=1; $UserIndex -le 10; $UserIndex++)
{

$userName = "Employee$userIndex"
$user = get-aduser $userName
Write-Host "Moving user $user.DistinguishedName to $factory" 
Move-ADObject $user -TargetPath $factory
}

#The following would also move Employee11..20 to $office
11..20 | foreach { Get-aduser "Employee$_" | Move-ADObject -TargetPath $office }

#Create Global Group
New-ADGroup -GroupScope Global -Name "GG_Office" 
New-ADGroup -GroupScope Global -name "GG_Factory"

#Modify Group Membership
1..10 | foreach {Add-ADGroupMember -Identity "GG_Factory" -Members "Employee$_" }
11..20 | foreach {Add-ADGroupMember -Identity "GG_Office" -Members "Employee$_" }
