New-Item -Path "C:\" -Name "Employees" -ItemType Directory -Force
New-Item -Path "C:\Employees" -Name "TimeSheets" -ItemType Directory
New-Item -Path "C:\" -Name "TestPermissions" -ItemType Directory -Force

New-ADGroup -GroupScope Global -Name "GG_Factory"
New-ADGroup -GroupScope Global -Name "GG_Office"

Get-acl "C:\Employees" | Out-GridView
Get-acl "C:\Employees" | Format-List
Get-acl "C:\TestPermissions" | fl #use to determine format, group identification, syntax, etc

New-SmbShare -Path "C:\Employees" -Name Employees -FullAccess "Domain Admins","GG_Factory","GG_Office"
Get-SmbShareAccess -Name Employees

#https://blog.netwrix.com/2018/04/18/how-to-manage-file-system-acls-with-powershell-scripts/
$acl = Get-acl "C:\Employees"
$acl | gm
#The first parameter is responsible for blocking inheritance from the parent folder. It has two states: “$true” and “$false”.
#The second parameter determines whether the current inherited permissions are retained or removed. It has the same two states: “$true” and “$false”.
#Disable Inheritance, Retain permissions
$acl.SetAccessRuleProtection($true,$true)   

$acl | set-acl "C:\Employees" 
set-acl "C:\Employees" -AclObject $acl

$acl = Get-acl "C:\Employees"
#Remove the users group
$usersid = New-Object System.Security.Principal.Ntaccount ("BUILTIN\Users")
$acl.PurgeAccessRules($usersid)
$acl | Set-Acl C:\employees
$acl | fl

$acl | Set-Acl C:\TestPermissions
$acl = Get-Acl C:\TestPermissions
$acl.SetAccessRuleProtection($false,$false)  
$acl | Set-Acl C:\TestPermissions

$acl = Get-acl "C:\Employees"
#assign read permissions to C:\Employees
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("ITNET-154\GG_Factory","ReadAndExecute","ContainerInherit, ObjectInherit", "None","Allow")
$acl.SetAccessRule($AccessRule)
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("ITNET-154\GG_Office","ReadAndExecute","ContainerInherit, ObjectInherit", "None","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl C:\employees
$acl | fl

#assign Write permissions to C:\Employees\TimeSheets
$acl = Get-acl "C:\Employees\TimeSheets"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("ITNET-154\GG_Factory","Write","ContainerInherit, ObjectInherit", "None","Allow")
$acl.SetAccessRule($AccessRule)
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("ITNET-154\GG_Office","Write","ContainerInherit, ObjectInherit", "None","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl C:\employees\TimeSheets
$acl | fl
