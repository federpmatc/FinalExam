#Capstone Setup.ps1
#3/24/2024

#region - Config IP and Computer Name
Get-ChildItem env:
dir env:

#Check current IP
Get-NetIPConfiguration
Get-NetAdapter -Physical


#region - Install AD Domain Services
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
#Note we have the option to promote this to a DC (in Server Manager now)

Import-Module ADDSDeployment

Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName "ITNET-154.pri" `
-DomainNetbiosName "ITNET-154" `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true

#Get the AD Domain Controllers
Get-ADDomainController

#Get ADGroups
Get-ADGroup -Filter * | Select-Object name, groupscope 

#endregion - Install AD Domain Services

###################################################################################
#region - config DHCP
Add-WindowsFeature -IncludeManagementTools dhcp
#Add local DCHP groups DHCP Administrators and DHCP User 
#https://blogs.technet.microsoft.com/craigf/2013/06/23/installing-dhcp-on-windows-server-2012-did-not-create-the-local-groups/

netsh dhcp add securitygroups

#Note: the following cmdlet is the equivalent of the command above
Add-DhcpServerSecurityGroup

#Authorize DHCP Server
Add-DhcpServerInDC

#Remove notification
Set-ItemProperty `
        -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
        -Name ConfigurationState `
        -Value 2

#############################
##Create a DHCP scope for the 192.168.222.0 subnet called Main Scope w/ a range of 192.168.222.200-.250
    Add-DhcpServerv4Scope `
        -Name ì192.168.222.0 `
        -StartRange 192.168.222.200 `
        -EndRange 192.168.222.250 `
        -SubnetMask 255.255.255.0 `
        -ComputerName DC1 `
        -LeaseDuration 8:0:0:0 `
        -verbose

    ##Set DHCP Scope Options including DNSserver, DnsDomain, and Router (aka Default Gateway) used by your clients
    Set-DhcpServerv4OptionValue  `
        -ScopeId 192.168.222.0 `
        -ComputerName DC1.ITNET-154.pri `
        -DnsServer 192.168.222.101 `
        -DnsDomain itnet-154.pri `
        -Verbose

    Get-DhcpServerv4Scope | FL
    Get-DhcpServerv4Lease -ScopeId 192.168.222.0
    Test-NetConnection 192.168.222.201
#endregion - Config DHCP

#region - Configure DNS Records
    Get-DnsServerZone -ComputerName DC1
    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri

    #Add A Record
    Add-DnsServerResourceRecordA -Name www -ZoneName ITNET-154.pri -IPv4Address 192.168.20.101
    Get-DnsServerZone -Name ITNET-154.pri 
    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri
#endregion - Configure DNS 

#Verify Remote System is Domain Joined and in DNS

    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri
    Get-ADComputer -Filter *
    Test-NetConnection DC2.ITNET-154.pri #Will fail due to firewall, successful on name resolution

#region - Create OUs
New-ADOrganizationalUnit -Name TempEmployees -Path "DC=ITNET-154, DC=pri"
#Create the Employees, Workstations, and Member Servers OUs (and sub OUs) 

New-ADOrganizationalUnit -Name Employees -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Workstations -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name "Member Servers" -Path "DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Employees, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Employees, DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Workstations, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Workstations, DC=ITNET-154, DC=pri"
#endregion - Create OUs

#region - Create User Accounts
#Create Admin1, Admin2
New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "Admin1" `
-Enabled $true `
-Path "CN=Users, DC=ITNET-154, DC=pri" `
-SamAccountName Admin1 `
-UserPrincipalName ("Admin1@ITNET-154.pri")

New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "Admin2" `
-Enabled $true `
-Path "CN=Users, DC=ITNET-154, DC=pri" `
-SamAccountName Admin2 `
-UserPrincipalName ("Admin2@ITNET-154.pri")

#Add Admin1 & Admin2 to Domain Admin Groups
Add-ADGroupMember -Identity 'Domain Admins' -Members 'Admin1','Admin2'

Rename-ADObject -Identity "CN=Administrator,CN=Users,DC=ITNET-154,DC=pri" -NewName "Enterprise_Admin"
Get-ADUser -Filter "name -like 'Enterprise_Admin'"
Get-ADUser -Filter "name -like 'Enterprise_Admin'" | Set-ADUser -UserPrincipalName "Enterprise_Admin@ITNET-154.pri" -SamAccountName "Enterprise_Admin"

#endregion - Create User Accounts
