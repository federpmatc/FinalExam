#Capstone Setup.ps1
#12/24/2021

#region - Config IP and Computer Name
Get-ChildItem env:
dir env:

#Check current IP
Get-NetIPConfiguration
Get-NetAdapter -Physical

#Remove IP address
$interface = Get-NetAdapter -Physical | Get-NetIPInterface -AddressFamily "IPv4"
If ($interface.Dhcp -eq "Disabled") {
 # Remove existing gateway
 If (($interface | Get-NetIPConfiguration).Ipv4DefaultGateway) { $interface | Remove-NetRoute -Confirm:$false }
 # Enable DHCP
 $interface | Set-NetIPInterface -DHCP Enabled
 # Configure the DNS Servers automatically
 $interface | Set-DnsClientServerAddress -ResetServerAddresses
}
    
New-netIPAddress -IPAddress 192.168.20.101 -PrefixLength 24 -DefaultGateway 192.168.20.1 -InterfaceIndex 5

Set-DnsClientServerAddress `
        -InterfaceIndex 5 `
        -ServerAddresses 192.168.20.101

#rename computer
Rename-Computer -NewName DC1
Restart-Computer

#check computer name
Get-ChildItem Env:\COMPUTERNAME
#endregion - Config IP and Computer NAme

#region - Install AD Domain Services
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
#Note we have the option to promote this to a DC (in Server Manager now)

Import-Module ADDSDeployment

#Configure this server as the first Active Directory domain controller in a new forest.
#The new domain name is "ITNET-154.pri". This is also the name of the new forest.
#The NetBIOS name of the domain: ITNET-154
#Forest Functional Level: Windows Server 2016
#Domain Functional Level: Windows Server 2016
#Additional Options:
#  Global catalog: Yes
#  DNS Server: Yes
#  Create DNS Delegation: No
# Database folder: C:\Windows\NTDS
#Log file folder: C:\Windows\NTDS
#SYSVOL folder: C:\Windows\SYSVOL
#The DNS Server service will be configured on this computer.
#This computer will be configured to use this DNS server as its preferred DNS server.
#The password of the new domain Administrator will be the same as the password of the local Administrator of this computer.
#This will reboot computer less than 5 minutes

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

#region - config DHCP
Add-WindowsFeature -IncludeManagementTools dhcp
#Add local DCHP groups ìDHCP Administratorsî and ìDHCP Usersî 
#https://blogs.technet.microsoft.com/craigf/2013/06/23/installing-dhcp-on-windows-server-2012-did-not-create-the-local-groups/
netsh dhcp add securitygroups

#Authorize DHCP Server
Add-DhcpServerInDC

#Remove notification
Set-ItemProperty `
        Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
        Name ConfigurationState `
        Value 2

#############################
##Create a DHCP scope for the 192.168.20.0 subnet called Main Scope w/ a range of 192.168.20.200-.250
    Add-DhcpServerv4Scope `
        -Name ì192.168.20.0 `
        -StartRange 192.168.20.200 `
        -EndRange 192.168.20.250 `
        -SubnetMask 255.255.255.0 `
        -ComputerName DC1 `
        -LeaseDuration 8:0:0:0 `
        -verbose

    ##Set DHCP Scope Options including DNSserver, DnsDomain, and Router (aka Default Gateway) used by your clients
    Set-DhcpServerv4OptionValue  `
        -ScopeId 192.168.20.0 `
        -ComputerName DC1.ITNET-154.pri `
        -DnsServer 192.168.20.101 `
        -DnsDomain itnet-154.pri `
        -Router 192.168.20.1 `
        -Verbose

    Get-DhcpServerv4Scope | FL
    Get-DhcpServerv4Lease -ScopeId 192.168.20.0
    Test-NetConnection 192.168.20.201
#endregion - Config DHCP

#region - Configure DNS Records
    Get-DnsServerZone -ComputerName DC1
    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri

    #Add A Record
    Add-DnsServerResourceRecordA -Name www -ZoneName ITNET-154.pri -IPv4Address 192.168.20.101
    Get-DnsServerZone -Name ITNET-154.pri 
    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri
   
#endregion - Configure DNS 

#region - Configure Windows 10 Client
Get-NetIPConfiguration
    $env:computername
    Rename-Computer -NewName Client1
        
    #Set Time Zone 
    Tzutil.exe /?
    Tzutil.exe /g
    Tzutil.exe /s "Central Standard Time"
    Restart-computer -Force 
    
    $Domaincred = Get-Credential -Credential "ITNET-154\administrator"  #Domain Credentials
    Add-Computer -DomainName ITNET-154.pri -credential $Domaincred -Restart

#Verify Remote System is Domain Joined and in DNS
    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri
    Get-ADComputer -Filter *
    Test-NetConnection Client1.ITNET-154.pri #may fail due if firewall enabled, name resolution works
    Set-NetFirewallProfile -Name domain -Enabled False
#endregion - Configure Windows 10 Client

#region - Verify Remote System is Domain Joined
    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri
    Get-ADComputer -Filter *
    Test-NetConnection Client1.ITNET-154.pri #Will fail due to firewall, successful on name resolution
#endregion - Verify Remote System is Domain Joined

#region - Configure Member Server
   #Re-Set Trusted Hosts (Optional)

    Get-Item WSMan:\localhost\Client\TrustedHosts
    Set-item WSMAN:\Localhost\Client\TrustedHosts -value * -Force

#Start up a client computer
#On the client run enable-psremoting (this is on by default in Server 2016)

    #Find IP Address for Client
    Get-DhcpServerv4Lease -ScopeId 192.168.20.0 
    
    #Set IP Address
    #provide credentials on client (admin/Password01)
    Enter-PSSession -ComputerName 192.168.20.200 -Credential "Administrator"
    
    Get-NetIPConfiguration
    New-netIPAddress -IPAddress 192.168.20.252 -PrefixLength 24 -DefaultGateway 192.168.20.1 -InterfaceIndex 4
        #Will freeze up for a bit since we changed IP Address
    
    Enter-PSSession -ComputerName 192.168.20.252 -Credential "Administrator"      
        #Rename DC2
        Rename-Computer -NewName DC2
        #Set Time Zone 
        Tzutil.exe /?
        Tzutil.exe /g
        Tzutil.exe /s "Central Standard Time"
 
    Set-DnsClientServerAddress `
        -InterfaceIndex 8 `
        -ServerAddresses 192.168.20.101

    Restart-computer -Force 
    
    Enter-PSSession -ComputerName 192.168.20.252 -Credential "Administrator"
        Get-NetIPConfiguration
        $env:computername
   
#Domain Join ServerB
    $Domaincred = Get-Credential -Credential "ITNET-154\administrator"  #Domain Credentials
    Invoke-command -ComputerName 192.168.20.252 -Credential "Administrator" -scriptblock {
        Add-Computer -DomainName ITNET-154.pri -credential $using:Domaincred -Restart}

    #if you enable PSR Remoting on the client, the following ilustrates that multiple commands can be executed simultaneously
    ICM -ComputerName dc2, client1 -ScriptBlock { 
    gsv
    gps}

#Verify Remote System is Domain Joined and in DNS

    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri
    Get-ADComputer -Filter *
    Test-NetConnection DC2.ITNET-154.pri #Will fail due to firewall, successful on name resolution

#endregion - Configure Member Server

#region - Promote to DC
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
 
#This example shows how to create a credential object that is identical to the object that Get-Credential returns without prompting the user. 
#This method requires a plain text password, which might violate the security standards in some enterprises.
$Pword = ConvertTo-SecureString "Password01" -AsPlainText -Force
$User = "ITNET-154\Administrator"
$DomainCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

#Used wizard to generate this.  i added the $pword & $domaincred
Import-Module ADDSDeployment
Install-ADDSDomainController `
-NoGlobalCatalog:$false `
-Credential $DomainCred `
-CriticalReplicationOnly:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainName "ITNET-154.pri" `
-InstallDns:$false `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SiteName "Default-First-Site-Name" `
-SysvolPath "C:\Windows\SYSVOL" `
-SafeModeAdministratorPassword $Pword `
-Force:$true
#endregion

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

# Run Create 20 Users
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

#Add Admin1 & Admin2 to Admin Groups
Add-ADGroupMember -Identity 'Domain Admins' -Members 'Admin1','Admin2'

Rename-ADObject -Identity "CN=Administrator,CN=Users,DC=ITNET-154,DC=pri" -NewName "Enterprise_Admin"
Get-ADUser -Filter "name -like 'Enterprise_Admin'"
Get-ADUser -Filter "name -like 'Enterprise_Admin'" | Set-ADUser -UserPrincipalName "Enterprise_Admin@ITNET-154.pri" -SamAccountName "Enterprise_Admin"

#endregion - Create User Accounts
