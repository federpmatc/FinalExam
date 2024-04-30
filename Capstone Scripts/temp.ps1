$Password = ConvertTo-SecureString "Password01" -AsPlainText -Force
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
-SafeModeAdministratorPassword $Password `
-Force:$true
