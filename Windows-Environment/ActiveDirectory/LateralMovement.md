# About UAC & Admins:
- The differences we are interested in are restrictions imposed by User Account Control (UAC) over local administrators (except for the default Administrator account). By default, **local administrators won't be able to remotely connect to a machine** and perform administrative tasks unless using an interactive session through **RDP**. Windows will deny any administrative task requested via RPC, SMB or WinRM since such administrators will be logged in with a filtered medium integrity token, preventing the account from doing privileged actions. The only local account that will get full privileges is the default Administrator account.
- **Domain accounts with local administration privileges** won't be subject to the same treatment and will be logged in with **full administrative privileges**.



### Runas is usefull:
    + runas.exe /netonly /user:<domain>\<username> cmd.exe

# Psexec:
- **Required_1**: Ports: 445/TCP (SMB)
- **Required_2**: Group Memberships: Administrators
- **command**
```ps1
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe
```

# WinRM(create process):
- **Required_1**: Ports: 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required_2**: Group Memberships: Remote Management Users
- **command**
```ps1
#To connect to a remote Powershell session from the command line, we can use the following command
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd
```
- **OR**:
```ps1
#We can achieve the same from Powershell, but to pass different credentials, we will need to create a PSCredential object:
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
#Options1_ Interactive session:
Enter-PSSession -Computername TARGET -Credential $credential
#Options2_ run Script:
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```

