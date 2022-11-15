# About UAC & Admins:
- The differences we are interested in are restrictions imposed by User Account Control (UAC) over local administrators (except for the default Administrator account). By default, **local administrators won't be able to remotely connect to a machine** and perform administrative tasks unless using an interactive session through **RDP**. Windows will deny any administrative task requested via RPC, SMB or WinRM since such administrators will be logged in with a filtered medium integrity token, preventing the account from doing privileged actions. The only local account that will get full privileges is the default Administrator account.
- **Domain accounts with local administration privileges** won't be subject to the same treatment and will be logged in with **full administrative privileges**.



### Runas is usefull:
    + runas.exe /netonly /user:<domain>\<username> cmd.exe

# 1-Psexec:
- **Required_1**: Ports: 445/TCP (SMB)
- **Required_2**: Group Memberships: Administrators
- **command**
```ps1
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe
```

# 2-WinRM(create process):
- **Required_1**: Ports: 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required_2**: Group Memberships: Remote Management Users
- **command option1**
```ps1
#To connect to a remote Powershell session from the command line, we can use the following command
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd
```
- **command option2**
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


# 3-SC.exe
**create services remotely**
- **Required_1**: Ports:
    - 135/TCP, 49152-65535/TCP (DCE/RPC)
    - 445/TCP (RPC over SMB Named Pipes)
    - 139/TCP (RPC over SMB Named Pipes)
- **Required_2**: Group Memberships: Administrators
- **command**
```ps1
# create Service
sc.exe \\TARGET create ServiceName binPath= "<command/payload to execute>" start= auto 
sc.exe \\TARGET start ServiceName
# kill Service
sc.exe \\TARGET stop ServiceName
sc.exe \\TARGET delete ServiceName
``` 

# 4-creating Scheduled Task remotely:
```ps1
schtasks /s TARGET /RU "SYSTEM" /create /tn "TaskName" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 
schtasks /s TARGET /run /TN "TaskName" 

# Kill Schedule task:
schtasks /S TARGET /TN "TaskName" /DELETE /F
```
