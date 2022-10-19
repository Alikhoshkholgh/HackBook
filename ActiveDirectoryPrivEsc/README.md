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
Windows services are managed by the Service Control Manager (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

### + check Insecure Permissions on Service Executable
	query on service to get information:
	```ps1
	# look for BINARY_PATH_NAME & SERVICE_START_NAME and check Binary for overwriting it
	C:\> sc qc apphostsvc
	# start & stop a service
	C:\> sc stop windowsscheduler
	C:\> sc start windowsscheduler
	```
### + look for Services in Registrie:
	+ HKLM\SYSTEM\CurrentControlSet\Services\	
	
### + Note: Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service,



	






# Active Directory and Kerberos attacks and qoutes:

				---Kerberos Communication---

		(user) -----------------{ AS-REQ }---------------->> Kerberos 		contains: {1-Pre Auth Data: time-stamp encrypted with user's password  2-username  3-service-name: always KRBTGT}

		(user) <<---------------{ AS-REP }------------------ Kerberos		contains: {1-UserTicket:encrypted by krbtgt's password   2-SessionKey: encrypted with user's password }

		(user) -----------------{ TGS-REQ }--------------->> Kerberos		contains: {1-Service principal name  2-Pre-Auth ticket 3-Authenticator}

		(user) <<---------------{ TGS-REP }----------------- Kerberos		contains: {1-ServiceTicket: encrypted with service password  2-SessionKey: encrypted with user's password }

		(user) -----------------{ AP-REQ }----------------->> Service		contains: {1- ServiceTicket  2-Authenticator}







-------------------------------------------------------------------------------------------------------------------------------------- How To ATTACK:	


1- AS-REP roasting attack:
		+ if "Kerberos preauthentication" is disabled. _ AD doesnt check the time. _ so we can do the replay attack
		+ somehow we are able to ask the system to give us all the users that have this property

		+ AS-REP contains:
			{ User ticket(TGT):encrypted by krbtgt's password + session key : encrypted by user's password}
 


1- attack on TGS-REP:
		+ if "Kerberos preauthentication" is enabled and if we were able to capture the network packets, we can ready the content of this packet and then crack it to find user's password


2- NTLM RELAY: ?


3- kerberoasting:
		+ using a AD user we can request for a TGT to use a service, then we can crack the password-hash of that service
		+ this works IF the service was installed on user based account. NOT computer based
		+ TGS-REP contains:
			


4- pass the hash


5- DCSync Attack: First impersonate a Domain-Controller and then request to other Domain-Controllers to give you information
5- AD Replication: database replication between domain controllers. impersonate a Domain-Controller


6- visibility of group policies


7- Cached Credentials (Mscach): 
		+ attacking the localy cached password on any computer.
		+ maybe there is a Dmain-Admin that previously loged into target's computer and his password is alredy cached in registery


8- Important-Users: 
		most Attractive credentials for malicious actors that are under the 'Users' group in AD is
		  + user:"Administrator"		(obvious) 
		  + user:"krbtgt" 			(for golden ticket attacks)
		  + group:"Enterprise Admins"		(a group of all of the domain admins) 


9- steal NTDS.dit database 


10- Sid History Hack: 
		+ users are actually identified with this numbers  
		+  (Example: 5-1-5-21-565990156-30132566284-3589782459-500)  
			-->  user_sid = DOMAIN_sid (5-1-5-21-565990156-30132566284-3589782459) + RID (500)


11- DC Shadow Attack:
		+ register a Domain-Admin


12- pass-the-Kerberos-ticket


13- Golden Ticket:
		+ if we know the password of the "KRBTGT" account, then we can run the Golden-ticket attack
		+ KRBTGT-user:  KRBTGT is the service account for the KDC this is the Key Distribution Center 
			that issues all of the tickets to the clients. If you impersonate this account and create 
			a golden ticket form the KRBTGT you give yourself the ability to create a service ticket 
			for anything you want
		+ note: KRBTGT remembers tha lst TWO PASSWORDS.
		+ essential information that we should have:
			+ Domain name
			+ Domain Admin username
			+ Domain SID
			+ Password hash of the krbtgt


14- Silver Ticket:
		+ again we are able to send a ticket to a service but this time this ticket is specific to the service. NOT GOLDEN
		+ a Silver ticket is a forged service authentication ticket	
		+ we have to know the password for that service-accoutn that we try to attack
		+ with this ticket, IF "PAC authentication" is disabled, there is no communication between domain-controller and service


15- Skeleton Key attack: 
		+ inject the skeleton key malware to LSASS on a domain-controller 
			which creates a master password for any account without any conflict with actual user's password
		+ if anytime domain-controler's computer goes down, this password gonna be disappeared


16- AdminADHolder attack:
		+ somehow its related to permissions of resouces and manipulate them
		+ related to "SDProp" process   
		+ by abusing this process, we probably have access to all of the protected groups:
			+Administrator User
			+ Krbtgt User
			+ Account Operatos Group	
			+ Adminstrator Group
			+ Backup Operators Group
			+ Domain Admins Group
			+ Domain Controllers Group
			+ Enterprise Admins Group
			+ Print Operators Group
			+ Read-olny Domain Controllers Group
			+ Replicator
			+ Schema Admins Group
			+ Server Operators Group

---------------------------------------------------------------------- 







-------------------------------------------------------------------------------------------------------------------------------------- TOOLS:

1- Responder

2- mimikatz

3- NTLMRelayx

4- Rubeus

5- disinternals

6- NTDSUtil	(steal NTDS)

7- Impacket

8-kerbrute
---------------------------------------------------------------------- 






-------------------------------------------------------------------------------------------------------------------------------------- Qoutes 


--> kerberos tickets are stored in LSAS

--> in active directory, each domain has its own database.


--> as a hacker, we should look for forest root domains.


--> the database for each domain will be replicated and copies itself to all of the domain controller's  computers.


--> SAM database path (SAM):
	+ C:\Windows\System32\config\SAM


--> Active directory databse path (NTDS):
	+ C:\Windows\ntds\ntds.dit


--> NTLM version-2 has a time-stamp on it to avoid replay attacks. with some kind of timeout of 5s


--> CACHED Credentials:
	+ for user to be able to login to their accounts when network is down or domain controller is down, what 
	   system does is that it caches the user credentials LOCALY in the system to make this work. and this 
	   causes some issues.
	+ depending on system configurations, cached password can be up to last 25-50 user's password.
	_ Mitigation: use "Protected Users" group to prevent this kind of credentials to be cached.


--> User Principal Name (UPN): user logonname + the domain name like james@geektoys.com


--> service Pirncipal Name (SPN): 
		+ unique identifier of a service instance
		+ can be assigned to 1-user-accounts(Service Account) or 2-Computer-accounts
 

--> kerberos:
		+ runs on the domain controller
		+ there are two kind of tickets:  TGT, TGS 
		

--> info: group-name = "Group Managed Service Accounts(GMSA)"
		+ mitigation: create service accounts and add it to this group to maintain
		+ this group sets a long password account and changes the password dynamicly every 30-days

--> try to keep the number of the domain-admins small as possible

---------------------------------------------------------------------- 


-------------------------------------------------------------------------------------------------------------------------------------- Default Security Groups:

	--> Domain Controllers - All domain controllers in the domain

	--> Domain Guests - All domain guests

	--> Domain Users - All domain users

	--> Domain Computers - All workstations and servers joined to the domain

	--> Domain Admins - Designated administrators of the domain

	--> Enterprise Admins - Designated administrators of the enterprise

	--> Schema Admins - Designated administrators of the schema

	--> DNS Admins - DNS Administrators Group

	--> DNS Update Proxy - DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).

	--> Allowed RODC Password Replication Group - Members in this group can have their passwords replicated to all read-only domain controllers in the domain

	--> Group Policy Creator Owners - Members in this group can modify group policy for the domain

	--> Denied RODC Password Replication Group - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain

	--> Protected Users - Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.

	--> Cert Publishers - Members of this group are permitted to publish certificates to the directory

	--> Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain

	--> Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise

	--> Key Admins - Members of this group can perform administrative actions on key objects within the domain.

	--> Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest.

	--> Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned.

	--> RAS and IAS Servers - Servers in this group can access remote access properties of users

-------------------------------------------------------------------------------------------------------------------------------------- 




-------------------------------------------------------------------------------------------------------------------------------------- attack scenario:




  		+-> if kerberos port was exposed, bruteforce usernames.
                        kerbrute userenum --dc <DomainName> -d <DomainName> <userlist-file>

		+-> look for users with "kerberos pre-authentication:Disable"

		+-> with this users we can request TGT then crack the it to find user's password. 
                	tool:Rubeus
                        crack users and computer's passwords ( Rebeus.exe harvest /interval:30 ) (harvesting TGT)
                        find and crack service's passwords ( Rubeus.exe kerberoast ) (kerberoasting)
                        find users with disabled pre-authentication and crack their passwords(AS-REP Roasting)


                +-> tool:mimikatz  
                        dump the LSAS
                        pass the ticket(TGT ticket), then impersonate admin user if it exsits, we just reused the ticket


                +-> tool:mimikatz
                        Golden/Silver ticket attack

                +-> tool:mimikatz
                        key skeleton attack. maitaining access
                                                                  



------------------------------------------------------------------------------------------------------------------------- Kerberos Communication



		







