## Native commands:

### list Users:
  ```ps1
  # local users
  get-localuser
  net user
  
  # domain users
  net user /domain
  
  # domain users specific
  net user <username> /domain

  ```

### list Groups:
  ```ps1
  # domain groups
  net group /domain
  
  # domain group specific
  net group <groupname> /domain
  
  # local groups
  get-localgroup
  ```


### check account password policies:
```ps1
# on the domain
  net accounts /domain
# local
  net accounts
# Note: The net commands may not show all information. For example, 
#if a user is a member of more than ten groups, not all of these groups will be shown in the output.
```


## AD module:
  + ## **setup-install**:
    + in **windows servers** its already **installed**, and i recommend that to **only use it in windowsServer**.
    + to enable active directory module on windows10:
    ```powershell
       Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell
    ```
    + to install active directory module on windows10:
    ```powershell
       Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”
    ```


  + ## **Usage**:
  + **Get Current Domain**: `Get-ADDomain`    
  + **Enum Other Domains**: `Get-ADDomain -Identity <DomainName>`    
  + **Get Domain SID**: `Get-DomainSID`    
  + **Get Domain Controlers**:
    ```powershell    
      Get-ADDomainController
      Get-ADDomainController -Identity DomainName
      Get-ADDomainController -filter * | Select-Object name
    ```
  + **Enumerate Domain Users**:
    ```powershell
       Get-ADUser -Filter * -Identity <user> -Properties *
       #Get a spesific "string" on a user's attribute
       Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
       Get-ADUser -Identity gordon.stevens -Server sub.domainname.com -Properties *
       Get-ADUser -Filter 'Name -like "*stevens"' -Server sub.domainname.com | Format-Table Name,SamAccountName -A
    ```
  + **Enumerate Domain groups:** 
    ```powershell
        #list groups
        Get-ADGroup -Identity Administrators -Server sub.domainname.com
        #list memebers
        Get-ADGroupMember -Identity Administrators -Server sub.domainname.com
    ```
  + **Enum Domain Computers:** 
    ```powershell
        Get-ADComputer -Filter * -Properties *
        Get-ADGroup -Filter * 
    ```
    
  + **AD Objects:** 
    ```powershell
        #For example, if we are looking for all AD objects that were changed after a specific date:
        $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
        Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server sub.domainname.com        
        
        #for example, perform a password spraying attack without locking out accounts, we can use this to enumerate accounts that 
        #have a badPwdCount that is greater than 0, to avoid these accounts in our attack:
        Get-ADObject -Filter 'badPwdCount -gt 0' -Server sub.domainname.com        
    ```
    
    
# PowerView:
  + ## **Download-install**:    
    -  download [powerview.ps1](https://github.com/Alikhoshkholgh/HackBook/blob/main/ActiveDirectoryRecon/tools/PowerView.ps1)

  + ## **Usage**:    
    - **Get Current Domain:** `Get-NetDomain`
    - **Enum Other Domains:** `Get-NetDomain -Domain <DomainName>`
    - **Get Domain SID:** `Get-DomainSID`
    - **Get Domain Policy:** 
      ```powershell
      Get-DomainPolicy
      
      #Will show us the policy configurations of the Domain about system access or kerberos
      (Get-DomainPolicy)."system access"
      (Get-DomainPolicy)."kerberos policy"
      ```
    - **Get Domain Controlers:** 
      ```powershell
      Get-NetDomainController
      Get-NetDomainController -Domain <DomainName>
      ```
    - **Enumerate Domain Users:** 
      ```powershell
      Get-NetUser
      Get-NetUser -SamAccountName <user> 
      Get-NetUser | select cn
      Get-UserProperty

      #Check last password change
      Get-UserProperty -Properties pwdlastset

      #Get a spesific "string" on a user's attribute
      Find-UserField -SearchField Description -SearchTerm "wtver"

      #Enumerate user logged on a machine
      Get-NetLoggedon -ComputerName <ComputerName>

      #Enumerate Session Information for a machine
      Get-NetSession -ComputerName <ComputerName>

      #Enumerate domain machines of the current/specified domain where specific users are logged into
      Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
      ```
    - **Enum Domain Computers:** 
      ```powershell
      Get-NetComputer -FullData
      Get-DomainGroup

      #Enumerate Live machines 
      Get-NetComputer -Ping
      ```
    - **Enum Groups and Group Members:**
      ```powershell
      Get-NetGroupMember -GroupName "<GroupName>" -Domain <DomainName>

      #Enumerate the members of a specified group of the domain
      Get-DomainGroup -Identity <GroupName> | Select-Object -ExpandProperty Member

      #Returns all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
      Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
      ```
    - **Enumerate Shares**
      ```powershell
      #Enumerate Domain Shares
      Find-DomainShare

      #Enumerate Domain Shares the current user has access
      Find-DomainShare -CheckShareAccess
      ```
    - **Enum Group Policies:** 
      ```powershell
      Get-NetGPO

      # Shows active Policy on specified machine
      Get-NetGPO -ComputerName <Name of the PC>
      Get-NetGPOGroup

      #Get users that are part of a Machine's local Admin group
      Find-GPOComputerAdmin -ComputerName <ComputerName>
      ```
    - **Enum OUs:** 
      ```powershell
      Get-NetOU -FullData 
      Get-NetGPO -GPOname <The GUID of the GPO>
      ```
    - **Enum ACLs:** 
      ```powershell
      # Returns the ACLs associated with the specified account
      Get-ObjectAcl -SamAccountName <AccountName> -ResolveGUIDs
      Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose

      #Search for interesting ACEs
      Invoke-ACLScanner -ResolveGUIDs

      #Check the ACLs associated with a specified path (e.g smb share)
      Get-PathAcl -Path "\\Path\Of\A\Share"
      ```
    - **Enum Domain Trust:** 
      ```powershell
      Get-NetDomainTrust
      Get-NetDomainTrust -Domain <DomainName>
      ```
    - **Enum Forest Trust:** 
      ```powershell
      Get-NetForestDomain
      Get-NetForestDomain Forest <ForestName>

      #Domains of Forest Enumeration
      Get-NetForestDomain
      Get-NetForestDomain Forest <ForestName>

      #Map the Trust of the Forest
      Get-NetForestTrust
      Get-NetDomainTrust -Forest <ForestName>
      ```
    - **User Hunting:** 
      ```powershell
      #Finds all machines on the current domain where the current user has local admin access
      Find-LocalAdminAccess -Verbose

      #Find local admins on all machines of the domain:
      Invoke-EnumerateLocalAdmin -Verbose

      #Find computers were a Domain Admin OR a specified user has a session
      Invoke-UserHunter
      Invoke-UserHunter -GroupName "RDPUsers"
      Invoke-UserHunter -Stealth

      #Confirming admin access:
      Invoke-UserHunter -CheckAccess
      ``` 
    
    
## use The BloodHound Tool


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





