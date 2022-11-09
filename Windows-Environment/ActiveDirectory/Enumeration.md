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
# Note: The net commands may not show all information. For example, if a user is a member of more than ten groups, not all of these groups will be shown in the output.
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
        Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com
    ```
  + **Enum Domain Computers:** 
    ```powershell
        Get-ADComputer -Filter * -Properties *
        Get-ADGroup -Filter * 
    ```
    
