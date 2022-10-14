
# AD module:
  + ## **setup-install**:
    + in **windows servers** its already **installed**, and i recommend that to only use it in DC.
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
    ```
  + **Enumerate Domain Users:** 
    ```powershell
        Get-ADUser -Filter * -Identity <user> -Properties *
        #Get a spesific "string" on a user's attribute
        Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
    ```
  + **Enum Domain Computers:** 
    ```powershell
        Get-ADComputer -Filter * -Properties *
        Get-ADGroup -Filter * 
    ```
    
