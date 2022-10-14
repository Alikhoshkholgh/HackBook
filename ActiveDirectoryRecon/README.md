# AD module:

  + **## setup-install**:
    + in **windows servers** its already **installed**, and i recommend that to only use it in DC.
    + to enable active directory module on windows10:
      + Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell
    + to install active directory module on windows10:
      + Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”


  + **## Usage**:
    + Get Current Domain: 
      + Get-ADDomain
