# Other Interesting Commands

- **Find Domain Controllers**
  ```ps1
  nslookup domain.com
  nslookup -type=srv _ldap._tcp.dc._msdcs.<domain>.com
  nltest /dclist:domain.com
  gpresult /r
  $Env:LOGONSERVER 
  echo %LOGONSERVER%
  ```

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
    
- **check firewall status**
  ```ps1
  Get-NetFirewallProfile | Format-Table Name, Enabled
    
  # set firewall disable
  Get-NetFirewallProfile | Format-Table Name, Enabled
  
  #  check the current Firewall rules
  Get-NetFirewallRule | select DisplayName, Enabled, Description
  ```
    
