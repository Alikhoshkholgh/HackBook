# Enumerate security Tools that implemented on the target

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
  wmic product get name,version  
  ```

- **services**
  ```ps1
  # list running services
  net start
  
  #We can see a service with the name <Service-name> which we want to know more about
  wmic service where "name like 'Service-name'" get Name,PathName
  
  # We find the file name and its path; now let's find more details using the Get-Process cmdlet
  Get-Process -Name Exe-demo
  ```
  
