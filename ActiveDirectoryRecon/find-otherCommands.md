
- **Find Domain Controllers**
  ```ps1
  nslookup domain.com
  nslookup -type=srv _ldap._tcp.dc._msdcs.<domain>.com
  nltest /dclist:domain.com
  gpresult /r
  $Env:LOGONSERVER 
  echo %LOGONSERVER%
  ```

- **Know About Services**
```ps1
Get-CimInstance -ClassName Win32_Service | Where-Object {$_.StartName -like 'svcIIS*'} | Select-Object *
```
