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
