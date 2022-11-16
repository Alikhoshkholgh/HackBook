# Find Clear-Text Files:
- **Powershell History**:
```
Path: C:\<UserName>\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
- **Registry: find password keyword**:
```
c:\Users\user> reg query HKLM /f password /t REG_SZ /s
C:\Users\user> reg query HKCU /f password /t REG_SZ /s
```
