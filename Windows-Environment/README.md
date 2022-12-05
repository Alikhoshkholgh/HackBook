# Handy Commands in Windows (In Progress...):

  ## change file permissions Or change ACL:
    ```ps1
    $ACL = Get-ACL -Path "<file-path>"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("<Username>","Read|write|full","Allow")
    $ACL.RemoveAccessRule($AccessRule)
    $ACL | Set-Acl -Path "<file-path>"
    ```
