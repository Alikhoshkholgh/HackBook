
### list Users:
  ```ps1
  # local users
  get-localuser
  net user
  
  # domain users
  net user /domain
  
  # domain users specific
  net user <username> /domain

  ```

### list Groups:
  ```ps1
  # domain groups
  net group /domain
  
  # domain group specific
  net group <groupname> /domain
  
  # local groups
  get-localgroup
  ```


### check account password policies:
```ps1
# on the domain
  net accounts /domain
# local
  net accounts
# Note: The net commands may not show all information. For example, if a user is a member of more than ten groups, not all of these groups will be shown in the output.
```
