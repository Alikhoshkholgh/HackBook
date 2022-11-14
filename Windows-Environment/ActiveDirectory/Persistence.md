
# Credentials:
### The goal then is to persist with near-privileged credentials.
  - **Credentials that have local administrator rights on several machines**
  - **Service accounts that have delegation permissions**
  - **Accounts used for privileged AD services**

### there are many ways to dump credentials or hijack sessions.
for example:

## DCSync:
```
  - mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all
```

# Tickets:
  - **Golden Tickets**
  - **Silver Tickets**
