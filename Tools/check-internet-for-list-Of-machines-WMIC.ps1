#obviously you should see the Port:135 on the target machine
$hostname = $env:computername
$addressList = "hostname1","hostname2","hostname3",
$delay_perReq = 1
$storeFile = "\\Hostname\C$\Users\Public\Documents\$hostname-checkInternet.txt"

foreach($ip in $addressList){    
    wmic.exe /node:$ip process call create "powershell.exe -ep bypass -c (test-netconnection google.com).pingsucceeded >> $storeFile"
    Start-Sleep -Seconds $delay_perReq
}


