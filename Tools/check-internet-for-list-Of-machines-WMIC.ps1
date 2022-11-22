#obviously you should see the Port:135 on the target machine
$addressList = "hostname1","hostname2","hostname3",
$delay_perReq = 1
#if target machines are able to see my shares
$storageHostname = $env:computername

foreach($ip in $addressList){    
wmic.exe /node:$ip process call create "powershell.exe -ep bypass -c (test-netconnection google.com).pingsucceeded >> \\$storageHostname\C$\Users\Public\Documents\$ip-checkInternet.txt"
Start-Sleep -Seconds $delay_perReq
}


