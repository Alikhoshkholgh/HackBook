$addressList = "192.168.11.1", "192.168.11.2", "192.168.11.3", "192.168.11.4"
$portList = 3389,135,445 
$hostname = $env:computername
$delay_perReq = 10

write-output "scanning initiated by $hostname"


foreach($ip in $addressList){
    
    foreach($port in $portList){

        $conn_res=(test-netconnection -computername $ip -port $port -warningAction silentlycontinue)
        $comName = $conn_res.tcptestsucceeded        
        
        if($comName){           write-output "($ip):($port)   is available for $hostname"            }
        else{                   write-output "($ip):($port)   is not-available for $hostname"            }
        start-sleep -Seconds $delay_perReq
    }    
}



#$requestCallback = $state = $null
#$client = New-Object System.Net.Sockets.TcpClient
#$beginConnect = $client.BeginConnect($hostname,$port,$requestCallback,$state)
#Start-Sleep -milli $timeOut
#if ($client.Connected) { $open = $true } else { $open = $false }
#$client.Close()
