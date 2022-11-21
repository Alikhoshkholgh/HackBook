$hostname = $env:computername
$addressList = "IP1", "IP2", "IP3", "myMachineName1", "myMachineName2", "myMachineName3"
$portList = 135,445
$delay_perReq = 1
$storeFile = "\\localhost\C$\Users\Public\Documents\$hostname.txt"

$result = "scanning initiated by $hostname`n"

foreach($ip in $addressList){    
    foreach($port in $portList){           
        $requestCallback = $state = $null
        $client = New-Object System.Net.Sockets.TcpClient
        $beginConnect = $client.BeginConnect($ip,$port,$requestCallback,$state)
        Start-Sleep -seconds 1
        if ($client.Connected) { $open = $true } else { $open = $false }
        $client.Close()
        
        if($open){           $result += "($ip):($port)   is available for $hostname`n"            }
        else{                $result += "($ip):($port)   is not-available for $hostname`n"            }
        start-sleep -Seconds $delay_perReq
    }
}

Write-Output $result > $storeFile
