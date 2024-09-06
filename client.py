import os
import fcntl
import struct
import subprocess

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Open the TUN device file
tun = os.open('/dev/net/tun', os.O_RDWR)

# Configure the TUN interface
ifr = struct.pack('16sH', b'dprox', IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

# Bring up the interface (using subprocess to run ifconfig/ip commands)
subprocess.run(['ip', 'addr', 'add', '172.16.0.2/24', 'dev', 'dprox'])
subprocess.run(['ip', 'link', 'set', 'dev', 'dprox', 'up'])

print("TUN interface 'dprox' is up and running.")

# Reading and writing to the TUN interface
try:
    while True:
        # Reading data from TUN interface
        packet = os.read(tun, 2048)
        print(f'Received packet: {packet}')

        # Writing data to the TUN interface
        response = b'Hello, world!'  # Example packet
        os.write(tun, response)
except KeyboardInterrupt:
    print("Shutting down TUN interface.")
finally:
    os.close(tun)
