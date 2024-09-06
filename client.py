import os
import fcntl
import struct
import subprocess
from dotenv import load_dotenv
load_dotenv()

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

tun = os.open('/dev/net/tun', os.O_RDWR)

TUN_NAME = os.getenv('TUN_NAME')

ifr = struct.pack('16sH', TUN_NAME, IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

subprocess.run(['ip', 'addr', 'add', os.getenv('SUBNET'), 'dev', TUN_NAME])
subprocess.run(['ip', 'link', 'set', 'dev', TUN_NAME, 'up'])

print(f"TUN interface '{TUN_NAME}' is up and running.")

try:
    while True:
        packet = os.read(tun, 1500)
        print(f'Received packet: {packet}')
except KeyboardInterrupt:
    print("Shutting down TUN interface.")
finally:
    os.close(tun)
