import os
import fcntl
import struct
import subprocess
from scapy.all import *
from dotenv import load_dotenv
load_dotenv()

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

tun = os.open('/dev/net/tun', os.O_RDWR)

TUN_NAME = os.getenv('TUN_NAME')

ifr = struct.pack('16sH', TUN_NAME.encode('utf-8'), IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

subprocess.run(['ip', 'addr', 'add', os.getenv('SUBNET'), 'dev', TUN_NAME])
subprocess.run(['ip', 'link', 'set', 'dev', TUN_NAME, 'up'])

print(f"TUN interface '{TUN_NAME}' is up and running.")

def parse_packet(packet):
    eth = Ether(packet)
    if eth.haslayer(IP):
        ip_layer = eth[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}, Protocol: {ip_layer.proto}")
        
        if ip_layer.proto == 6:
            tcp_layer = eth[TCP]
            print(f"TCP Packet: Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        elif ip_layer.proto == 17:
            udp_layer = eth[UDP]
            print(f"UDP Packet: Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
    else:
        print("Non-IP Packet or Unsupported Layer")

try:
    while True:
        packet = os.read(tun, 1500)
        print(f'Received packet: {packet}')
except KeyboardInterrupt:
    print("Shutting down TUN interface.")
finally:
    os.close(tun)
