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
    ip_layer = IP(packet)
    if ip_layer.proto != 6:
        return
    tcp_layer = ip_layer[TCP]
    seq_num = tcp_layer.seq
    ack_num = tcp_layer.ack
    payload_size = len(tcp_layer.payload)
    tcp_flags = tcp_layer.flags
    mss_option = [opt[1] for opt in tcp_layer.options if opt[0] == 'MSS']
    mss_value = mss_option[0] if mss_option else 'Not Set'
    print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
    print(f"  Sequence Number: {seq_num}")
    print(f"  Acknowledgment Number: {ack_num}")
    print(f"  Payload Size: {payload_size} bytes")
    print(f"  MSS: {mss_value}")
    print(f"  Flags: {tcp_flags}")
    
try:
    while True:
        packet = os.read(tun, 1500)
        print(f'Received packet: {packet}')
        parse_packet(packet)
except KeyboardInterrupt:
    print("Shutting down TUN interface.")
finally:
    os.close(tun)
