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

def wrap_in_dns(packet):
    ip_layer = IP(packet)
    if ip_layer.proto != 6:
        return
    opt_record = DNSRROPT(
        rclass=4096,  # UDP payload size
        rdlen=len(packet) + 4,  # Length of the option data plus option header
        rdata=[EDNS0TLV(optcode=65001, optlen=len(packet), optdata=packet)]
    )
    dns_packet = DNS(
        id=random.getrandbits(16),
        opcode=0,
        rcode=0,
        qd=DNSQR(qname="sharif.edu", qtype="A", qclass="IN"),
        ar=opt_record,
    )

    return dns_packet
    
try:
    while True:
        packet = os.read(tun, 1500)
        print(f'Received packet: {packet}')
        packet = wrap_in_dns(packet)
        if packet:
            print(packet.summary())
except KeyboardInterrupt:
    print("Shutting down TUN interface.")
finally:
    os.close(tun)
