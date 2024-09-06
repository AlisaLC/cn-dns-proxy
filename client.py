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
    dns_packet = DNS(
        id=0xAAAA,  # Random transaction ID
        qr=1,  # This is a response
        opcode=0,  # Standard query
        aa=1,  # Authoritative answer
        rd=1,  # Recursion desired
        ra=1,  # Recursion available
        z=0,
        rcode=0,  # No error
        qd=DNSQR(qname="sharif.edu", qtype="A", qclass="IN"),  # A simple DNS query
        an=DNSRR(rrname="sharif.edu", rdata="192.0.2.1"),  # DNS Answer
    )
    
    opt_record = DNSRROPT(
        rrname='.',
        rclass=4096,  # Requestor's UDP payload size (e.g., 4096 bytes)
        extrcode=0,
        ttl=0,
        options=[('Unknown-OPT', packet)]  # Unknown OPT record with TCP packet as RData
    )

    # Add the OPT record to the DNS packet
    dns_packet.ar = opt_record

    return dns_packet
    
try:
    while True:
        packet = os.read(tun, 1500)
        print(f'Received packet: {packet}')
        packet = wrap_in_dns(packet)
        if packet:
            print(packet.show(dump=True))
except KeyboardInterrupt:
    print("Shutting down TUN interface.")
finally:
    os.close(tun)
