import threading
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
        rclass=4096,
        rdlen=len(packet) + 4,
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


def send_dns_packet(dns_packet):
    raw_dns_packet = bytes(dns_packet)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        DNS_SERVER = os.getenv('REMOTE_SERVER_IP')
        DNS_PORT = int(os.getenv('LOCAL_SERVER_PORT'))
        sock.sendto(raw_dns_packet, (DNS_SERVER, DNS_PORT))
        print(f"Sent DNS packet to {DNS_SERVER}:{DNS_PORT}")
    except Exception as e:
        print(f"Failed to send DNS packet: {e}")
    finally:
        sock.close()


def receive_dns_responses():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    LOCAL_PORT = int(os.getenv('LOCAL_CLIENT_PORT'))
    sock.bind(('0.0.0.0', LOCAL_PORT))
    try:
        while True:
            data, addr = sock.recvfrom(1500)
            print(f"Received DNS response from {addr}")
            dns_response = DNS(data)
            if DNSRROPT in dns_response:
                opt_record = dns_response[DNSRROPT]
                tcp_packet_data = opt_record.rdata
                print(f"Extracted TCP packet (hex): {tcp_packet_data.hex()}")
                tcp_packet = IP(tcp_packet_data)
                if TCP in tcp_packet:
                    print(f"Extracted TCP Packet: {tcp_packet.src}:{tcp_packet[TCP].sport} -> {tcp_packet.dst}:{tcp_packet[TCP].dport}")
            else:
                print("No EDNS options found in the DNS response")
    except KeyboardInterrupt:
        print("Stopping DNS response listener")
    finally:
        sock.close()


receiver_thread = threading.Thread(target=receive_dns_responses)
receiver_thread.daemon = True
receiver_thread.start()

try:
    while True:
        packet = os.read(tun, 1500)
        packet = wrap_in_dns(packet)
        if packet:
            send_dns_packet(packet)
except KeyboardInterrupt:
    print("Shutting down TUN interface.")
finally:
    os.close(tun)
