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
REMOTE_IP = os.getenv('REMOTE_SERVER_IP')
REMOTE_PORT = int(os.getenv('LOCAL_SERVER_PORT'))
LOCAL_PORT = int(os.getenv('LOCAL_CLIENT_PORT'))

ifr = struct.pack('16sH', TUN_NAME.encode('utf-8'), IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

subprocess.run(['ip', 'addr', 'add', os.getenv('SUBNET'), 'dev', TUN_NAME])
subprocess.run(['ip', 'link', 'set', 'dev', TUN_NAME, 'up'])

print(f"TUN interface '{TUN_NAME}' is up and running.")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', LOCAL_PORT))
print(f"Socket binded to {LOCAL_PORT}")


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
    try:
        sock.sendto(raw_dns_packet, (REMOTE_IP, REMOTE_PORT))
        print(f"Sent DNS packet to {REMOTE_IP}:{REMOTE_PORT}")
    except Exception as e:
        print(f"Failed to send DNS packet: {e}")


def receive_dns_responses():
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
                    os.write(tun, tcp_packet_data)
                    print(f"TCP packet written to TUN interface")
            else:
                print("No EDNS options found in the DNS response")
    except KeyboardInterrupt:
        print("Stopping DNS response listener")

def recieve_tun_requests():
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


dns_receiver_thread = threading.Thread(target=receive_dns_responses)
tun_receiver_thread = threading.Thread(target=recieve_tun_requests)
dns_receiver_thread.daemon = True
tun_receiver_thread.daemon = True
dns_receiver_thread.start()
tun_receiver_thread.start()