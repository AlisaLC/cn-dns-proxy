import threading
import os
from scapy.all import *
from dotenv import load_dotenv

from utils import extract_from_dns, init_tun, wrap_in_dns
load_dotenv()

REMOTE_IP = None
REMOTE_PORT = None

tun = init_tun()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', REMOTE_PORT))


def send_dns_packet(dns_packet):
    if REMOTE_IP is None or REMOTE_PORT is None:
        return
    raw_dns_packet = bytes(dns_packet)
    try:
        sock.sendto(raw_dns_packet, (REMOTE_IP, REMOTE_PORT))
    except Exception as e:
        print(f"Failed to send DNS packet: {e}")


def receive_dns_requests():
    try:
        while True:
            data, (REMOTE_IP, REMOTE_PORT) = sock.recvfrom(1500)
            REMOTE_PORT = int(REMOTE_PORT)
            tcp_packet_data = extract_from_dns(data)
            if tcp_packet_data:
                os.write(tun, tcp_packet_data)
    except KeyboardInterrupt:
        print("Stopping DNS response listener")


def recieve_tun_responses():
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


dns_receiver_thread = threading.Thread(target=receive_dns_requests)
tun_receiver_thread = threading.Thread(target=recieve_tun_responses)
dns_receiver_thread.daemon = True
dns_receiver_thread.start()
tun_receiver_thread.start()
