import threading
import os
import socket
from dotenv import load_dotenv

from utils import extract_from_dns, init_tun, wrap_in_dns
load_dotenv()

REMOTE_IP = os.getenv('REMOTE_SERVER_IP')
REMOTE_PORT = int(os.getenv('REMOTE_SERVER_PORT'))

tun = init_tun()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_dns_packet(dns_packet):
    raw_dns_packet = bytes(dns_packet)
    try:
        sock.sendto(raw_dns_packet, (REMOTE_IP, REMOTE_PORT))
    except Exception as e:
        print(f"Failed to send DNS packet: {e}")


def receive_dns_responses():
    try:
        while True:
            data, addr = sock.recvfrom(1500)
            print(f"Received DNS response from {addr}")
            tcp_packet_data = extract_from_dns(data)
            if tcp_packet_data:
                os.write(tun, bytes(tcp_packet_data))
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
dns_receiver_thread.start()
tun_receiver_thread.start()
