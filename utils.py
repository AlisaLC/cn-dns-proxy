import fcntl
from scapy.all import *
import logging
import os
import struct
import subprocess

logging.basicConfig(level=logging.INFO)


def wrap_in_dns(packet):
    logging.info("Wrapping packet into DNS")
    
    try:
        ip_layer = IP(packet)
        if ip_layer.proto != 6:
            logging.info("Non-TCP packet received, ignoring.")
            return

        tcp = ip_layer[TCP]
        if 'S' in tcp.flags:
            logging.info("TCP SYN packet detected, modifying MSS if present.")
            # Modify MSS option in TCP SYN packets
            tcp.options = [(key, value if key != 'MSS' else min(value, 1300))
                           for key, value in tcp.options]
            del tcp.chksum
            tcp.chksum
            del ip_layer.chksum
            ip_layer.chksum

        packet = bytes(ip_layer)
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
        logging.info("DNS packet successfully created.")
        return dns_packet
    except Exception as e:
        logging.error(f"Error while wrapping DNS packet: {e}", exc_info=True)
        return None


def extract_from_dns(packet):
    logging.info("Extracting TCP packet from DNS response.")
    
    try:
        dns_response = DNS(packet)
        tcp_packet = b""
        for ar in dns_response.ar:
            if not isinstance(ar, DNSRROPT):
                logging.debug("Ignoring non-EDNS record in additional section.")
                continue
            for option in ar.rdata:
                if not isinstance(option, EDNS0TLV) or option.optcode != 65001:
                    logging.debug("Ignoring non-TLV or non-matching optcode.")
                    continue
                tcp_packet = option.optdata
                logging.info("TCP packet successfully extracted from DNS.")
        return tcp_packet
    except Exception as e:
        logging.error(f"Error while extracting TCP packet from DNS: {e}", exc_info=True)
        return None


def init_tun():
    logging.info("Initializing TUN interface.")
    
    try:
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000

        tun = os.open('/dev/net/tun', os.O_RDWR)
        logging.info("TUN device opened.")

        TUN_NAME = os.getenv('TUN_NAME')
        if not TUN_NAME:
            raise ValueError("TUN_NAME environment variable is not set.")

        ifr = struct.pack('16sH', TUN_NAME.encode('utf-8'), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(tun, TUNSETIFF, ifr)
        logging.info(f"TUN interface {TUN_NAME} configured.")

        subprocess.run(['ip', 'addr', 'add', os.getenv('SUBNET'), 'dev', TUN_NAME])
        subprocess.run(['ip', 'link', 'set', 'dev', TUN_NAME, 'up'])
        logging.info(f"TUN interface {TUN_NAME} is up and running with subnet {os.getenv('SUBNET')}.")

        return tun
    except Exception as e:
        logging.error(f"Error while initializing TUN interface: {e}", exc_info=True)
        return None
