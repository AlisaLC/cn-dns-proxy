import fcntl
from scapy.all import *


def wrap_in_dns(packet):
    ip_layer = IP(packet)
    if ip_layer.proto != 6:
        return
    tcp = ip_layer[TCP]
    if 'S' in tcp.flags:
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
    return dns_packet


def extract_from_dns(packet):
    dns_response = DNS(data)
    tcp_packet = b""
    for ar in dns_response.ar:
        if not isinstance(ar, DNSRROPT):
            continue
        for option in ar.rdata:
            if not isinstance(option, EDNS0TLV) or option.optcode != 65001:
                continue
            tcp_packet = option.optdata
    return tcp_packet


def init_tun():
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    tun = os.open('/dev/net/tun', os.O_RDWR)

    TUN_NAME = os.getenv('TUN_NAME')

    ifr = struct.pack('16sH', TUN_NAME.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)

    subprocess.run(['ip', 'addr', 'add', os.getenv('SUBNET'), 'dev', TUN_NAME])
    subprocess.run(['ip', 'link', 'set', 'dev', TUN_NAME, 'up'])

    return tun
