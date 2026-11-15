from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, ARP
from datetime import datetime

def identify_protocol(pkt):
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(TCP):
        ports = (pkt[TCP].sport, pkt[TCP].dport)
        if 443 in ports:
            return "HTTPS"
        if 80 in ports or 8080 in ports:
            return "HTTP"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"

def handle_packet(pkt):
    src_mac = dst_mac = src_ip = dst_ip = None
    src_port = dst_port = None

    if pkt.haslayer(Ether):
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    size = len(pkt)
    protocol = identify_protocol(pkt)
    time = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S")

    print(time, protocol, "|", src_ip, ":", src_port, "->", dst_ip, ":", dst_port, "| size:", size)

print("Capturing 10 packets...")
sniff(prn=handle_packet, count=30)