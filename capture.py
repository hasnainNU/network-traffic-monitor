from scapy.all import sniff, AsyncSniffer, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, ARP
from datetime import datetime
from time import sleep
import db

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
    # ARP packets have no IP layer, so without this their IPs are saved as None
    elif pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    size = len(pkt)
    protocol = identify_protocol(pkt)
    # include the date, because the database keeps packets from many days
    time = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")

    print(time, protocol, "|", src_ip, ":", src_port, "->", dst_ip, ":", dst_port, "| size:", size)

    # save the packet last, after every value has been calculated
    db.insert_packet((time, src_mac, dst_mac, src_ip, dst_ip,
                      src_port, dst_port, protocol, size))


# ---------- Start / Stop control (used by the dashboard buttons in app.py) ----------
sniffer = None

def is_running():
    return sniffer is not None and sniffer.running

def start_capture(iface=None):
    """Start capturing in the background. Returns False if it is already running."""
    global sniffer
    if is_running():
        return False
    db.init_db()
    sniffer = AsyncSniffer(iface=iface or None, prn=handle_packet, store=False)
    sniffer.start()
    sleep(0.5)  # give it a moment to fail if the interface or permission is wrong
    error = getattr(sniffer, "exception", None)
    if error is not None or not sniffer.running:
        sniffer = None
        raise RuntimeError(str(error) if error else "Could not start capture")
    return True

def stop_capture():
    global sniffer
    if sniffer is not None and sniffer.running:
        sniffer.stop()
    sniffer = None


# Running this file directly still works the old way (captures 30 packets)
if __name__ == "__main__":
    db.init_db()
    print("Capturing 30 packets...")
    sniff(prn=handle_packet, count=30)