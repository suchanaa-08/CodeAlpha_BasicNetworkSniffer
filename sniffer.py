
from scapy.all import (
    sniff, conf, IP, IPv6,
    TCP, UDP, ICMP, ARP, Raw
)
from datetime import datetime
import string


# Select our Samsung USB network adapter
interface = conf.ifaces.dev_from_index(7)


def analyze_packet(packet):

    print("\n" + "=" * 65)
    print("              NETWORK PACKET ANALYSIS")
    print("=" * 65)

    # 1. Timestamp
    timestamp = datetime.fromtimestamp(float(packet.time))
    print("Time:", timestamp.strftime("%H:%M:%S"))

    # 2. Packet size
    print("Packet Size:", len(packet), "bytes")

    # 3. Identify IP addresses and protocol
    source_ip = "-"
    destination_ip = "-"
    protocol = "Other"
    source_port = "-"
    destination_port = "-"

    if packet.haslayer(IP):

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif packet.haslayer(IPv6):

        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    elif packet.haslayer(ARP):

        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst
        protocol = "ARP"

    # 4. Identify transport protocol
    if packet.haslayer(TCP):

        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        print("TCP Flags:", packet[TCP].flags)

    elif packet.haslayer(UDP):

        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif packet.haslayer(ICMP):

        protocol = "ICMP"

    elif any(
    layer.__name__.startswith("ICMPv6")
    for layer in packet.layers()
):

       protocol = "ICMPv6"

    # 5. Display packet information
    print("Protocol:", protocol)
    print("Source IP:", source_ip)
    print("Destination IP:", destination_ip)
    print("Source Port:", source_port)
    print("Destination Port:", destination_port)

    # 6. Extract payload
    if packet.haslayer(Raw):

        payload = bytes(packet[Raw].load)

        print("\nPayload Information:")

        print("Hexadecimal:", payload[:32].hex())

        readable = "".join(
            chr(byte) if chr(byte) in string.printable
            and byte not in (10, 13) else "."
            for byte in payload[:32]
        )

        print("Text Preview:", readable)

    else:

        print("\nNo Raw payload found.")


def start_sniffer():

    print("=" * 65)
    print("             BASIC NETWORK SNIFFER")
    print("=" * 65)

    print("Network Interface: Samsung USB Adapter")
    print("Starting packet capture...")
    print("Capturing 10 packets...")
    print("Press Ctrl + C to stop if needed.\n")

    try:

        sniff(
            iface=interface,
            prn=analyze_packet,
            count=10,
            store=False
        )

        print("\nPacket capture completed!")

    except PermissionError:

        print("Permission denied. Run VS Code as Administrator.")

    except Exception as error:

        print("Error:", error)


if __name__ == "__main__":

    start_sniffer()
