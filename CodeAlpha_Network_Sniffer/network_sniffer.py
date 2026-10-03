from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

packet_number = 0


def analyze_packet(packet):
    global packet_number
    packet_number += 1

    print("\n" + "=" * 60)
    print("Packet #", packet_number)
    print("=" * 60)

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        print("Source IP      :", source_ip)
        print("Destination IP :", destination_ip)

        # Identify protocol
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        print("Protocol       :", protocol)

        # Show payload
        if Raw in packet:
            payload = packet[Raw].load
            print("Payload (hex)  :", payload[:50].hex())
        else:
            print("Payload        : No payload")

        print("Packet Length  :", len(packet), "bytes")

    else:
        print("Non-IP packet detected")

    print("=" * 60)


print("=" * 60)
print("       CODEALPHA BASIC NETWORK SNIFFER")
print("=" * 60)
print("Starting packet capture...")
print("Capturing 20 packets...")
print("Generate some traffic using your browser.")
print()

sniff(
    prn=analyze_packet,
    count=20,
    store=False
)

print("\nPacket capture completed.")
