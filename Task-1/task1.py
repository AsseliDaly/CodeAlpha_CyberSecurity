from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = None
        payload = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            payload = bytes(packet[UDP].payload)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            protocol = "Other"
            payload = b""

        print("="*60)
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {protocol}")
        print(f"Payload        : {payload[:50]}...")  # Limit for readability

def start_sniffer():
    print("[*] Starting Packet Sniffer... (Press Ctrl+C to stop)")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    try:
        start_sniffer()
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
 