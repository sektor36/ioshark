# ioshark
iOshark is a powerful network analysis tool written in Python that enables packet sniffing, ARP spoofing, and DNS tunneling. It utilizes Scapy to capture and manipulate network packets for various network-based attacks and analysis.

iOshark: Network Sniffer & Exploitation Tool

iOshark is a powerful network analysis tool written in Python that enables packet sniffing, ARP spoofing, and DNS tunneling. It utilizes Scapy to capture and manipulate network packets for various network-based attacks and analysis.

Whether you're a cybersecurity enthusiast, network administrator, or a penetration tester, iOshark allows you to intercept network traffic, spoof ARP requests, and conduct DNS tunneling attacks with ease.
⚙️ Features

    Packet Sniffing: Capture and analyze network packets on any given interface (e.g., wlan0).

    ARP Spoofing: Perform ARP poisoning to redirect network traffic between devices.

    DNS Tunneling: Establish communication through DNS queries and responses.

    Wireshark Capture File Analysis: Read and analyze .pcap files captured by Wireshark.

    Cross-platform Support: Works on Linux, macOS, and potentially Windows (with some modifications).

📦 Installation

To use iOshark, you'll need Python 3.x and some dependencies. Follow these steps to get started:
1. Install Dependencies

First, install Scapy, the main dependency for packet manipulation:

pip install scapy

2. Clone the Repository

Clone the repository to your local machine:

git clone https://github.com/yourusername/ioshark.git
cd ioshark

🛠️ Usage

After installing, you can use iOshark to sniff network traffic, perform ARP spoofing, or analyze .pcap files.
📡 Sniffing Network Traffic

To start sniffing traffic on a specific network interface (e.g., wlan0):

python3 ioshark.py -i wlan0 --sniff

💻 ARP Spoofing

To perform ARP spoofing (Poisoning) between a target and a gateway:

python3 ioshark.py --arp <TARGET_IP> <GATEWAY_IP> -i <INTERFACE>

Example:

python3 ioshark.py --arp 192.168.1.5 192.168.1.1 -i wlan0

🌐 DNS Tunneling

To start DNS tunneling on a specific interface:

python3 ioshark.py --dns -i wlan0

📂 Analyzing .pcap Files

To analyze a .pcap file (captured using Wireshark or any other tool):

python3 ioshark.py -w capture_file.pcap

🔧 Command-Line Arguments
Argument	Description
-i, --interface	Network interface to use (e.g., wlan0, eth0)
-w, --pcap	Analyze a Wireshark .pcap file for packet details
--sniff	Sniff network traffic in real-time
--arp	Perform ARP spoofing (Target IP and Gateway IP required)
--dns	Start DNS tunneling
📝 Example Use Cases
1. Sniffing Network Traffic

To capture and analyze network packets on the wlan0 interface:

python3 ioshark.py -i wlan0 --sniff

2. ARP Spoofing Attack

To poison the ARP cache and redirect traffic between a target (e.g., 192.168.1.5) and the gateway (e.g., 192.168.1.1):

python3 ioshark.py --arp 192.168.1.5 192.168.1.1 -i wlan0

3. DNS Tunneling

To start DNS tunneling to communicate via DNS requests:

python3 ioshark.py --dns -i wlan0

4. Analyzing a .pcap File

To analyze the packets in a .pcap file (e.g., capture.pcap):

python3 ioshark.py -w capture.pcap

📑 License

This project is licensed under the MIT License – see the LICENSE file for details.
⚠️ Disclaimer

This tool is intended for educational purposes and responsible use only. Ensure that you have proper authorization to perform network sniffing, ARP spoofing, or DNS tunneling on any network. Unauthorized use may be illegal and could result in penalties.
