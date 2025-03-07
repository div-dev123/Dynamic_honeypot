from scapy.all import sniff, IP, TCP, UDP
import logging
from collections import defaultdict
import time
from honeypot_engine import honeypot_engine

# Configure logging for network traffic
traffic_logger = logging.getLogger('network_traffic')
traffic_logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('network_traffic.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
traffic_logger.addHandler(fh)

# Data structures to store traffic data
traffic_data = defaultdict(int)
scan_data = defaultdict(set)  # Use a set to track unique ports scanned by each IP

# Thresholds for detecting suspicious activity
PORT_SCAN_THRESHOLD = 100  # Lowering the threshold for testing purposes
DOS_THRESHOLD = 1000

def detect_port_scan(packet):
    """ Detects port scanning by tracking the number of different ports accessed by a single IP. """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
        else:
            return

        scan_data[ip_src].add(port)
        traffic_logger.debug(f"Port scan data for IP {ip_src}: {scan_data[ip_src]}")
        if len(scan_data[ip_src]) > PORT_SCAN_THRESHOLD:
            traffic_logger.warning(f"Port scan detected from IP: {ip_src}")
            # Activate honeypot services based on detected port scans
        if 443 in scan_data[ip_src]:
            honeypot_engine.activate_service('HTTP')
        if 443 in scan_data[ip_src]:
            honeypot_engine.activate_service('SSH')
        if 443 in scan_data[ip_src]:
            honeypot_engine.activate_service('MySQL')
        if 443 in scan_data[ip_src]:
            honeypot_engine.activate_service('FTP')
        if 443 in scan_data[ip_src]:
            honeypot_engine.activate_service('Telnet')
        if 443 in scan_data[ip_src]:
            honeypot_engine.activate_service('SMTP')

def detect_dos(packet):
    """ Detects DoS attacks by tracking the number of packets from a single IP in a short time span. """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        traffic_data[ip_src] += 1
        if traffic_data[ip_src] > DOS_THRESHOLD:
            traffic_logger.warning(f"Potential DoS attack detected from IP: {ip_src}")

def process_packet(packet):
    """ Process each packet to extract details and detect anomalies. """
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        traffic_logger.info(f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")
        
        # Detect suspicious activity
        detect_port_scan(packet)
        detect_dos(packet)

def main():
    print("Starting network sniffer...")
    sniff(prn=process_packet, store=0)

if __name__ == '__main__':
    main()