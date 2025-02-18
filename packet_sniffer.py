from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")

        if packet.haslayer(TCP):
            print(f"TCP Packet: {packet[TCP].summary()}")
        elif packet.haslayer(UDP):
            print(f"UDP Packet: {packet[UDP].summary()}")
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")

def start_sniffer():
    print("Starting the packet sniffer...")
    sniff(prn=packet_handler, store=0, filter="ip", count=0)

if __name__ == "__main__":
    print("This tool should only be used in an ethical manner, with permission to capture network traffic.")
    start_sniffer()
