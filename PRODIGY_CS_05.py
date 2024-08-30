from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Extract IP addresses and protocol
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine the protocol name
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = "Other"
        
        # Display relevant packet information
        print(f"Packet: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        
        # Display additional information based on protocol
        if protocol_name == "TCP" and TCP in packet:
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif protocol_name == "UDP" and UDP in packet:
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        
        # Check if the packet has payload data
        if Raw in packet:
            payload_data = packet[Raw].load
            print(f"Payload: {payload_data}")
        
        # Print a separator for readability
        print("-" * 50)

# Start sniffing packets on interface 'eth0'
sniff(iface="Wi-Fi", prn=packet_callback, store=0)
