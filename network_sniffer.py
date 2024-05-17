from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        else:
            src_port = 'N/A'
            dst_port = 'N/A'
            protocol = 'N/A'
        
        print(f"Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip},Destination port {dst_port}  ,  Protocol: {protocol}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=0)


interface = 'Wi-Fi'  # Change this to your network interface
start_sniffing(interface)

