import struct
import sys
import socket

def init_sock ():
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Error: Packet operations require root/sudo privileges")
        sys.exit(1)
    print('Listening for raw packets...')
    return raw_sock

def format_mac (addr):
    """Converts a raw 6-byte string into an AA:BB:CC:DD:EE:FF format."""
    # map() applies the hex formatting to every byte in the string
    mac_str = map('{:02x}'.format, addr)
    return ':'.join(mac_str).upper()

def generate_ip_log_message (packet):
    return (
        f"{packet['source_ip']} -> "
        f"{packet['dest_ip']} "
        f"[{packet['transport_type']}] "
    )

def get_eth_log_message (eth_frame):
    return (
        f"{eth_frame['src_mac']} -> "
        f"{eth_frame['dest_mac']} "
        f"[{eth_frame['packet_type']}] "
    )

def generate_tcp_log_message (segment):
    flags = [flag for flag in segment['flags'] \
        if segment['flags'][flag] is True]

    return (
        f"{segment['src_port']} -> "
        f"{segment['dest_port']} "
        f"{len(segment['payload_bytes'])}B ["
        f"{', '.join(flags)}]"
    )

def generate_udp_log_message (segment):
    return (
        f"{segment['source_port']} -> "
        f"{segment['dest_port']} "
        f"{len(segment['payload_bytes'])}B"
    )

def generate_icmp_log_message (packet):
    type = ''
    match packet['type']:
        case 8 | 128:
            type = 'Echo Request/Ping'
        case 0 | 129: 
            type = 'Echo Reply'

    return (
        f"{type}:{packet['seq']} " 
    )

def get_eth_frame (sock):
    eth_frame, addr = sock.recvfrom(65535)
    eth_hdr = eth_frame[:14]
    # binary data
    dest_addr_b, src_addr_b, eth_type = struct.unpack('! 6s 6s H', eth_hdr)
    # convert to string
    match eth_type:
        case 0x0800:
            eth_type_str = 'IPv4'
        case 0x0806:
            eth_type_str = 'ARP'
        case 0x86DD:
            eth_type_str = 'IPv6'
        case 0x8100:
            eth_type_str = 'VLAN'
        case _:
            eth_type_str = 'Unknown'
    return {
        'packet_type': eth_type_str,
        'dest_mac': format_mac(dest_addr_b),
        'src_mac': format_mac(src_addr_b),
        'payload_bytes': eth_frame
    }

def get_ipv4_packet (eth_frame):
    # extract the entire packet 
    packet = {}
    payload = eth_frame['payload_bytes'][14:]
    hdr = payload[:20]
    unpacked_hdr = struct.unpack('! B B H 2s 2s B B 2s 4s 4s', hdr)
    packet['header_length'] = (unpacked_hdr[0] & 0x0F) * 4
    # Is this required?
    packet['packet_length'] = unpacked_hdr[2]
    match (unpacked_hdr[6]):
        case 6:
            packet['transport_type'] = 'TCP'
        case 17:
            packet['transport_type'] = 'UDP'
        case 1: 
            packet['transport_type'] = 'ICMP'
        case _:
            packet['transport_type'] = 'Unknown'
     
    packet['source_ip'] = socket.inet_ntoa(unpacked_hdr[8])    
    packet['dest_ip'] = socket.inet_ntoa(unpacked_hdr[9]) 
    packet['payload_bytes'] = payload[packet['header_length']:]
    # return the unpacked packet dict
    return packet

def get_ipv6_packet (eth_frame):
    packet = {}
    payload = eth_frame['payload_bytes'][14:]
    # Size of the IPv6 header is fixed (40 bytes)
    packet['header_length'] = 40
    hdr = payload[:packet['header_length']]
    unpacked_hdr = struct.unpack('! I H B B 16s 16s', hdr)
    payload_length = unpacked_hdr[1]
    # Is the index correct?
    match (unpacked_hdr[2]):
        case 6:
            packet['transport_type'] = 'TCP'
        case 17:
            packet['transport_type'] = 'UDP'
        case 1: 
            packet['transport_type'] = 'ICMP'
        case 58:
            packet['transport_type'] = 'ICMP'
        case _:
            packet['transport_type'] = 'Unknown'

    packet['source_ip'] = \
    socket.inet_ntop(socket.AF_INET6, unpacked_hdr[4])    

    packet['dest_ip'] = \
    socket.inet_ntop(socket.AF_INET6, unpacked_hdr[5])    
    packet['payload_bytes'] = payload[40:]
    return packet

def get_tcp_segment (ip_packet):
    segment = {}
    hdr = ip_packet['payload_bytes'][:20]
    unpacked_hdr = struct.unpack('! H H I I H H H H', hdr)
    segment['src_port'] = unpacked_hdr[0]
    segment['dest_port'] = unpacked_hdr[1]
    segment['header_length'] = (unpacked_hdr[4] >> 12) * 4
    segment['payload_bytes'] = ip_packet['payload_bytes'][segment['header_length']:]
    flag_masks = {
        'FIN': 0x01,
        'SYN': 0x02,
        'RST': 0x04,
        'PSH': 0x08,
        'ACK': 0x10,
        'URG': 0x20
    }
    flags = unpacked_hdr[4] & 0x0fff
    segment['flags'] = {}
    
    for flag_name, mask in flag_masks.items():
        segment['flags'][flag_name] = bool(flags & mask)
    return segment
    
def get_udp_segment (ip_packet):
    segment = {}
    hdr = ip_packet['payload_bytes'][:8]
    unpacked_hdr = struct.unpack('!HHHH', hdr)
    segment['source_port'] = unpacked_hdr[0]
    segment['dest_port'] = unpacked_hdr[1]
    segment['length'] = unpacked_hdr[2]
    segment['payload_bytes'] = ip_packet['payload_bytes'][8:segment['length']] 
    return segment

def get_icmp_packet (ip_packet):
    hdr = ip_packet['payload_bytes'][:8] 
    unpacked_hdr = struct.unpack('!BBHHH', hdr)
    return {
        'type': unpacked_hdr[0],
        'code': unpacked_hdr[1],
        'checksum': unpacked_hdr[2],
        'id': unpacked_hdr[3],
        'seq': unpacked_hdr[4],
        'payload_bytes': ip_packet['payload_bytes'][8:]
    }

def sniffer ():
    raw_sock = init_sock()
    while True:
        eth_frame = get_eth_frame(raw_sock)
        ip_packet = {}
        match eth_frame['packet_type']:
            case 'IPv4':
                ip_packet = get_ipv4_packet(eth_frame)

            case 'IPv6':
                ip_packet = get_ipv6_packet(eth_frame)
            case _:
                continue

        eth_log = get_eth_log_message (eth_frame)
        ip_log = generate_ip_log_message(ip_packet)

        match ip_packet['transport_type']:
            case 'TCP':
                tcp_segment = get_tcp_segment(ip_packet)
                tcp_log = generate_tcp_log_message(tcp_segment)
                log = eth_log + ip_log + tcp_log 
                print(log)
            case 'UDP':
                udp_segment = get_udp_segment(ip_packet)
                udp_log = generate_udp_log_message(udp_segment)
                log = eth_log + ip_log + udp_log 
                print(log)
            case 'ICMP':
                icmp_packet = get_icmp_packet(ip_packet) 
                icmp_log = generate_icmp_log_message(icmp_packet)
                log = eth_log + ip_log + icmp_log 
                print(log)
            case _:
                continue

if __name__ == '__main__':
    sniffer() 
