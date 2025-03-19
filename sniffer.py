import socket
import struct
import textwrap

def unpack_ethernet_frame(data):
    """
    Unpacks the Ethernet frame
    
    Args: 
        data: bytes
            The raw data
            
    Returns:
        dest: str
            The destination MAC address
        src: str
            The source MAC address
        protocol_type: int
            The protocol type
        data: bytes
            The data
    """
    dest, src, protocol_type = struct.unpack("! 6s 6s H", data[:14]) # 6 bits + 6 bits + 2 bits
    return get_mac_addr(dest), get_mac_addr(src), socket.htons(protocol_type), data[14:]

def get_mac_addr(bytes_addr):
    """
    Converts the MAC address to a readable format
    
    Args:
        bytes_addr: bytes
            The MAC address
            
    Returns:
        str
            The MAC address in format AA:BB:CC:DD:EE:FF
    """
    return ":".join(map("{:02x}".format, bytes_addr))


def unpack_ipv4_packet(data):
    """
    Unpacks the IPv4 packet
    
    Args:
        data: bytes
            The raw data
            
    Returns:
        version: int
            The version of the IP
        header_length: int
            The header length
        ttl: int
            The time to live
        protocol: int
            The protocol
        src: str
            The source IP address
        dest: str
            The destination IP address
        data: bytes
            The data
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, dest = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, protocol, get_ipv4_addr(src), get_ipv4_addr(dest), data[header_length:]

def get_ipv4_addr(bytes_addr):
    """
    Converts the IP address to a readable format
    
    Args:
        bytes_addr: bytes
            The IP address
            
    Returns:
        str
            The IP address in format x.x.x.x
    """
    return ".".join(map(str, bytes_addr))

def unpack_icmp_packet(data):
    """
    Unpacks the ICMP packet
    
    Args:
        data: bytes
            The raw data
            
    Returns:
        icmp_type: int
            The ICMP type
        code: int
            The code
        checksum: int
            The checksum
        data: bytes
            The data
    """
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

def unpack_tcp_segment(data):
    """
    Unpacks the TCP segment
    
    Args:
        data: bytes
            The raw data
            
    Returns:
        src_port: int
            The source port
        dest_port: int
            The destination port
        sequence: int
            The sequence number
        data: bytes
            The data
    """
    src_port, dest_port, sequence = struct.unpack("! H H L", data[:8])
    return src_port, dest_port, sequence, data[8:]

def unpack_udp_segment(data):
    """
    Unpacks the UDP segment
    
    Args:
        data: bytes
            The raw data
            
    Returns:
        src_port: int
            The source port
        dest_port: int
            The destination port
        length: int
            The length
        data: bytes
            The data
    """
    src_port, dest_port, length = struct.unpack("! H H H", data[:6])
    return src_port, dest_port, length, data[6:]

def unpack_arp_packet(data):
    """
    Unpacks the ARP packet
    
    Args:
        data: bytes
            The raw data
            
    Returns:
        hardware_type: int
            The hardware type
        protocol_type: int
            The protocol type
        hardware_length: int
            The hardware length
        protocol_length: int
            The protocol length
        operation: int
            The operation
        src_mac: str
            The source MAC address
        src_ip: str
            The source IP address
        dest_mac: str
            The destination MAC address
        dest_ip: str
            The destination IP address
    """
    hardware_type, protocol_type, hardware_length, protocol_length, operation = struct.unpack("! H H B B H", data[:8])
    return hardware_type, protocol_type, hardware_length, protocol_length, operation, get_mac_addr(data[8:14]), get_ipv4_addr(data[14:18]), get_mac_addr(data[18:24]), get_ipv4_addr(data[24:28])


if __name__ == '__main__':
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Sniffer started")
    while True:
        raw_data, addr = connection.recvfrom(65535)
        dest, src, protocol_type, data = unpack_ethernet_frame(raw_data)
        print("Ethernet Frame:")
        print("Destination: {}, Source: {}, Protocol: {}\n".format(dest, src, protocol_type))
        
        if protocol_type == 8:
            version, header_length, ttl, protocol, src, dest, data = unpack_ipv4_packet(data)
            print("IPv4 Packet:")
            print("Version: {}, Header Length: {}, TTL: {}, Protocol: {}, Source: {}, Destination: {}\n".format(version, header_length, ttl, protocol, src, dest))
            print("Data:")
            print(textwrap.indent(data.hex(), "    "))
            
        elif protocol_type == 1:
            icmp_type, code, checksum, data = unpack_icmp_packet(data)
            print("ICMP Packet:")
            print("Type: {}, Code: {}, Checksum: {}\n".format(icmp_type, code, checksum))
            print("Data:")
            print(textwrap.indent(data.hex(), "    "))

        elif protocol_type == 6:
            src_port, dest_port, sequence, data = unpack_tcp_segment(data)
            print("TCP Segment:")
            print("Source Port: {}, Destination Port: {}, Sequence: {}\n".format(src_port, dest_port, sequence))
            print("Data:")
            print(textwrap.indent(data.hex(), "    "))

        elif protocol_type == 17:
            src_port, dest_port, length, data = unpack_udp_segment(data)
            print("UDP Segment:")
            print("Source Port: {}, Destination Port: {}, Length: {}\n".format(src_port, dest_port, length))
            print("Data:")
            print(textwrap.indent(data.hex(), "    "))

        elif protocol_type == 1544:
            hardware_type, protocol_type, hardware_length, protocol_length, operation, src_mac, src_ip, dest_mac, dest_ip = unpack_arp_packet(data)
            print("ARP Packet:")
            print("Hardware Type: {}, Protocol Type: {}, Hardware Length: {}, Protocol Length: {}, Operation: {}, Source MAC: {}, Source IP: {}, Destination MAC: {}, Destination IP: {}\n".format(hardware_type, protocol_type, hardware_length, protocol_length, operation, src_mac, src_ip, dest_mac, dest_ip))
        
        print("\n-------------------------------------------------------------------------------------------------------\n")
