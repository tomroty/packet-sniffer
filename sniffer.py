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
