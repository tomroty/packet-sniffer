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

if __name__ == '__main__':
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Sniffer started")
    while True:
        raw_data, addr = connection.recvfrom(65535)
        dest, src, protocol_type, data = unpack_ethernet_frame(raw_data)
        print("Ethernet Frame:")
        print("Destination: {}, Source: {}, Protocol: {}\n".format(dest, src, protocol_type))
