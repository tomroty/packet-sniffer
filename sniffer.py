import socket
import struct
import textwrap


def unpack_ethernet_frame(data):
    dest_mac, src_mac, protocol_type = struct.unpack("! 6s 6s H", data[:14]) # 6 bits + 6 bits + 2 bits
    return dest_mac, src_mac, protocol_type, data[14:]

