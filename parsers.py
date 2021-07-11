import socket
from struct import unpack

import helpers


def eth_head(raw):
    """
    ! == network(=big-endian) ordering
    s == char[] (bytes)
    H = unsigned char (2 bytes)
    """

    dest, src, protocol_raw = unpack(
        "! 6s 6s H", raw[:14]
    )  # https://docs.python.org/3/library/struct.html
    dest_mac = helpers.get_mac_addr(dest)
    src_mac = helpers.get_mac_addr(src)
    protocol = socket.htons(protocol_raw)
    data = raw[14:]

    return (dest_mac, src_mac, protocol, data)


def ipv4_head(raw):
    prot_ver_head_len, ttl, protocol, src_raw, dest_raw = unpack(
        "! B 7x B B 2x 4s 4s", raw[:20]
    )

    protocol_version = prot_ver_head_len >> 4
    header_length = (
        prot_ver_head_len & 0xF
    ) * 4  # dikali 4, karena ada "4 baris" dengan 1 "baris" 5 byte
    data = raw[header_length:]
    src = helpers.get_ip(src_raw)
    dest = helpers.get_ip(dest_raw)

    return protocol_version, header_length, ttl, protocol, src, dest, data


def tcp_head(raw):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = unpack(
        "! H H I I H", raw[:14]
    )

    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = helpers.get_tcp_flags(offset_reserved_flags, "urg")
    flag_ack = helpers.get_tcp_flags(offset_reserved_flags, "ack")
    flag_psh = helpers.get_tcp_flags(offset_reserved_flags, "psh")
    flag_rst = helpers.get_tcp_flags(offset_reserved_flags, "rst")
    flag_syn = helpers.get_tcp_flags(offset_reserved_flags, "syn")
    flag_fin = helpers.get_tcp_flags(offset_reserved_flags, "fin")

    data = raw[offset:]
    flags = {
        "urg": flag_urg,
        "ack": flag_ack,
        "psh": flag_psh,
        "rst": flag_rst,
        "syn": flag_syn,
        "fin": flag_fin,
    }

    return src_port, dest_port, sequence, acknowledgement, flags, data


def udp_head(raw):
    return unpack("! H H H", raw[6:])
