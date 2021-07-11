import socket
from struct import unpack


def get_mac_addr(raw_mac):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("BBBBBB", raw_mac)


def get_ip(raw_ip):
    return ".".join(map(str, raw_ip))


def get_tcp_flags(raw, flag):
    flag_id = {
        "fin": 0,
        "syn": 1,
        "rst": 2,
        "psh": 3,
        "ack": 4,
        "urg": 5,
    }

    used_id = flag_id[flag]

    if used_id != 0:
        return (raw & (int("1" * used_id, 2) + 1)) >> used_id
    else:
        return raw & 1


def ifnames_to_array():
    if_devices = socket.if_nameindex()
    res = [""]
    for if_device in if_devices:
        res.append(if_device[1])
    return res
