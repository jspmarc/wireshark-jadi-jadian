from struct import unpack

def get_mac_addr(raw_mac):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("BBBBBB", raw_mac)

def get_ip(raw_ip):
    return '.'.join(map(str, raw_ip))

def get_tcp_flags(raw, flag):
    flag_id = {
        'fin': 0,
        'ack': 1,
        'psh': 2,
        'rst': 3,
        'syn': 4,
        'urg': 5,
    }

    used_id = flag_id[flag]

    if used_id != 0:
        return (raw & (int('1' * used_id) + 1)) >> used_id
    else:
        return raw & 1