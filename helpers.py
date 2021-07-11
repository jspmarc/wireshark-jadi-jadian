from struct import unpack

def get_mac_addr(raw_mac):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % unpack("BBBBBB", raw_mac)