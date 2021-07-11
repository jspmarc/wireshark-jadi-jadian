import helpers

import socket
from struct import unpack

def parse_ipv4(raw):
    pass

def parse_eth_head(raw):
    dest, src, protocol_raw = unpack("! 6s 6s H", raw[:14]) # https://docs.python.org/3/library/struct.html
    '''
    ! == network(=big-endian) ordering
    s == char[] (bytes)
    H = unsigned char (2 bytes)
    '''

    dest_mac = helpers.get_mac_addr(dest)
    src_mac = helpers.get_mac_addr(src)
    protocol = socket.htons(protocol_raw)
    data = raw[14:]

    return (dest_mac, src_mac, protocol, data)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw = s.recvfrom(65565)

    while True:
        dest, src, proto, data = parse_eth_head(raw[0])
        print(f'Dest = {dest}, source: {src}, protocol: {proto}, data: {data}')

if __name__ == '__main__':
    main()