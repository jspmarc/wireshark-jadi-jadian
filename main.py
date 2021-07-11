import helpers

import socket
from struct import unpack

def parse_ipv4(raw):
    prot_ver_head_len, ttl, protocol, src_raw, dest_raw = unpack("! B 7x B B 2x 4s 4s", raw[:20])

    protocol_version = prot_ver_head_len >> 4
    header_length = (prot_ver_head_len & 0xF) * 4 # dikali 4, karena ada "4 baris" dengan 1 "baris" 5 byte
    data = raw[header_length:]
    src = helpers.get_ip(src_raw)
    dest = helpers.get_ip(dest_raw)

    return protocol_version, header_length, ttl, protocol, src, dest, data


def parse_eth_head(raw):
    '''
    ! == network(=big-endian) ordering
    s == char[] (bytes)
    H = unsigned char (2 bytes)
    '''

    dest, src, protocol_raw = unpack("! 6s 6s H", raw[:14]) # https://docs.python.org/3/library/struct.html
    dest_mac = helpers.get_mac_addr(dest)
    src_mac = helpers.get_mac_addr(src)
    protocol = socket.htons(protocol_raw)
    data = raw[14:]

    return (dest_mac, src_mac, protocol, data)

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    raw, addr = s.recvfrom(65565)

    while True:
        eth = parse_eth_head(raw)
        print(f'Dest = {eth[0]}, source: {eth[1]}, protocol: {eth[2]}')
        if eth[2] == 8:
            ipv4 = parse_ipv4(eth[3])
            print('\tIPv4 packet:')
            print(f'\t\tVersion: {ipv4[0]}, header length: {ipv4[1]}, TTL: {ipv4[2]}')
            print(f'\t\tProtocol: {ipv4[3]}, sourec: {ipv4[4]}, destination: {ipv4[5]}')

if __name__ == '__main__':
    main()