import socket

import parsers as parse

protocol_id = {
    'icmp': 1,
    'tcp': 6,
    'udp': 17,
}

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    raw, addr = s.recvfrom(65565)

    while True:
        eth = parse.eth_head(raw)
        print(f'Dest = {eth[0]}, source: {eth[1]}, protocol: {eth[2]}')
        if eth[2] == 8:
            ipv4 = parse.ipv4_head(eth[3])
            print('\tIPv4 packet:')
            print(f'\t\tVersion: {ipv4[0]}, header length: {ipv4[1]}, TTL: {ipv4[2]}')
            print(f'\t\tProtocol: {ipv4[3]}, sourec: {ipv4[4]}, destination: {ipv4[5]}')

if __name__ == '__main__':
    main()