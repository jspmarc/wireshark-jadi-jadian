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
        if eth[2] == 8: # ipv4
            ipv4 = parse.ipv4_head(eth[3])
            print('\tIPv4 packet:')
            print(f'\t\tVersion: {ipv4[0]}, header length: {ipv4[1]}, TTL: {ipv4[2]}')
            print(f'\t\tProtocol: {ipv4[3]}, source: {ipv4[4]}, destination: {ipv4[5]}')

            if ipv4[3] == 6: # protocol-nya TCP
                tcp = parse.tcp_head(ipv4[6])
                print('\t\t\tTCP segment:')
                print(f'\t\t\t\tSource port: {tcp[0]}, Destination port: {tcp[1]}')
                print(f'\t\t\t\tSequence: {tcp[2]}, Acknoledgement: {tcp[3]}')
                print('\t\t\t\tFlags:')
                print(f'\t\t\t\t\tURG: {tcp[4]["urg"]}, ACK: {tcp[4]["ack"]}, PSH: {tcp[4]["psh"]}')
                print(f'\t\t\t\t\tRST: {tcp[4]["rst"]}, SYN: {tcp[4]["syn"]}, FIN: {tcp[4]["fin"]}')

if __name__ == '__main__':
    main()