import parsers as parse


def handle_icmp(data):
    icmp = parse.icmp(data)
    print(f"\tType: {icmp[0]}, Code: {icmp[1]}")


def handle_tcp(data):
    tcp = parse.tcp_head(data)
    print(f"Source port: {tcp[0]}, Destination port: {tcp[1]}")
    print(f"\tSequence: {tcp[2]}, Acknoledgement: {tcp[3]}")
    print("\tFlags:")
    print(f'\t\tURG: {tcp[4]["urg"]}, ACK: {tcp[4]["ack"]}, PSH: {tcp[4]["psh"]}')
    print(f'\t\tRST: {tcp[4]["rst"]}, SYN: {tcp[4]["syn"]}, FIN: {tcp[4]["fin"]}')


def handle_udp(data):
    udp = parse.udp_head(data)
    print(f"\tSource port: {udp[0]}, Destination port: {udp[1]}, Length: {udp[2]}")
