import parsers as parse


TAB = "\t"


def handle_icmp(data):
    icmp = parse.icmp_head(data)
    print(f"{TAB}Type: {icmp[0]}, Code: {icmp[1]}")
    print(
        "Details: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages"
    )


def handle_tcp(data):
    tcp = parse.tcp_head(data)
    print(f"{TAB}Source port: {tcp[0]}, Destination port: {tcp[1]}")
    print(f"{TAB}Sequence: {tcp[2]}, Acknoledgement: {tcp[3]}")
    print(f"{TAB}Flags:")
    print(f'{TAB * 2}URG: {tcp[4]["urg"]}, ACK: {tcp[4]["ack"]}, PSH: {tcp[4]["psh"]}')
    print(f'{TAB * 2}RST: {tcp[4]["rst"]}, SYN: {tcp[4]["syn"]}, FIN: {tcp[4]["fin"]}')


def handle_udp(data):
    udp = parse.udp_head(data)
    print(f"{TAB}Source port: {udp[0]}, Destination port: {udp[1]}, Length: {udp[2]}")
