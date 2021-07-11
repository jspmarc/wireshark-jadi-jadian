import socket

import handlers
import parsers as parse

ipv4_protocol_id = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
}

ipv4_protocol_handler ={
    "icmp": handlers.handle_icmp,
    "tcp": handlers.handle_tcp,
    "udp": handlers.handle_udp
}


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    raw, addr = s.recvfrom(65565)

    ipv4_protocol_chosen = ["", "icmp", "tcp", "udp"][
        int(input("Mau pakai protokol apa?\n1: ICMP\n2: TCP\n3: UDP\n(1/2/3)> "))
    ]

    while True:
        eth = parse.eth_head(raw)
        if eth[2] == 8:  # ipv4
            ipv4 = parse.ipv4_head(eth[3])
            data = ipv4[6]
            ipv4_protocol = ipv4[3]

            if ipv4_protocol == ipv4_protocol_id[ipv4_protocol_chosen]:
                ipv4_protocol_handler[ipv4_protocol_chosen](data)


if __name__ == "__main__":
    main()
