import socket
from sys import platform

import handlers
import helpers
import parsers as parse

ipv4_protocol_id = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
}

ipv4_protocol_handler = {
    "icmp": handlers.handle_icmp,
    "tcp": handlers.handle_tcp,
    "udp": handlers.handle_udp,
}


def main():
    if platform.startswith("linux"):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            # eth_type_chosen = int(input("Mau pakai ether type apa?\n1: IPv4\n2: ARP\n(1/2)> "))
            if_names = helpers.ifnames_to_array()
            i = 1
            tmp_str = ""
            print("Pilih network device:")
            for if_name in if_names[1:]:
                print(f"{i}: {if_name}")
                tmp_str += f"{i}/"
                i += 1
            tmp_str = tmp_str[:-1]
            if_name_chosen = if_names[int(input(f"({tmp_str})> "))]

            ipv4_protocol_chosen = ["", "icmp", "tcp", "udp"][
                int(input("Mau pakai protokol apa?\n1: ICMP\n2: TCP\n3: UDP\n(1/2/3)> "))
            ]

            while True:
                raw, other_info = s.recvfrom(65565)
                if_name = other_info[0]
                eth = parse.eth_head(raw)

                if eth[2] == 8 and if_name_chosen == if_name:  # ipv4, 0x0008
                    ipv4 = parse.ipv4_head(eth[3])

                    data = ipv4[6]
                    ipv4_protocol = ipv4[3]

                    if ipv4_protocol == ipv4_protocol_id[ipv4_protocol_chosen]:
                        print(
                            f"Source IP: {ipv4[4]}; Destination IP: {ipv4[5]}; TTL: {ipv4[2]}"
                        )
                        ipv4_protocol_handler[ipv4_protocol_chosen](data)
                        print()
                elif eth[2] == 1544 and if_name_chosen == if_name:  # ARP, 0x0608
                    print("ARP is not yet implemented")
        except KeyboardInterrupt:
            print("\nSelamat tinggal")
        except PermissionError:
            print("Harus dijalankan sebagai root")
    else:
        print("Hanya bisa digunakan pada sistem operasi Linux.")


if __name__ == "__main__":
    main()
