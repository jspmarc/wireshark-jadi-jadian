import socket

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    tmp = s.recvfrom(65565)
    print(tmp)
    # while True:
    #     print(s.recvfrom(65565))

if __name__ == '__main__':
    main()