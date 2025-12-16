import socket

class UDP:
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
        self.sock.bind(("0.0.0.0", port))
        self.sock.setblocking(False)

    def recv(self):
        return self.sock.recvfrom(2048)

    def send(self, data, addr):
        self.sock.sendto(data, addr)

    def fileno(self):
        return self.sock.fileno()

    def close(self):
        self.sock.close()
