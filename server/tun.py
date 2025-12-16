import os, fcntl, struct

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

class Tun:
    def __init__(self, name):
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)

    def read(self, n=2048):
        return os.read(self.fd, n)

    def write(self, data):
        os.write(self.fd, data)

    def fileno(self):
        return self.fd

    def close(self):
        os.close(self.fd)
