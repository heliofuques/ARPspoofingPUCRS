import socket
from struct import *

"""
IPv6 Header

version         (4bits)
traffic class   (8bits)
flow label      (20bits)
paylod length   (16bits)
next header     (8bits)


    0       3       7       11      15      19      23      27      31
    +-------+-------+-------+-------+-------+-------+-------+-------+
1   |  ver  |    traffic    |               flowlabel               |
    +-------+-------+-------+-------+-------+-------+-------+-------+
2   |         Payload lenght        |   nxt header  |  hop limit    |
    +-------+-------+-------+-------+-------+-------+-------+-------+
3   |                                                               |
    +                                                               +
4   |                                                               |
    +                    Source Address (128 bits)                  +
5   |                                                               |
    +                                                               +
6   |                                                               |
    +-------+-------+-------+-------+-------+-------+-------+-------+
7   |                                                               |
    +                                                               +
8   |                                                               |
    +               Destination Address (128 bits)                  +
9   |                                                               |
    +                                                               +
10  |                                                               |
    +-------+-------+-------+-------+-------+-------+-------+-------+
"""


def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = s + (s >>16);

    s = ~s & 0xffff
    return s


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + 'Message ' + msg[1]
    sys.exit()




packet = ''




version = 6
traffic = 0
flowlabel = 0
payload = 0
nextHeader = 6
hopLimit = 255
src = "::1"
dst = "::1"

ip_saddr = socket.inet_aton(src)
ip_daddr = socket.inet_aton(dst)

