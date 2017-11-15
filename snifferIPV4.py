#self.packet sniffer in python for Linux
#Sniffs only incoming TCP self.packet
 
import socket, sys, logging
from struct import *

g_debug=False

# CONSTANTS 
c_AllPorts = 65565
c_macSize = 6

def debug_print(string):
    if(g_debug):
        print(string)
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

def ListToString(l):
    rt = ''
    for item in l:
        rt.append(item);
    return rt

def formatMAC(mac):
    rt = ""
    for i in range(0,c_macSize):
        rt += "%s%s"%(mac[i:i+2],":")
    return rt

class HijackIPV4:

    src_mac = ''
    dst_mac = ''
    source_port = '' 
    dest_port = ''
    sequence = ''
    acknowledgement = ''
    doff_reserved = ''
    tcph_length = ''
    packet = ''
    packetFull = ''
    s_addr = ''
    d_addr = ''

    def __init__(self):
        #create an INET, STREAMing socket
        try:
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self.s.bind((sys.argv[2],0))
            #self.sendingSocker = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
 
    def receive(self):
        print 'received'
        self.packetFull = self.s.recvfrom(c_AllPorts)

        #self.packet string from tuple
        self.packet = self.packetFull[0]
        self.translateEthernet()
        self.translateIP()
        self.translateTCP()
        

    def sendto(self):
        self.s.send(self.packetFull[0])


    def translateEthernet(self):
        ethernet_header = self.packet[0:14]
        eth = unpack('!6s6sH' , ethernet_header)
         
        
        self.src_mac = toHex(ethernet_header[0:6].decode("latin1")))
        self.dst_mac = toHex(ethernet_header[6:12].decode("latin1")))

        string_print =  'Source MAC-Address : ' + str(self.src_mac)\
        + ' Destination MAC-Address : ' + str(self.dst_mac)
        debug_print(string_print) 

        # nao seria o src_mac? 
        self.dst_mac = ListToString(toHex(argv[3]))#funcao q transforma agv[3] em hex

        
        self.packet[0:14] = pack('!6s6sH', self.src_mac, self.dst_mac, eth[2])
        


    def translateIP(self):

        #take first 20 characters for the ip header
        ip_header = self.packet[14:34]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        self.iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        self.s_addr = socket.inet_ntoa(iph[8]);
        self.d_addr = socket.inet_ntoa(iph[9]);

        string_print = 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : '\
        + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(self.s_addr)\
        + ' Destination Address : ' + str(self.d_addr)
        debug_print(string_print) 

        if self.s_addr == '10.0.0.1':
            print 'found'
            self.sendto()
        # print d_addr
        #self.sendingSocker.sendto(self.packetFull[0], (d_addr,8080))

    def translateTCP(self):

        tcp_header = self.packet[self.iph_length:self.iph_length+20]

        #now unpack them :)
        tcph = unpack('!HHLLBBHHH' , tcp_header)

        self.source_port = tcph[0]
        self.dest_port = tcph[1]
        self.sequence = tcph[2]
        self.acknowledgement = tcph[3]
        self.doff_reserved = tcph[4]
        self.tcph_length = self.doff_reserved >> 4

        debug_print ("%s" %('Source Port : ' + str(self.source_port) + ' Dest Port : ' + str(self.dest_port)\
        + ' Sequence Number : ' + str(self.sequence) + ' Acknowledgement : '\
        + str(self.acknowledgement) + ' TCP header length : ' + str(self.tcph_length))) 

        h_size = self.iph_length + self.tcph_length * 4
        data_size = len(self.packet) - h_size

        #get data from the self.packet
        data = self.packet[h_size:]

        debug_print("%s"%'Data : ' + data +'\n') 

if (len(sys.argv)>1):
    if(sys.argv[1] == 'debug'):
        g_debug=True
hijack = HijackIPV4()
# receive a self.packet
while True:
    hijack.receive()

