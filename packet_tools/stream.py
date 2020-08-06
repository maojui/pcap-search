#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from config import *
import pickle
import dpkt
import argparse
from urllib.parse import unquote
import os, sys
import hashlib

hash = lambda sport, dport: hashlib.md5('-'.join(map(str,sorted([sport,dport]))).encode('utf-8')).hexdigest()

inet_to_ip = lambda _IP : '.'.join(map(str,map(int,_IP)))

if CHALLENGE_SPLIT_BY_IP :
    # challenge split by ip
    masked = lambda _IP : ''.join(list(map(lambda x : bin(x)[2:].rjust(8,'0'),_IP)))[:-MASK] + MASK * '0'
else :
    # challenge split by port
    masked = lambda _IP : ''.join(list(map(lambda x : bin(x)[2:].rjust(8,'0'),_IP)))[:-MASK] + MASK * '0'


my_ip = map(int,IP.split('.'))
my_ip = masked(my_ip)

class stream:
    
    Count = 1
    
    def __init__(self, pcap, source, destination, num, start, udp=False):
        self.pcap = pcap
        self.pcap_filename = self.pcap.rstrip('.pcap').split("/")[-1]
        os.makedirs(os.path.join(STREAM_OUTPUT_DIR),exist_ok=True)
        self.src = source[0]
        self.sport = source[1]         # from attacker's or my random port out
        self.dst = destination[0]
        self.dport = destination[1]    # vulnerable port connect
        self.count = stream.Count
        self.udp = udp
        self.num = num
        self.ts = []
        self.pkt = []
        self.start = start
        stream.Count += 1
        self.hash = None

    # save the content to each stream class.
    def add_content(self, data, ts, pkt, dst):
        self.ts.append( ts )
        self.pkt.append(bytes(pkt))
        dst = masked(map(int,dst))
        if dst == my_ip or self.udp :
            try:
                request = dpkt.http.Request(data)
                data = pickle.dumps(request)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                pass

            if not self.hash :
                self.hash = hashlib.md5(data)
            else :
                self.hash.update(data)

    def gethash(self):
        if not self.hash :
            return None
        else :
            return self.hash.hexdigest() 
        
    # write out to file.
    def save(self):
        
        if not IGNORE_SIZE:
            
            size_cal = 0

            for pkt in self.pkt :
                size_cal += sys.getsizeof(pkt)
                
            if size_cal > MAXIMUM_ACCEPT_PACKET_SIZE :
                print("too big")
                return

        if self.start :

            if CHALLENGE_SPLIT_BY_IP and self.dst in challenge_ip :
                
                # IP Save
                filename_path = '/'.join(map(str,[STREAM_OUTPUT_DIR,challenge_ip[self.dst],self.pcap_filename,""]))
                os.makedirs(os.path.join(filename_path),exist_ok=True)

            elif not CHALLENGE_SPLIT_BY_IP and self.dport in challenge_port :  # filter my attack
                
                # Save in challenge/port
                filename_path = '/'.join(map(str,[STREAM_OUTPUT_DIR,challenge_port[self.dport],self.pcap_filename,""]))
                os.makedirs(os.path.join(filename_path),exist_ok=True)

            else :

                filename_path = '/'.join(map(str,[STREAM_OUTPUT_DIR,str('backdoor?') + self.dst,self.pcap_filename,""]))
                os.makedirs(os.path.join(filename_path),exist_ok=True)

        else :

            filename_path = '/'.join(map(str,[STREAM_OUTPUT_DIR,'incomplete',self.pcap_filename,""]))
            os.makedirs(os.path.join(filename_path),exist_ok=True)
        
        if self.udp:
            print( os.path.join("".join([filename_path, str(self.sport) ,'_' + self.num,'.cap'])))

        with open( os.path.join("".join([filename_path, str(self.sport) ,'_' + self.num,'.cap'])),'wb') as fileoutput :
            
            writer = dpkt.pcap.Writer(fileoutput, nano=False)
            for i in range(len(self.ts)):
                writer.writepkt(self.pkt[i],self.ts[i])
            
                

def extract(filename):
    
    payload = []
    streams = {}
    Rport = {}
    Repeated = {}
    key = ''
    
    for ts, pkt in dpkt.pcap.Reader(open(filename,'rb')):

        eth = dpkt.ethernet.Ethernet(pkt)

        # if eth.type & dpkt.ethernet.ETH_TYPE_IP :
        #     continue
        # print(eth.type,dpkt.ethernet.ETH_TYPE_IP)

        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_TCP : 
            
            tcp = ip.data
            source = ( inet_to_ip(ip.src), tcp.sport)
            dest = ( inet_to_ip(ip.dst), tcp.dport)
            key = hash(source,dest)

            if REPEATED_PORT_DETECT :
                syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
                ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
                Rport[key] = temp = Rport.get(key,0)

                start = False
                # some pkt's port collision
                if syn_flag & ~ack_flag == 1 :
                    Rport[key] = temp + 1
                    start = True

                Rnum = str(Rport[key])
                key = hashlib.md5( (key+Rnum).encode('utf-8') ).hexdigest()
                streams[key] = streams.get(key, stream(filename, source, dest, Rnum, start))

            else :

                streams[key] = streams.get(key, stream(filename, source, dest, '1', False))

            streams[key].add_content(tcp.data, ts, pkt, ip.dst)
            
        else :
            if ip.p == dpkt.ip.IP_PROTO_UDP :                
                udp = ip.data

                source = ( inet_to_ip(ip.src), udp.sport)
                dest = ( inet_to_ip(ip.dst), udp.dport)
                key = hash(source, dest)
                # Pass the IP addresses, source port, destination port, and data back to the caller.
                # yield ( ip.src, udp.sport, ip.dst, udp.dport, udp.data, ip.v)
                streams[key] = streams.get(key, stream(filename, source, dest, '1', True, udp=True))

            streams[key].add_content(udp.data, ts, pkt, ip.dst)
        

    for ss in streams.values():
        
        digest = ss.gethash()
        if REPEATED_PACKET_DETECT :
            if not Repeated.get(digest,False) :
                Repeated[digest] = True
                ss.save()
        else :
            ss.save()




if __name__ == "__main__":
    
    for file in sys.argv[1:] :
        
        extract(file)
        print(file," Extracted.")



# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
# ETH_TYPE_EDP = 0x00bb  # Extreme Networks Discovery Protocol
# ETH_TYPE_PUP = 0x0200  # PUP protocol
# ETH_TYPE_IP = 0x0800  # IP protocol
# ETH_TYPE_ARP = 0x0806  # address resolution protocol
# ETH_TYPE_AOE = 0x88a2  # AoE protocol
# ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
# ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
# ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
# ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
# ETH_TYPE_8021AD = 0x88a8  # IEEE 802.1ad
# ETH_TYPE_QINQ1 = 0x9100  # Legacy QinQ
# ETH_TYPE_QINQ2 = 0x9200  # Legacy QinQ
# ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
# ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
# ETH_TYPE_PPP = 0x880B  # PPP
# ETH_TYPE_MPLS = 0x8847  # MPLS
# ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
# ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
# ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage
# ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol
# ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging
