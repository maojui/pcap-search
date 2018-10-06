#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from config import *
import dpkt
import os
import sys

files_path = []

def listdir(d):
    
    if not os.path.isdir(d):
        if d.endswith(EXTENTION):
            files_path.append(d)
    else:
        for item in os.listdir(d):
            listdir((d + '/' + item) if d != '/' else '/' + item)

listdir(FILTER_INPUT)

for path in files_path :
    
    acceptable = True

    content = b''

    for ts, pkt in dpkt.pcap.Reader(open(path,'rb')):
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data
        tcp = ip.data
        content += tcp.data

    for b in BLACK_LIST :
        if b in content :
            acceptable = False
    
    
    if acceptable :
        filename = os.path.basename(path)
        dirname = os.path.basename(os.path.dirname(path))
        os.makedirs(FILTER_OUTPUT,exist_ok=True)
        os.makedirs(FILTER_OUTPUT+'/'+dirname,exist_ok=True)
        os.system('mv {} {}/{}/{}'.format(path,FILTER_OUTPUT,dirname,filename))