############################################################################################
# stream.py : cut huge packet into piece
# Usage : python3 stream.py [.pcap file]
############################################################################################

challenge_port = {
    80 : 'challenge1',
    8000 : 'challenge2',
    9487 : 'challenge3',
    2323 : 'challenge4',
    56746 : 'challenge5',
    10104 : 'applestore',
}

STREAM_OUTPUT_DIR = 'pcapio'
CONSIDER_ONLY_INPUT = True  # 3s
REPEATED_PORT_DETECT = True # 0.5 ~ 1s 
REPEATED_PACKET_DETECT = True  # 60s

KB = 1024
MB = 1024*1024
IGNORE_SIZE = False
MAXIMUM_ACCEPT_PACKET_SIZE = 1*MB
IP = '192.168.56.101' # start with
MASK = 0
