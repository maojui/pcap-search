EXTENTION = '.cap' # for pcap-search parser

############################################################################################
# stream.py : cut huge packet into piece
# Usage : python3 stream.py [.pcap file]
############################################################################################

IP = '10.0.1.1' # service ip
MASK = 8         # bits  : 8 -> 10.0.1.x
CHALLENGE_SPLIT_BY_IP = True
# If challenge split by port
# challenge_port = {
#     2121 : 'blackjack',
#     5566 : 'hitcon-ftp'
# }
############################################################################################
# If challenge split by IP
challenge_ip = {
    '10.0.1.1' : 'blackjack',
    '10.0.1.2' : 'hitcon-ftp',
    '10.0.1.4' : 'stupid-robot',
    '10.0.1.5' : 'noobieweb'
}


STREAM_OUTPUT_DIR = '/home/public/extracted'

# Saving time is tested by HITCON CTF 2018 Final packet
CONSIDER_ONLY_INPUT = True      # Some random output (E.G. address leak) will be ignore.    (save 3s)
REPEATED_PORT_DETECT = True     # If port collision, this will save both.                   (spend about 0.5 ~ 1s)
REPEATED_PACKET_DETECT = True   # This will drop the repeated packet.                       (save 60s)

KB = 1024
MB = 1024*1024
IGNORE_SIZE = False
MAXIMUM_ACCEPT_PACKET_SIZE = 100 * MB

############################################################################################
# filter.py : move qualified packet to further analyize
############################################################################################

FILTER_INPUT = STREAM_OUTPUT_DIR
FILTER_OUTPUT = 'pcap/filter'

BLACK_LIST = []
