#!/usr/bin/env python2

import re
import sys
import struct
import socket
import time

ff = open(sys.argv[1], 'rb')
offset = int(sys.argv[2])

ff.seek(-4, 2)
total_conns = struct.unpack('I', ff.read(4))[0]
ff.seek(-4 * (1 + total_conns), 2)
len_conns = list(struct.unpack('I' * total_conns, ff.read(4 * total_conns)))

_out_file = sys.stdout
_offset_in_data = False
_idir = {'sc': 0, 'cs': 1}

cur_dir = None
cur_data = None
is_last_packet = False

def out_begin_locconn(_a, _b, ff):
    print ff.tell(),

def out_locconn(*args):
    pass

def out_end_locconn(ff):
    print ff.tell()

def out_end_str(*args):
    if _out_file != sys.stdout:
        _out_file.close()
out_end_repr = out_end_hex = out_end_str

def out_end_loc(*args):
    if not _offset_in_data:
        print >>_out_file, -1, -1
    if _out_file != sys.stdout:
        _out_file.close()


def out_begin_hex(*args):
    global _out_file
    _out_file = open(sys.argv[5], 'wb')
    print >>_out_file, 'Time: ', time.ctime(args[1])
out_begin_str = out_begin_repr = out_begin_hex

def out_begin_loc(*args):
    global _out_file
    _out_file = open(sys.argv[5], 'wb')


def out_pcap(*args):
    pass
out_end_pcap = out_pcap

def out_loc(srcip, srcport, destip, dstport, data, direction, ff):
    global _offset_in_data
    if ff.tell() > offset and ff.tell() - len(data) <= offset:
        _offset_in_data = True
        print >>_out_file, ff.tell() - len(data), ff.tell()


def out_repr(srcip, srcport, destip, dstport, data, direction, ff):
    print >>_out_file, socket.inet_ntoa(struct.pack('I', srcip)) + ':' + str(srcport),
    print >>_out_file, ' -->{}'.format(direction),
    print >>_out_file, socket.inet_ntoa(struct.pack('I', destip)) + ':' + str(dstport),
    print >>_out_file, '(%d bytes)' % len(data)
    print >>_out_file, repr(data)
    print >>_out_file, "--------------------------------------------"


def out_hex(srcip, srcport, destip, dstport, data, direction, ff):
    print >>_out_file, socket.inet_ntoa(struct.pack('I', srcip)) + ':' + str(srcport),
    print >>_out_file, ' -->{}'.format(direction),
    print >>_out_file, socket.inet_ntoa(struct.pack('I', destip)) + ':' + str(dstport),
    print >>_out_file, '(%d bytes)' % len(data)
    enc_data = data.encode('hex')
    print >>_out_file, ' '.join([enc_data[j:j+2] for j in xrange(0, len(enc_data), 2)])
    print >>_out_file, "--------------------------------------------"


def out_str(srcip, srcport, destip, dstport, data, direction, ff):
    print >>_out_file, socket.inet_ntoa(struct.pack('I', srcip)) + ':' + str(srcport),
    print >>_out_file, ' -->{}'.format(direction),
    print >>_out_file, socket.inet_ntoa(struct.pack('I', destip)) + ':' + str(dstport),
    print >>_out_file, '(%d bytes)' % len(data)
    print >>_out_file, str(data)
    print >>_out_file, "--------------------------------------------"



def out_begin_c(*args):
    global _out_file, ix
    _out_file = open(sys.argv[5], 'wb')
    ix = [0, 0]

def out_c(srcip, srcport, destip, dstport, data, direction, ff):
    payload = ''
    last = False
    for c in data:
        if 32 <= ord(c) < 127 and c not in '&<>\\"':
            if last:
                payload += '""'
            payload += c
            last = False
        else:
            payload += '\\x%0*x' % (2, ord(c))
            last = True
    side = 1 if direction == 'sc' else 0
    print >>_out_file, 'const unsigned char payload_{}_{}[] = "'.format('client' if side == 0 else 'server', ix[side], payload)+payload+'";'
    ix[side] += 1

def out_end_c(*args):
    if _out_file != sys.stdout:
        _out_file.close()



def out_begin_pythonsimple(*args):
    global _out_file
    _out_file = open(sys.argv[5], 'wb')
    print >>_out_file, '#!/usr/bin/env python2'
    print >>_out_file, '#-*- coding:utf-8 -*-'
    print >>_out_file, r"""
import os, sys, string, random
from pwn import *

DO_RECV, DO_SEND = 0, 1

try:
    from termcolor import colored
except:
    # if termcolor import failed, use the following v1.1.0 source code of termcolor here
    # since termcolor use MIT license, SATA license above should be OK
    ATTRIBUTES = dict( list(zip([ 'bold', 'dark', '', 'underline', 'blink', '', 'reverse', 'concealed' ], list(range(1, 9)))))
    del ATTRIBUTES['']
    HIGHLIGHTS = dict( list(zip([ 'on_grey', 'on_red', 'on_green', 'on_yellow', 'on_blue', 'on_magenta', 'on_cyan', 'on_white' ], list(range(40, 48)))))
    COLORS = dict(list(zip(['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', ], list(range(30, 38)))))
    RESET = '\033[0m'

    def colored(text, color=None, on_color=None, attrs=None):
        fmt_str = '\033[%dm%s'
        if color is not None: text = fmt_str % (COLORS[color], text)
        if on_color is not None: text = fmt_str % (HIGHLIGHTS[on_color], text)
        if attrs is not None:
            for attr in attrs:
                text = fmt_str % (ATTRIBUTES[attr], text)

        text += RESET
        return text
"""
    print >>_out_file, 'seq = []'
    print >>_out_file, '# 1 for SEND, 0 for RECV'


def out_end_pythonsimple(*args):
    print >>_out_file, "colors = ['yellow', 'cyan']"
    print >>_out_file, r"""
def attack(host, port):
    r = remote(host, port, timeout=40)
    for action, s in seq:
        if action == DO_RECV:
            data = r.recvuntil(s)
            print("RECV: \033[33m{}\033[0m").format(repr(data))
        elif action == DO_SEND:
            print("SEND: \033[36m{}\033[0m").format(repr(s))
            r.send(s)
    #r.interactive()
    return r.recv(0x1000)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print '-' * 50, ' BEGIN NETWORK FLOW ', '-' * 50
        for c, s in seq:
            print c == 0 and '[ Server ]:' or '[ Client ]:', colored(repr(s), colors[c])
        print '-' * 50, ' END NETWORK FLOW ', '-' * 50
        print 'usage: \n    %s <host> <port>' % sys.argv[0]
        sys.exit()
    port = 143
    host = '127.0.0.1'
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except:
            port = 143
    flags = attack(host, port)

    print 'flags = %r' % (flags)
"""
    if _out_file != sys.stdout:
        _out_file.close()

def out_pythonsimple(srcip, srcport, destip, dstport, data, direction, ff):
    global _idir
    idir = _idir[direction]
    print >>_out_file, "seq.append((%d, %r))" % (idir, data)

def out_pythonsimple_zigzag(srcip, srcport, destip, dstport, data, direction, ff):
    global _idir, cur_dir, cur_data
    global is_last_packet
    idir = _idir[direction]

    if cur_dir == None: # first packet
        cur_dir = idir
        cur_data = data
    elif cur_dir == idir: # same direction
        cur_data += data
    else: # change direction, append the previous sequence
        print >>_out_file, "seq.append((%d, %r))" % (cur_dir, cur_data)
        cur_dir = idir # new direction
        cur_data = data # new data

    if is_last_packet: # last packet, write directly
        print >>_out_file, "seq.append((%d, %r))" % (cur_dir, cur_data)

def out_begin_pythondiff(*args):
    global _out_file
    _out_file = open(sys.argv[5], 'wb')
    print >>_out_file, '#!/usr/bin/env python2'
    print >>_out_file, '#-*- coding:utf-8 -*-'
    print >>_out_file, 'from pwn import *'
    print >>_out_file, 'import sys'
    print >>_out_file, 'timeout = 0.2'
    print >>_out_file, r"""
try:
    from termcolor import colored
except:
    # if termcolor import failed, use the following v1.1.0 source code of termcolor here
    # since termcolor use MIT license, SATA license above should be OK
    ATTRIBUTES = dict( list(zip([ 'bold', 'dark', '', 'underline', 'blink', '', 'reverse', 'concealed' ], list(range(1, 9)))))
    del ATTRIBUTES['']
    HIGHLIGHTS = dict( list(zip([ 'on_grey', 'on_red', 'on_green', 'on_yellow', 'on_blue', 'on_magenta', 'on_cyan', 'on_white' ], list(range(40, 48)))))
    COLORS = dict(list(zip(['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', ], list(range(30, 38)))))
    RESET = '\033[0m'

    def colored(text, color=None, on_color=None, attrs=None):
        fmt_str = '\033[%dm%s'
        if color is not None: text = fmt_str % (COLORS[color], text)
        if on_color is not None: text = fmt_str % (HIGHLIGHTS[on_color], text)
        if attrs is not None:
            for attr in attrs:
                text = fmt_str % (ATTRIBUTES[attr], text)

        text += RESET
        return text

def send_data(data):
    print("="*50)
    print("SEND: \033[36m{}\033[0m").format(repr(data))
    r.send(data)

def recv_data(expected, debug):
    print("="*50)
    if debug == True:
        sys.stdout.write("RECV: ")
        recv_data = r.recvrepeat(timeout = timeout)
        diffstr(recv_data, expected)
    else:
        recv_data = r.recvuntil(expected)
        print("RECV: \033[33m{}\033[0m").format(repr(recv_data))

def diffstr(content, expected):
    import difflib
    differ = difflib.ndiff(expected, content)
    for i in differ:
        text = repr(i[-1])[1:-1]
        if i[0] == " ":
	    sys.stdout.write(text)
        if i[0] == "+": # red means "I shoudn\'t recv these bytes"
	    sys.stdout.write(colored(text, on_color="on_red"))
        if i[0] == "-": # blue means "I expect to recv these bytes, but I didn\'t see them"
	    sys.stdout.write(colored(text, on_color="on_blue"))
    sys.stdout.write("\n")
    sys.stdout.flush()

"""
    print >>_out_file, 'print("Usage: {} <host> <port> [ird]\\n\\ti: interactive at the end\\n\\tr: recv till timeout at the end\\n\\td: show info of diff response and expected response".format(sys.argv[0]))'
    print >>_out_file, 'print("Diff info example:")'
    print >>_out_file, 'print("{} : Don\'t expect \\"A\\" to be received but receive it.".format(colored("A", on_color="on_red")))'
    print >>_out_file, 'print("{} : Expect \\"A\\" to be received but didn\'t receive it.".format(colored("A", on_color="on_blue")))'
    print >>_out_file, '\nr = remote(sys.argv[1], int(sys.argv[2]))'
    print >>_out_file, 'debug = True if ( len(sys.argv) >= 4 and "d" in sys.argv[3] ) else False # set the debug level'

def out_end_pythondiff(*args):
    print >>_out_file, '\nif len(sys.argv) >= 4 and "r" in sys.argv[3]:'
    print >>_out_file, '    data = r.recv(0x1000)'
    print >>_out_file, '    print ("\\033[33m{}\\033[0m".format(repr(data)) )'
    print >>_out_file, 'if len(sys.argv) >= 4 and "i" in sys.argv[3]:'
    print >>_out_file, '    r.interactive()'
    if _out_file != sys.stdout:
        _out_file.close()

def write_diff_on_direction(direction, data, prev=False):
    if prev: direction = direction[::-1]
    if direction == 'cs': # send ( Client -> Server )
        print >>_out_file, '\nsend_data({})'.format(repr(data))
    else:
        print >>_out_file, '\nexpected = {}'.format(repr(data))
        print >>_out_file, 'recv_data(expected, debug)'

def out_pythondiff(srcip, srcport, destip, dstport, data, direction, ff):
    write_diff_on_direction(direction, data)

def out_pythondiff_zigzag(srcip, srcport, destip, dstport, data, direction, ff):
    global cur_dir, cur_data
    global is_last_packet
    idir = _idir[direction]

    if cur_dir == None: # first packet
        cur_dir = idir
        cur_data = data
    elif cur_dir == idir: # same direction
        cur_data += data
    else: # change direction, append the previous sequence
        write_diff_on_direction(direction, cur_data, prev=True)
        cur_dir = idir # new direction
        cur_data = data # new data

    if is_last_packet: # last packet, write directly
        write_diff_on_direction(direction, cur_data)

def out_begin_pcap(_pkts, timestamp, *args):
    import dpkt
    import pcap
    pkts = list(_pkts)
    reader = pcap.pcap(sys.argv[4])
    writer = dpkt.pcap.Writer(open(sys.argv[5], 'wb'))
    cnt = 0
    while True:
        try:
            i = reader.next()
            cnt += 1
            if cnt in pkts:
                writer.writepkt(str(i[1]), i[0])
                pkts.remove(cnt)
            if len(pkts) == 0:
                break
        except StopIteration:
            break
    assert(pkts == [])
    writer.close()

def out_begin_json(*args):
    global _out
    _out = dict(timestamp=args[1], conversation=[])

import base64
def out_json(srcip, srcport, dstip, dstport, data, direction, ff):
    _out['conversation'].append(dict(
        srcip=socket.inet_ntoa(struct.pack('I', srcip)),
        srcport=srcport,
        dstip=socket.inet_ntoa(struct.pack('I', dstip)),
        dstport=dstport,
        dir=direction,
        data=base64.b64encode(data),
    ))

def out_end_json(*args):
    import json
    with open(sys.argv[5], 'w') as _out_file:
        _out_file.write(json.dumps(_out, indent=2, ensure_ascii=False))



out = eval('out_' + sys.argv[3])
begin_end_func = sys.argv[3] if "_zigzag" not in sys.argv[3] else sys.argv[3][:-7:]
out_begin = eval('out_begin_' + begin_end_func)
out_end = eval('out_end_' + begin_end_func)

current_offset = 0
found = False
for i in len_conns:
    if current_offset <= offset < current_offset + i:
        found = True
        ff.seek(current_offset, 0)
        len_pkt, cliip, servip, cliport, servport, timestamp = struct.unpack('IIIHHI', ff.read(20))
        cnt_pkt = struct.unpack('I', ff.read(4))[0]
        pkts_id = struct.unpack('I' * cnt_pkt, ff.read(4 * cnt_pkt))
        out_begin(pkts_id, timestamp, ff)
        cur_dir = None
        is_last_packet = False
        for cur_packet in xrange(len_pkt):
            if cur_packet == len_pkt - 1: is_last_packet = True
            direction = ff.read(1)
            len_data = struct.unpack('I', ff.read(4))[0]
            data = ff.read(len_data)
            if direction == 'c':
                out(cliip, cliport, servip, servport, data, 'cs', ff)
            else:
                out(servip, servport, cliip, cliport, data, 'sc', ff)
        out_end(ff)
        break
    current_offset += i

ff.close()

if not found:
    sys.exit(5)
