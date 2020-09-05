import dshell
import util
import colorout
#from impacket.ImpactDecoder import EthDecoder
import datetime
import sys
import traceback
import logging
import struct
import socket
import os

# import any other modules here
import cgi


class DshellDecoder(dshell.TCPDecoder):

    def __init__(self):
        dshell.TCPDecoder.__init__(self,
                                   name='stream2dump',
                                   description='Generates color-coded Screen/HTML output similar to Wireshark Follow Stream',
                                   longdescription="""
Generates color-coded Screen/HTML output similar to Wireshark Follow Stream.

Output by default uses the "colorout" output class.  This will send TTY
color-formatted text to stdout (the screen) if available.  If output
is directed to a file (-o or --outfile), the output will be in HTML format.

Note that the default bpf filter is to view all tcp traffic.  The decoder
can also process UDP traffic, or it can be limited to specific streams
with --bpf/--ebpf.

Useful options:

	--followstream_hex -- generates output in hex mode
	--followstream_time -- includes timestamp for each blob/transmission
	
Example:

  decode -d followstream --ebpf 'port 80' mypcap.pcap --followstream_time
  decode -d followstream --ebpf 'port 80' mypcap.pcap -o file.html --followstream_time

""",
                                   filter="",
                                   author='amm',
                                   optiondict={
                                       'hex': {'action': 'store_true', 'help': 'two-column hex/ascii output'},
                                       'time': {'action': 'store_true', 'help': 'include timestamp for each blob'},
                                       'encoding': {'type': 'string', 'help': 'attempt to interpret text as encoded with specified schema'},
                                       'padding': {'type': 'string', 'help': 'padding character for the missing bytes. Format: 0x??'},
                                       'outfiles': {'type': 'string', 'help': 'output files'},
                                   }
                                   )
        self.out = colorout.ColorOutput()

    def __errorHandler(self, blob, expected, offset, caller):
        # Custom error handler that is called when data in a blob is missing or
        # overlapping
        if offset > expected:  # data is missing
            self.data_missing_message += "[%d missing bytes]" % (
                offset - expected)
        elif offset < expected:  # data is overlapping
            self.data_missing_message += "[%d overlapping bytes]" % (
                offset - expected)
        return True

    def preModule(self):
        self.connectionCount = 0
        # Reset the color mode, in case a file is specified
        self.out.setColorMode()
        # Used to indicate when data is missing or overlapping
        self.data_missing_message = ''
        # overwrite the output module's default error handler
        self.out.errorH = self.__errorHandler
        self.dumpfiles = open(self.outfiles, 'wb')
        self.connlen = []

    def postModule(self):
        self.out.write('Writing Index\n')
        for i in self.connlen:
            self.dumpfiles.write(struct.pack('I', i))
        self.dumpfiles.write(struct.pack('I', len(self.connlen)))
        self.dumpfiles.close()

    def check_padding(self):
        ret = ''
        if self.padding != None: # padding is set
	    import re
	    patt = r"0x[0-9a-f][0-9a-f]"
	    if re.match(patt, self.padding) != None: # valid padding format
	        tmp = re.match(patt, self.padding).group(0)
                ret = tmp.replace("0x", "").decode('hex')
	    else: # invalid padding format
	       print("[!] Invalid padding format: {}".format(repr(self.padding)))
	       print("[!] It should be: 0x??\n")
	       exit(1)
        return ret

    def connectionHandler(self, connection):

        try:
            # Skip Connections with no data transferred
            if connection.clientbytes + connection.serverbytes < 1:
                return

            # Update Connection Counter
            self.connectionCount += 1

            # Connection Header Information
            self.out.write("Connection %d (%s)\n" % (
                self.connectionCount, str(connection.proto)), formatTag='H1')
            self.out.write("Start: %s UTC\n  End: %s UTC\n" % (datetime.datetime.utcfromtimestamp(
                connection.starttime), datetime.datetime.utcfromtimestamp(connection.endtime)), formatTag='H2')
            self.out.write("%s:%s -> %s:%s (%d bytes)\n" % (connection.clientip, connection.clientport,
                                                            connection.serverip, connection.serverport, connection.clientbytes), formatTag="H2", direction="cs")
            self.out.write("%s:%s -> %s:%s (%d bytes)\n\n" % (connection.serverip, connection.serverport,
                                                              connection.clientip, connection.clientport, connection.serverbytes), formatTag="H2", direction="sc")


            clientip = struct.unpack('I', socket.inet_aton(connection.clientip))[0]
            serverip = struct.unpack('I', socket.inet_aton(connection.serverip))[0]
            outdata = struct.pack('IIIHHI', len(connection.blobs), clientip, serverip, connection.clientport, connection.serverport, int(connection.starttime))
            outdata += struct.pack('I', len(connection.pkts))
            for i in connection.pkts:
                outdata += struct.pack('I', i)

            for i in connection.blobs:
                pad = self.check_padding()
                packetdata = i.data(padding=pad)
                packetout = i.direction[0] + struct.pack('I', len(packetdata)) + packetdata
                outdata += packetout
            self.dumpfiles.write(outdata)
            self.connlen.append(len(outdata))

            #self.out.write(
            #    connection, hex=self.hex, time=self.time, encoding=self.encoding)
            if self.data_missing_message:
                self.out.write(
                    self.data_missing_message + "\n", level=logging.WARNING, time=self.time)
            self.data_missing_message = ''

            # Line break before next session
            self.out.write("\n\n")

        except KeyboardInterrupt:
            raise
        except:
            print 'Error in connectionHandler: ', sys.exc_info()[1]
            traceback.print_exc(file=sys.stdout)


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
