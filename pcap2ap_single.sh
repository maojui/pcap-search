#!/usr/bin/env sh

# cap2ap
if [ "$#" -eq 2 ]; then
    /root/pcap-search/dshell-defcon/dshell-decode -d stream2dump --stream2dump_outfiles=$2 $1
    exit 0
fi
# cap2ap with padding
if [ "$#" -eq 3 ]; then
    /root/pcap-search/dshell-defcon/dshell-decode -d stream2dump --stream2dump_outfiles=$2 --stream2dump_padding=$3 $1
    exit 0
fi

echo "Usage: $0 <.cap filepath> <.cap.ap filepath>"
exit 1
