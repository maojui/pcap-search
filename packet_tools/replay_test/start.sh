#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: ./start.sh <pcap file>"
    exit 1
fi

if [ -f "$1" ]; then
    ./stream.py $1
else
    echo "Invalid path: $1"
fi

./test_crash.py ./pcapio

