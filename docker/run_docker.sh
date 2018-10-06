#!/usr/bin/env sh

GREEN='\033[0;32m'

if [ "$#" -ne 1 ] && [ "$#" -ne 2 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    echo "Usage: ./run_docker.sh [absolute path to pcap dir to be mounted] [port to mounted]"
    exit 1
fi

if [ -d $1 ] && [ $2 ] 

then
    docker run -d -v $1:/mnt/pcap -p $2:4568 pcap-search;
    echo "pcap-search started: $GREEN<http://localhost:$2>";
elif [ -d $1 ] 
then
    docker run -d -v $1:/mnt/pcap -p 4568:4568 pcap-search
    echo "pcap-search started: $GREEN<http://localhost:4568>"
else
    echo "Invalid path & port: [path [port]]"
fi
