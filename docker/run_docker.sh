#!/usr/bin/env sh

if [ "$#" -ne 1 ]; then
    echo "Usage: ./run_docker.sh <pcap dir to be mounted>"
    exit 1
fi

if [ -d "$1" ]; then
    docker run -d -v $1:/mnt/pcap -p 4568:4568 --name "pcap0" pcap-search
else
    echo "Invalid path: $1"
fi
