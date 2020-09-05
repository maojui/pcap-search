#!/usr/bin/env sh

# your host IP
work_host=10.217.0.1

if [ "$#" -lt 1 ]; then
    echo "\nUsage: ./run_docker.sh [pcap dir to be mounted] [port] [name]"
    echo "\nDefault value:"
    echo "    port : 8000"
    echo "    name : pcap0"
    exit 1
fi

if [ -d "$1" ]; then
    port=${2:-8000}
    name=${3:-pcap0}
    echo "Running pcap-search as $name @ port $port"
    #docker run --cpus=8 --memory=16G --net=isolated -d -v $1:/mnt/pcap -p $work_host:$port:4568 --name "$name" pcap-search
    docker run -d -v $1:/mnt/pcap -p $port:4568 --name "$name" pcap-search
else
    echo "Invalid path: $1"
fi
