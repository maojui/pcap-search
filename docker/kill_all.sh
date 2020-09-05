#!/usr/bin/env sh

docker rm -f $(docker ps -a | grep pcap-search | awk '{print $1}')