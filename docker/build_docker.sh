#!/usr/bin/env sh
cur_dir=$(dirname $(readlink -f $0))
docker build --rm -t pcap-search -f $cur_dir/Dockerfile $cur_dir/../
