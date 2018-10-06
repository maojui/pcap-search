#!/usr/bin/env sh

if [ "$(uname)" == "Darwin" ]; then
    cur_dir=$(pwd)
    docker build --rm -t pcap-search -f $cur_dir/Dockerfile $cur_dir/../
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    cur_dir=$(dirname $(readlink -f $0))
    docker build --rm -t pcap-search -f $cur_dir/Dockerfile $cur_dir/../
fi
