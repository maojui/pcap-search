#!/usr/bin/env sh

# access pcap-search container with /bin/bash

name=${1:-pcap0}
echo "Accessing $name..."
docker exec -it $name /bin/bash
