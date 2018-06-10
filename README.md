# pcap-search docker

Deploy MaskRay/pcap-search in a docker container.

## Build
```bash
cd docker
./build_docker.sh
```

## Run

```bash
cd docker
./run_docker.sh <the pcap directory you want to mount>
```
This will create a container with the name `pcap0`, and mount the pcap directory to `/mnt/pcap` inside the docker  
Now you can open the browser and connect to `<HOST>:4568` for pcap searching
