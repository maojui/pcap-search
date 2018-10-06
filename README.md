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
./run_docker.sh [absolute path to pcap dir to be mounted] [port to mounted]
```
This will mount the pcap directory to `/mnt/pcap` inside the docker  
Now you can open the browser and connect to `<HOST>:port` for pcap searching

If you leave port blank, the default is mounted at 4568.

## Usage  
### Notice
* **All the pcap file should be named `XXX.cap` ( filename extension has to be `.cap` )**  
* **The structure of the pcap directory has to be something like this**:  
```
. <-- the directory you want to mount
├── service1
│   ├── 0.cap
│   ├── 1.cap
│   ├── 2.cap
│   ├── 3.cap
│   ├── 4.cap
├── service2
│   ├── 5.cap
│   ├── 6.cap
│   ├── 7.cap
│   ├── 8.cap
│   ├── 9.cap
...........
```
### Basic usage  
![context img](/img/1.png?raw=true)  
### View  
![context img](/img/2.PNG?raw=true)  
* The `Python Simple` & `Python Diff` is a simple python script for replay attack, base on [pwntools](https://github.com/arthaud/python3-pwntools)

### pwntools installation 

```bash
apt-get update
apt-get install python3 python3-dev python3-pip git
pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git
```

### Packet Extractor

[packet_tools](https://github.com/maojui/pcap-search-docker/tree/master/packet_tools)