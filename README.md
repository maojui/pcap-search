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


