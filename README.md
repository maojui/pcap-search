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
./run_docker.sh [the pcap directory you want to mount] [port] [name]
```
* This will create a docker container base on the pcap-search docker image, and mount the pcap directory to `/mnt/pcap` inside the container.  
    - The pcap directory has to be a specific format, check the [Usage](#usage) section for more details.
* If the `name` argument is not specified, it will use the default name `pcap0`.  
* Now you can open the browser and connect to `<HOST>:<port>` for pcap searching  
    - If the `port` argument is not specified, it will use the default port `8000`

### Notice
- Before you execute `run_docker.sh`, you'll have to modified the `work_host` variable to the host IP

- **Also, make sure you use the following line to launch the docker in `run_docker.sh`**

```bash
docker run --cpus=8 --memory=16G --net=isolated -d -v $1:/mnt/pcap -p $work_host:$port:4568 --name "$name" pcap-search
```
`--cpus` & `--memory` are for limiting the resource of each docker  
`--net=isolated` is for limiting the IPs that can connect to pcap-search ( ping lsc for more details )

## Access the docker  
```bash
cd docker
./exec_docker.sh [name]
```
* This will access the specified docker container and execute `/bin/bash`.  
    - If the `name` argument is not specified, it will use the default name `pcap0`.  


## Usage  
### Notice ( Important )
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
![context img](img/1.png?raw=true)  
### Support REGEX searching  
![context img](img/4.PNG?raw=true)  
### View  
String view  
![context img](img/2.PNG?raw=true)  
Python script for replay attack ( base on [pwntools](https://github.com/Gallopsled/pwntools) )
![context img](img/3.PNG?raw=true)
#### Python Simple
Script that attack directly.  
Usage: `<script_name> [host] [port]`  
You can also check the usage by just running `<script name>` (no argument).  
#### Python Simple (Zig Zag)  
The word `Zig-Zag` indicates that the script will attack the server using the following patterns:
```
send --> recv --> send --> recv...
```   
Python Simple may contain patterns like `send --> send --> recv --> recv...`  
The `zig-zag` mode merge the packets with the same direction, and send/recv the packet only if the direction is changed.  
#### Python Diff
Script that shows the diff info of the receive packets.  
For example, you expect the server will send you `0x41414141`, but it sends you `0x42424242` instead.  
Python Diff will show the diff message if it doesn't receive the expected packet.  
This is useful when we're attacking the service that requires address leaking.  

For usage, it will print out the usage everytime the script runs.  
Usage: `<script_name> [host] [port] [idr]`  
You can print out the diff info if you enable the `d` option.
#### Python Diff (Zig Zag)
Script that shows the diff info of the receive packets, with `zig-zag` mode.
 
