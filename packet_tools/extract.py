import os
import time
import subprocess

PCAP_FOLDER = "/home/public/pcap/"
SLEEP = 3
START = 2

for pname in sorted(os.listdir(PCAP_FOLDER))[START:] :
    pcap = os.path.join(PCAP_FOLDER, pname)
    print(START, end=' ', flush=True)
    subprocess.Popen(['sudo', 'python3', 'stream.py', pcap, ])
    START += 1
    time.sleep(3)


