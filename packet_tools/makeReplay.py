import os
import hashlib
import glob
import threading
import subprocess

EXTRACTED = '/home/public/extracted/'
PROB = 'blackjack/'
PCAP = '2019-12-14_10_55_19/'

SAVED_TO = '/home/public/replay/'
FLAG = b'HITCON'


def test() :
    os.chdir('../dshell-defcon/')
    folder = os.path.join(EXTRACTED, PROB, PCAP)
    targets = glob.glob(folder + '*.ap')
    for t in targets :
        data = open(t,'rb').read()
        if not (FLAG in data) : continue 
        digest = hashlib.md5(data).hexdigest()
        save_folder = os.path.join(SAVED_TO, PROB)
        os.makedirs(save_folder, exist_ok=True) 
        out = digest + '.py'
        if out in map(os.path.basename, glob.glob(save_folder + '**/*.py', recursive=True)) : continue
        out = os.path.join(save_folder, out) 
        subprocess.Popen(['sudo', 'python2', 'offset2stream.py', t, '0', 'pythonsimple', '99', out])

t = threading.Thread(target=test)
t.start()

