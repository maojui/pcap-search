#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
import os
import threading
import shutil

# command : ./exp.py pcap/pcap2io/


def exploit(PORT, root, f, crashpath, flagpath,executed_path):
    with open(root+"/"+f, 'rb') as fp:
        filedata = fp.read()
    datas = filedata.split("BFSBFSBFSBFS")[1:]

    shutil.move(root+"/"+f,executed_path+"/"+f )
    p = remote("127.0.0.1", PORT)
    try:
        for data in datas:
          if data[0] == '0' :
              data = p.recvrepeat(0.1)
              if "" in data:
                  print("find flag!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                  with open("/".join([flagpath,f]),'wb') as fp:
                      fp.write(filedata)
                  p.close()
                  return
              else:
                  pass
          else:
              p.send(data[1:])
              time.sleep(0.01)
    except:
        print("maybe crash")
        with open("/".join([crashpath,f]),'wb') as fp:
            fp.write(filedata)
    p.close()



if __name__ == '__main__':

    filepath = sys.argv[1]
    if filepath[-1] == "/":
        filepath = filepath[:-1]
    threads = []
    count = 0
    for root, dirs, files in os.walk(filepath):
        root_split = root.split("/")
        if len(root_split) < 3 or not root_split[-2].isdigit():
            continue
        crash_path = "/".join(["/".join(root_split[:-2]),"".join([root_split[-2],"_crash"]),root_split[-1]])
        if not os.path.isdir(crash_path) :
            os.makedirs(crash_path)
        flag_path = "/".join(["/".join(root_split[:-2]),"".join([root_split[-2],"_flag"]),root_split[-1]])
        if not os.path.isdir(flag_path) :
            os.makedirs(flag_path)
        executed_path = "/".join(["Executed",root_split[-2],root_split[-1]])
        if not os.path.isdir(executed_path) :
            os.makedirs(executed_path)
        for i in files:
            threads.append(threading.Thread(target = exploit, args = (root_split[-2],root,i,crash_path,flag_path,executed_path)))
            threads[count].start()
            count += 1
    for i in range(count):
        threads[i].join()
    print("Done.")

