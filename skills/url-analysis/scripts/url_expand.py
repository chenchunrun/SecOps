#!/usr/bin/env python3
"""
短链接展开工具
追踪短链接的重定向链，展开到最终目标 URL
"""

import argparse
import json
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse

# 尝试导入 requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class URLExpander:
    """短链接展开器"""

    # 已知的短链接服务
    SHORT_URL_SERVICES = {
        # 国际服务
        'bit.ly', 'j.mp', 'bitly.com',
        'tinyurl.com',
        't.co',
        'goo.gl',
        'ow.ly',
        'buff.ly',
        'adf.ly',
        'cutt.ly',
        'rb.gy',
        'is.gd', 'v.gd',
        'short.io',
        'rebrand.ly',
        'bl.ink',
        'soo.gd',
        'clck.ru',

        # 中国服务
        't.cn',  # 新浪
        'url.cn',  # 腾讯
        'dwz.cn',  # 百度
        'c7.gg',
        'suo.im',
        'mrw.so',
        '985.so',
        'rrd.me',
    }

    # 用户代理
    USER_AGENT = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )

    def __init__(self, timeout: int = 10, max_redirects: int = 10):
        self.timeout = timeout
        self.max_redirects = max_redirects

    def is_short_url(self, url: str) -> bool:
        """检查是否是短链接服务"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # 移除 www 前缀
            if domain.startswith('www.'):
                domain = domain[4:]

            return domain in self.SHORT_URL_SERVICES
        except Exception:
            return False

    def expand(self, url: str) -> Dict:
        """
        展开短链接

        Args:
            url: 短链接 URL

        Returns:
            dict: 展开结果
        """
        result = {
            'original_url': url,
            'is_short_url': self.is_short_url(url),
            'expanded': False,
            'final_url': None,
            'redirect_chain': [],
            'redirect_count': 0,
            'error': None,
            'warnings': [],
        }

        if not HAS_REQUESTS:
            result['error'] = "需要安装 requests 库: pip install requests"
            return result

        # 确保 URL 有协议
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            result['redirect_chain'] = self._follow_redirects(url)
            result['redirect_count'] = len(result['redirect_chain']) - 1

            if result['redirect_chain']:
                result['final_url'] = result['redirect_chain'][-1]['url']
                result['expanded'] = True

            # 检测可疑重定向
            if result['redirect_count'] > 5:
                result['warnings'].append(f"重定向次数过多: {result['redirect_count']}")

            # 检测协议降级
            for i in range(1, len(result['redirect_chain'])):
                prev = result['redirect_chain'][i-1]['url']
                curr = result['redirect_chain'][i]['url']
                if prev.startswith('https://') and curr.startswith('http://'):
                    result['warnings'].append("检测到 HTTPS 降级为 HTTP")

        except requests.exceptions.TooManyRedirects:
            result['error'] = "重定向次数超过限制"
        except requests.exceptions.Timeout:
            result['error'] = "请求超时"
        except requests.exceptions.ConnectionError as e:
            result['error'] = f"连接错误: {e}"
        except Exception as e:
            result['error'] = f"未知错误: {e}"

        return result

    def _follow_redirects(self, url: str) -> List[Dict]:
        """追踪重定向链"""
        chain = []
        current_url = url
        visited = set()

        for i in range(self.max_redirects):
            if current_url in visited:
                break
            visited.add(current_url)

            try:
                response = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=self.timeout,
                    headers={'User-Agent': self.USER_AGENT},
                    verify=True,
                )

                chain.append({
                    'step': i + 1,
                    'url': current_url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                })

                # 检查是否有重定向
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location')
                    if location:
                        # 处理相对 URL
                        if location.startswith('/'):
                            parsed = urlparse(current_url)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        current_url = location
                    else:
                        break
                else:
                    break

            except Exception:
                # 如果 HEAD 失败，尝试 GET
                try:
                    response = requests.get(
                        current_url,
                        allow_redirects=False,
                        timeout=self.timeout,
                        headers={'User-Agent': self.USER_AGENT},
                        stream=True,
                    )
                    response.close()

                    chain.append({
                        'step': i + 1,
                        'url': current_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                    })

                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get('Location')
                        if location:
                            if location.startswith('/'):
                                parsed = urlparse(current_url)
                                location = f"{parsed.scheme}://{parsed.netloc}{location}"
                            current_url = location
                        else:
                            break
                    else:
                        break
                except Exception:
                    chain.append({
                        'step': i + 1,
                        'url': current_url,
                        'status_code': 0,
                        'error': 'Request failed',
                    })
                    break

        return chain

    def expand_batch(self, urls: List[str]) -> List[Dict]:
        """批量展开短链接"""
        return [self.expand(url) for url in urls]


def format_result(result: Dict, output_format: str = 'text') -> str:
    """格式化输出"""
    if output_format == 'json':
        return json.dumps(result, ensure_ascii=False, indent=2)

    lines = []
    lines.append("=" * 60)
    lines.append("短链接展开结果")
    lines.append("=" * 60)
    lines.append("")

    lines.append(f"原始 URL: {result['original_url']}")
    lines.append(f"短链接服务: {'是' if result['is_short_url'] else '否'}")

    if result['error']:
        lines.append(f"错误: {result['error']}")
        return '\n'.join(lines)

    lines.append(f"展开成功: {'是' if result['expanded'] else '否'}")
    lines.append(f"重定向次数: {result['redirect_count']}")

    if result['final_url']:
        lines.append(f"最终 URL: {result['final_url']}")

    if result['redirect_chain']:
        lines.append("")
        lines.append("【重定向链】")
        for step in result['redirect_chain']:
            status = step.get('status_code', '?')
            lines.append(f"  [{step['step']}] {status} -> {step['url']}")

    if result['warnings']:
        lines.append("")
        lines.append("【警告】")
        for warning in result['warnings']:
            lines.append(f"  - {warning}")

    lines.append("")
    lines.append("=" * 60)

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='短链接展开工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s "https://bit.ly/xxxxx"
  %(prog)s "https://t.cn/xxxxx"
  %(prog)s -f short_urls.txt -o json
        '''
    )
    parser.add_argument('url', nargs='?', help='要展开的短链接')
    parser.add_argument('-f', '--file', help='从文件读取 URL 列表')
    parser.add_argument('-o', '--output', choices=['text', 'json'],
                        default='text', help='输出格式')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='请求超时时间（秒）')
    parser.add_argument('--max-redirects', type=int, default=10,
                        help='最大重定向次数')
    parser.add_argument('--check-only', action='store_true',
                        help='仅检查是否是短链接，不展开')

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    expander = URLExpander(timeout=args.timeout, max_redirects=args.max_redirects)

    if args.check_only:
        # 仅检查模式
        if args.file:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                is_short = expander.is_short_url(url)
                print(f"{'[短链接]' if is_short else '[普通]  '} {url}")
        else:
            is_short = expander.is_short_url(args.url)
            print(f"是短链接: {'是' if is_short else '否'}")
        sys.exit(0)

    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]

        results = expander.expand_batch(urls)

        if args.output == 'json':
            print(json.dumps(results, ensure_ascii=False, indent=2))
        else:
            for result in results:
                print(format_result(result, args.output))
                print()
    else:
        result = expander.expand(args.url)
        print(format_result(result, args.output))

        if result['error']:
            sys.exit(1)
        if result['warnings']:
            sys.exit(2)


if __name__ == '__main__':
    main()
