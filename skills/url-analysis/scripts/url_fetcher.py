#!/usr/bin/env python3
"""
URL 内容获取与重定向追踪模块
支持 HTTP 重定向和简单 JS 跳转检测

环境变量配置：
  URL_ANALYSIS_TIMEOUT      - HTTP 请求超时时间（秒），默认 30
  URL_ANALYSIS_MAX_REDIRECTS - 最大重定向次数，默认 10
  URL_ANALYSIS_USER_AGENT   - User-Agent 类型（chrome/firefox/safari/googlebot/curl），默认 chrome
  URL_ANALYSIS_VERIFY_SSL   - 是否验证 SSL 证书（true/false），默认 false
"""

import os
import re
import sys
import json
import argparse
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from datetime import datetime


# ============ 环境变量配置 ============
def _get_env_int(key: str, default: int) -> int:
    """从环境变量获取整数值"""
    val = os.environ.get(key, '')
    if val:
        try:
            return int(val)
        except ValueError:
            print(f"警告: 环境变量 {key}={val} 不是有效整数，使用默认值 {default}", file=sys.stderr)
    return default


def _get_env_bool(key: str, default: bool) -> bool:
    """从环境变量获取布尔值"""
    val = os.environ.get(key, '').lower()
    if val in ('true', '1', 'yes', 'on'):
        return True
    elif val in ('false', '0', 'no', 'off'):
        return False
    return default


def _get_env_str(key: str, default: str) -> str:
    """从环境变量获取字符串值"""
    return os.environ.get(key, default) or default


# 默认配置（可通过环境变量覆盖）
DEFAULT_TIMEOUT = _get_env_int('URL_ANALYSIS_TIMEOUT', 30)
DEFAULT_MAX_REDIRECTS = _get_env_int('URL_ANALYSIS_MAX_REDIRECTS', 10)
DEFAULT_USER_AGENT = _get_env_str('URL_ANALYSIS_USER_AGENT', 'chrome')
DEFAULT_VERIFY_SSL = _get_env_bool('URL_ANALYSIS_VERIFY_SSL', False)

try:
    import requests
    from requests.exceptions import RequestException, Timeout, SSLError
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class RedirectHop:
    """重定向跳转记录"""
    url: str
    status_code: int
    redirect_type: str  # http_301, http_302, http_303, http_307, js_redirect, meta_refresh
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class FetchResult:
    """URL 获取结果"""
    original_url: str
    final_url: str
    success: bool
    status_code: int = 0
    content_type: str = ''
    content_length: int = 0
    html_content: str = ''
    title: str = ''
    redirect_chain: List[RedirectHop] = field(default_factory=list)
    total_redirects: int = 0
    has_js_redirect: bool = False
    js_redirect_target: str = ''
    has_meta_refresh: bool = False
    meta_refresh_target: str = ''
    response_time_ms: int = 0
    ssl_verified: bool = True
    error: str = ''
    headers: Dict[str, str] = field(default_factory=dict)


class URLFetcher:
    """
    URL 内容获取器
    支持重定向追踪、JS 跳转检测、内容提取
    """

    # 常见 User-Agent
    USER_AGENTS = {
        'chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'firefox': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'safari': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'googlebot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'curl': 'curl/8.0.0',
    }

    # JS 跳转模式
    JS_REDIRECT_PATTERNS = [
        # window.location 系列
        r'window\.location\s*=\s*["\']([^"\']+)["\']',
        r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
        r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
        r'window\.location\.assign\s*\(\s*["\']([^"\']+)["\']\s*\)',
        # location 简写
        r'location\s*=\s*["\']([^"\']+)["\']',
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
        r'location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
        # document.location
        r'document\.location\s*=\s*["\']([^"\']+)["\']',
        r'document\.location\.href\s*=\s*["\']([^"\']+)["\']',
        # top.location (常用于框架逃逸)
        r'top\.location\s*=\s*["\']([^"\']+)["\']',
        r'top\.location\.href\s*=\s*["\']([^"\']+)["\']',
        # self.location
        r'self\.location\s*=\s*["\']([^"\']+)["\']',
    ]

    # Meta refresh 模式
    META_REFRESH_PATTERN = r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^"\'\s>]+)'

    def __init__(self, timeout: int = None, max_redirects: int = None,
                 user_agent: str = None, verify_ssl: bool = None):
        """
        初始化 URL 获取器

        Args:
            timeout: 请求超时时间（秒），默认从环境变量 URL_ANALYSIS_TIMEOUT 读取，未设置则为 30s
            max_redirects: 最大重定向次数，默认从环境变量 URL_ANALYSIS_MAX_REDIRECTS 读取，未设置则为 10
            user_agent: User-Agent 类型或自定义字符串，默认从环境变量 URL_ANALYSIS_USER_AGENT 读取
            verify_ssl: 是否验证 SSL 证书，默认从环境变量 URL_ANALYSIS_VERIFY_SSL 读取
        """
        # 使用环境变量默认值
        timeout = timeout if timeout is not None else DEFAULT_TIMEOUT
        max_redirects = max_redirects if max_redirects is not None else DEFAULT_MAX_REDIRECTS
        user_agent = user_agent if user_agent is not None else DEFAULT_USER_AGENT
        verify_ssl = verify_ssl if verify_ssl is not None else DEFAULT_VERIFY_SSL
        if not HAS_REQUESTS:
            raise ImportError("需要安装 requests 库: pip install requests")

        self.timeout = timeout
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl

        # 设置 User-Agent
        if user_agent in self.USER_AGENTS:
            self.user_agent = self.USER_AGENTS[user_agent]
        else:
            self.user_agent = user_agent

        # 创建 session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

    def fetch(self, url: str, follow_js_redirect: bool = True) -> FetchResult:
        """
        获取 URL 内容

        Args:
            url: 要获取的 URL
            follow_js_redirect: 是否追踪 JS 跳转

        Returns:
            FetchResult: 获取结果
        """
        result = FetchResult(
            original_url=url,
            final_url=url,
            success=False,
        )

        # 确保 URL 有协议
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        redirect_chain = []
        current_url = url
        visited_urls = set()

        try:
            start_time = datetime.now()

            # 手动追踪重定向
            for i in range(self.max_redirects + 1):
                if current_url in visited_urls:
                    result.error = "检测到重定向循环"
                    break
                visited_urls.add(current_url)

                try:
                    response = self.session.get(
                        current_url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        verify=self.verify_ssl,
                    )
                except SSLError as e:
                    result.ssl_verified = False
                    # 重试不验证 SSL
                    response = self.session.get(
                        current_url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        verify=False,
                    )

                # 记录 HTTP 重定向
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location', '')
                    if location:
                        # 处理相对 URL
                        next_url = urljoin(current_url, location)
                        redirect_chain.append(RedirectHop(
                            url=current_url,
                            status_code=response.status_code,
                            redirect_type=f'http_{response.status_code}',
                            headers=dict(response.headers),
                        ))
                        current_url = next_url
                        continue

                # 非重定向响应，处理内容
                result.status_code = response.status_code
                result.final_url = current_url
                result.headers = dict(response.headers)
                result.content_type = response.headers.get('Content-Type', '')
                result.content_length = len(response.content)

                # 获取 HTML 内容
                if 'text/html' in result.content_type or not result.content_type:
                    try:
                        result.html_content = response.text
                    except:
                        result.html_content = response.content.decode('utf-8', errors='ignore')

                    # 提取 title
                    result.title = self._extract_title(result.html_content)

                    # 检测 JS 跳转
                    js_target = self._detect_js_redirect(result.html_content)
                    if js_target:
                        result.has_js_redirect = True
                        result.js_redirect_target = urljoin(current_url, js_target)

                        # 是否继续追踪 JS 跳转
                        if follow_js_redirect and i < self.max_redirects:
                            redirect_chain.append(RedirectHop(
                                url=current_url,
                                status_code=response.status_code,
                                redirect_type='js_redirect',
                                headers=dict(response.headers),
                            ))
                            current_url = result.js_redirect_target
                            continue

                    # 检测 meta refresh
                    meta_target = self._detect_meta_refresh(result.html_content)
                    if meta_target:
                        result.has_meta_refresh = True
                        result.meta_refresh_target = urljoin(current_url, meta_target)

                        if follow_js_redirect and i < self.max_redirects:
                            redirect_chain.append(RedirectHop(
                                url=current_url,
                                status_code=response.status_code,
                                redirect_type='meta_refresh',
                                headers=dict(response.headers),
                            ))
                            current_url = result.meta_refresh_target
                            continue

                # 成功完成
                result.success = True
                break

            end_time = datetime.now()
            result.response_time_ms = int((end_time - start_time).total_seconds() * 1000)
            result.redirect_chain = redirect_chain
            result.total_redirects = len(redirect_chain)

            # 如果有未追踪的 JS 跳转，获取最终内容
            if result.has_js_redirect and result.final_url != result.js_redirect_target:
                result.final_url = result.js_redirect_target

        except Timeout:
            result.error = f"请求超时 ({self.timeout}s)"
        except RequestException as e:
            result.error = f"请求失败: {str(e)}"
        except Exception as e:
            result.error = f"未知错误: {str(e)}"

        return result

    def _extract_title(self, html: str) -> str:
        """提取页面标题"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ''

    def _detect_js_redirect(self, html: str) -> Optional[str]:
        """
        检测 JavaScript 跳转

        Args:
            html: HTML 内容

        Returns:
            跳转目标 URL 或 None
        """
        for pattern in self.JS_REDIRECT_PATTERNS:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                target = match.group(1)
                # 过滤掉动态生成的 URL
                if not any(x in target for x in ['javascript:', 'void(', '+']):
                    return target
        return None

    def _detect_meta_refresh(self, html: str) -> Optional[str]:
        """
        检测 meta refresh 跳转

        Args:
            html: HTML 内容

        Returns:
            跳转目标 URL 或 None
        """
        match = re.search(self.META_REFRESH_PATTERN, html, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def fetch_with_multiple_ua(self, url: str, ua_list: List[str] = None) -> Dict[str, FetchResult]:
        """
        使用多个 User-Agent 获取 URL，检测 UA 歧视

        Args:
            url: 要获取的 URL
            ua_list: User-Agent 列表

        Returns:
            {ua_name: FetchResult} 字典
        """
        if ua_list is None:
            ua_list = ['chrome', 'googlebot', 'curl']

        results = {}
        original_ua = self.user_agent

        for ua_name in ua_list:
            if ua_name in self.USER_AGENTS:
                self.session.headers['User-Agent'] = self.USER_AGENTS[ua_name]
            else:
                self.session.headers['User-Agent'] = ua_name

            results[ua_name] = self.fetch(url, follow_js_redirect=False)

        # 恢复原始 UA
        self.session.headers['User-Agent'] = original_ua

        return results


def format_result(result: FetchResult, verbose: bool = False) -> str:
    """格式化输出结果"""
    lines = []
    lines.append("=" * 60)
    lines.append("URL 内容获取报告")
    lines.append("=" * 60)
    lines.append("")

    lines.append("【基本信息】")
    lines.append(f"  原始 URL: {result.original_url}")
    lines.append(f"  最终 URL: {result.final_url}")
    lines.append(f"  状态码: {result.status_code}")
    lines.append(f"  成功: {'是' if result.success else '否'}")
    if result.error:
        lines.append(f"  错误: {result.error}")
    lines.append("")

    if result.redirect_chain:
        lines.append("【重定向链】")
        for i, hop in enumerate(result.redirect_chain, 1):
            lines.append(f"  {i}. [{hop.redirect_type}] {hop.url}")
        lines.append(f"  → 最终: {result.final_url}")
        lines.append("")

    if result.has_js_redirect:
        lines.append("【JS 跳转检测】")
        lines.append(f"  检测到 JS 跳转: {result.js_redirect_target}")
        lines.append("")

    if result.has_meta_refresh:
        lines.append("【Meta Refresh 检测】")
        lines.append(f"  检测到 Meta 跳转: {result.meta_refresh_target}")
        lines.append("")

    lines.append("【响应信息】")
    lines.append(f"  Content-Type: {result.content_type}")
    lines.append(f"  内容长度: {result.content_length} bytes")
    lines.append(f"  响应时间: {result.response_time_ms} ms")
    lines.append(f"  SSL 验证: {'通过' if result.ssl_verified else '失败/跳过'}")
    if result.title:
        lines.append(f"  页面标题: {result.title}")
    lines.append("")

    if verbose and result.html_content:
        lines.append("【内容预览】")
        preview = result.html_content[:500].replace('\n', ' ').replace('\r', '')
        lines.append(f"  {preview}...")
        lines.append("")

    lines.append("=" * 60)
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='URL 内容获取与重定向追踪',
        epilog='''
环境变量配置（优先级低于命令行参数）：
  URL_ANALYSIS_TIMEOUT       超时时间（秒），默认 30
  URL_ANALYSIS_MAX_REDIRECTS 最大重定向次数，默认 10
  URL_ANALYSIS_USER_AGENT    User-Agent 类型，默认 chrome
  URL_ANALYSIS_VERIFY_SSL    是否验证 SSL（true/false），默认 false
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='要获取的 URL')
    parser.add_argument('-t', '--timeout', type=int, default=None,
                        help=f'超时时间(秒)，默认 {DEFAULT_TIMEOUT}')
    parser.add_argument('-m', '--max-redirects', type=int, default=None,
                        help=f'最大重定向次数，默认 {DEFAULT_MAX_REDIRECTS}')
    parser.add_argument('-u', '--user-agent', default=None,
                        choices=['chrome', 'firefox', 'safari', 'googlebot', 'curl'],
                        help=f'User-Agent 类型，默认 {DEFAULT_USER_AGENT}')
    parser.add_argument('--no-follow-js', action='store_true', help='不追踪 JS 跳转')
    parser.add_argument('--multi-ua', action='store_true', help='使用多个 UA 测试')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text')
    parser.add_argument('--save-html', help='保存 HTML 内容到文件')

    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("错误: 需要安装 requests 库", file=sys.stderr)
        print("运行: pip install requests", file=sys.stderr)
        sys.exit(1)

    # URLFetcher 会自动使用环境变量默认值
    fetcher = URLFetcher(
        timeout=args.timeout,  # None 时使用环境变量
        max_redirects=args.max_redirects,  # None 时使用环境变量
        user_agent=args.user_agent,  # None 时使用环境变量
    )

    if args.multi_ua:
        results = fetcher.fetch_with_multiple_ua(args.url)
        if args.output == 'json':
            output = {ua: {
                'final_url': r.final_url,
                'status_code': r.status_code,
                'title': r.title,
                'content_length': r.content_length,
            } for ua, r in results.items()}
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            print("=" * 60)
            print("多 User-Agent 测试结果")
            print("=" * 60)
            for ua, r in results.items():
                status = '[+]' if r.success else '[-]'
                print(f"  [{ua}] {status} {r.status_code} - {r.title[:30] if r.title else 'N/A'}")
    else:
        result = fetcher.fetch(args.url, follow_js_redirect=not args.no_follow_js)

        if args.output == 'json':
            output = {
                'original_url': result.original_url,
                'final_url': result.final_url,
                'success': result.success,
                'status_code': result.status_code,
                'content_type': result.content_type,
                'content_length': result.content_length,
                'title': result.title,
                'redirect_chain': [
                    {'url': h.url, 'status': h.status_code, 'type': h.redirect_type}
                    for h in result.redirect_chain
                ],
                'total_redirects': result.total_redirects,
                'has_js_redirect': result.has_js_redirect,
                'js_redirect_target': result.js_redirect_target,
                'has_meta_refresh': result.has_meta_refresh,
                'meta_refresh_target': result.meta_refresh_target,
                'response_time_ms': result.response_time_ms,
                'error': result.error,
            }
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            print(format_result(result, verbose=args.verbose))

        if args.save_html and result.html_content:
            with open(args.save_html, 'w', encoding='utf-8') as f:
                f.write(result.html_content)
            print(f"HTML 已保存到: {args.save_html}")

        # 返回码
        if not result.success:
            sys.exit(1)
        if result.total_redirects > 3:
            sys.exit(2)  # 多重跳转警告


if __name__ == '__main__':
    main()
