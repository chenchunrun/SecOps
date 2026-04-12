#!/usr/bin/env python3
"""
邮箱文件中转站下载模块
支持 163 邮箱和 QQ 邮箱的文件中转站链接解析与下载
"""

import re
import sys
import json
import hashlib
import argparse
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field

try:
    import requests
    from requests.exceptions import RequestException, Timeout
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ============================================================
# 数据模型
# ============================================================

@dataclass
class DownloadResult:
    """下载结果"""
    success: bool = False
    url: str = ''
    download_url: str = ''
    filename: str = ''
    size: int = 0
    content_type: str = ''
    md5: str = ''
    sha256: str = ''
    path: str = ''
    error: str = ''
    provider: str = ''  # 163 / qq


# ============================================================
# 邮箱中转站识别
# ============================================================

# 支持的邮箱中转站 URL 模式
MAIL_PATTERNS = {
    '163': [
        r'https?://mail\.163\.com/large-attachment-download/index\.html',
        r'https?://dashi\.163\.com/html/cloud-attachment-download',
    ],
    'qq': [
        r'https?://wx\.mail\.qq\.com/ftn/download',
        r'https?://mail\.qq\.com/cgi-bin/ftnExs_download',
    ],
}


def detect_mail_provider(url: str) -> Optional[str]:
    """
    检测 URL 属于哪个邮箱服务商

    Args:
        url: 待检测的 URL

    Returns:
        服务商标识 ('163', 'qq') 或 None
    """
    for provider, patterns in MAIL_PATTERNS.items():
        for pattern in patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return provider
    return None


def is_mail_download_url(url: str) -> bool:
    """判断是否为邮箱中转站链接"""
    return detect_mail_provider(url) is not None


# ============================================================
# 163 邮箱中转站
# ============================================================

class NetEasyDownloader:
    """163 邮箱文件中转站下载器"""

    FILEHUB_API = "https://mail.163.com/filehub/bg/dl/prepare"

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
        })

    def extract_link_key(self, url: str) -> str:
        """
        从 URL 中提取 linkKey

        支持格式:
        - mail.163.com?file=<linkKey>
        - dashi.163.com?key=<linkKey>
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if parsed.netloc == 'mail.163.com':
            return params.get('file', [''])[0]
        elif parsed.netloc == 'dashi.163.com':
            return params.get('key', [''])[0]
        return ''

    def get_download_url(self, url: str) -> Tuple[str, str]:
        """
        获取真实下载链接

        Args:
            url: 分享链接

        Returns:
            (download_url, error_msg)
        """
        link_key = self.extract_link_key(url)
        if not link_key:
            return '', '无法从 URL 中提取 linkKey'

        try:
            resp = self.session.post(
                self.FILEHUB_API,
                json={"linkKey": link_key},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                download_url = data.get('data', {}).get('downloadUrl', '')
                if download_url:
                    return download_url, ''
                return '', f"API 返回无效: {data}"
            return '', f"API 请求失败: HTTP {resp.status_code}"
        except Timeout:
            return '', f"请求超时 ({self.timeout}s)"
        except RequestException as e:
            return '', f"请求异常: {e}"

    def download(self, url: str, save_dir: Optional[str] = None) -> DownloadResult:
        """下载文件"""
        result = DownloadResult(url=url, provider='163')

        download_url, error = self.get_download_url(url)
        if error:
            result.error = error
            return result

        result.download_url = download_url
        return self._download_file(result, download_url, save_dir)

    def _download_file(self, result: DownloadResult, url: str,
                       save_dir: Optional[str]) -> DownloadResult:
        """执行实际下载"""
        try:
            resp = self.session.get(url, stream=True, timeout=self.timeout)
            if resp.status_code != 200:
                result.error = f"下载失败: HTTP {resp.status_code}"
                return result

            # 解析文件信息
            result.content_type = resp.headers.get('Content-Type', '')
            result.size = int(resp.headers.get('Content-Length', 0))
            result.filename = self._extract_filename(resp.headers, url)

            # 确定保存路径
            if save_dir:
                save_path = Path(save_dir) / result.filename
            else:
                temp_dir = tempfile.mkdtemp(prefix='mail_download_')
                save_path = Path(temp_dir) / result.filename

            # 下载并计算哈希
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()

            with open(save_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        md5_hash.update(chunk)
                        sha256_hash.update(chunk)

            result.path = str(save_path)
            result.md5 = md5_hash.hexdigest()
            result.sha256 = sha256_hash.hexdigest()
            result.success = True

        except Timeout:
            result.error = f"下载超时 ({self.timeout}s)"
        except RequestException as e:
            result.error = f"下载异常: {e}"
        except IOError as e:
            result.error = f"写入文件失败: {e}"

        return result

    def _extract_filename(self, headers: Dict[str, str], url: str) -> str:
        """从响应头或 URL 提取文件名"""
        disposition = headers.get('Content-Disposition', '')
        if disposition:
            # filename*=UTF-8''xxx 或 filename="xxx"
            match = re.search(r"filename\*?=(?:UTF-8'')?([^\";]+)", disposition)
            if match:
                from urllib.parse import unquote
                return unquote(match.group(1))

        # 从 URL 路径提取
        path = urlparse(url).path
        if path:
            return path.split('/')[-1] or 'unknown_file'
        return 'unknown_file'


# ============================================================
# QQ 邮箱中转站
# ============================================================

class QQDownloader:
    """QQ 邮箱文件中转站下载器"""

    # 从页面 JS 中提取下载链接的正则（旧版 mail.qq.com）
    URL_PATTERN = re.compile(r'var\s+url\s*=\s*"([^"]+)"')

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/237.84.2.178 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

    def _is_wx_mail(self, url: str) -> bool:
        """判断是否为 wx.mail.qq.com（新版 JSON API）"""
        return 'wx.mail.qq.com' in url

    def _get_wx_download_url(self, url: str) -> Tuple[str, str]:
        """
        从 wx.mail.qq.com JSON API 获取下载链接

        新版接口直接返回 JSON:
        - 成功: {"head":{"ret":0}, "body":{"url":"..."}}
        - 失败: {"head":{"ret":-5002,"msg":"fileid error"}}

        Args:
            url: 分享链接

        Returns:
            (download_url, error_msg)
        """
        try:
            # 新版 API 接受 JSON
            headers = {
                'Accept': 'application/json, text/plain, */*',
            }
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code != 200:
                return '', f"API 请求失败: HTTP {resp.status_code}"

            try:
                data = resp.json()
            except json.JSONDecodeError:
                # 可能是旧版 HTML 格式，尝试正则提取
                match = self.URL_PATTERN.search(resp.text)
                if match:
                    return match.group(1).replace(r'\x26', '&'), ''
                return '', '响应既不是有效 JSON 也不包含下载链接'

            # 检查返回码
            head = data.get('head', {})
            ret_code = head.get('ret', -1)

            if ret_code != 0:
                error_msg = head.get('msg', '') or head.get('stack', '')
                return '', f"API 返回错误 (code={ret_code}): {error_msg}"

            # 从 body 中提取下载 URL
            body = data.get('body', {})
            download_url = body.get('url', '') or body.get('download_url', '')

            if not download_url:
                # 尝试其他可能的字段名
                for key in ['fileUrl', 'file_url', 'downloadUrl', 'link']:
                    if body.get(key):
                        download_url = body[key]
                        break

            if not download_url:
                return '', f"API 响应中未找到下载链接: {data}"

            return download_url, ''

        except Timeout:
            return '', f"请求超时 ({self.timeout}s)"
        except RequestException as e:
            return '', f"请求异常: {e}"

    def _get_legacy_download_url(self, url: str) -> Tuple[str, str]:
        """
        从 mail.qq.com 旧版 HTML 页面提取下载链接

        旧版页面包含: var url = "https://..."

        Args:
            url: 分享链接

        Returns:
            (download_url, error_msg)
        """
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return '', f"页面请求失败: HTTP {resp.status_code}"

            match = self.URL_PATTERN.search(resp.text)
            if not match:
                return '', '无法从页面提取下载链接'

            # QQ 邮箱使用 \x26 转义 &
            download_url = match.group(1).replace(r'\x26', '&')
            return download_url, ''

        except Timeout:
            return '', f"请求超时 ({self.timeout}s)"
        except RequestException as e:
            return '', f"请求异常: {e}"

    def get_download_url(self, url: str) -> Tuple[str, str]:
        """
        从分享页面提取真实下载链接

        自动识别 API 版本:
        - wx.mail.qq.com: 新版 JSON API
        - mail.qq.com: 旧版 HTML 页面

        Args:
            url: 分享链接

        Returns:
            (download_url, error_msg)
        """
        if self._is_wx_mail(url):
            return self._get_wx_download_url(url)
        else:
            return self._get_legacy_download_url(url)

    def download(self, url: str, save_dir: Optional[str] = None) -> DownloadResult:
        """下载文件"""
        result = DownloadResult(url=url, provider='qq')

        download_url, error = self.get_download_url(url)
        if error:
            result.error = error
            return result

        result.download_url = download_url

        # 复用 NetEasy 的下载逻辑
        downloader = NetEasyDownloader(timeout=self.timeout)
        downloader.session = self.session
        return downloader._download_file(result, download_url, save_dir)


# ============================================================
# 统一入口
# ============================================================

def download_from_mail(url: str, save_dir: Optional[str] = None,
                       timeout: int = 30) -> DownloadResult:
    """
    从邮箱中转站下载文件

    自动识别 163/QQ 邮箱并使用对应的下载器

    Args:
        url: 邮箱中转站分享链接
        save_dir: 保存目录（默认临时目录）
        timeout: 超时时间

    Returns:
        DownloadResult: 下载结果
    """
    provider = detect_mail_provider(url)

    if provider == '163':
        downloader = NetEasyDownloader(timeout=timeout)
    elif provider == 'qq':
        downloader = QQDownloader(timeout=timeout)
    else:
        return DownloadResult(
            url=url,
            error=f"不支持的邮箱中转站链接: {url}"
        )

    return downloader.download(url, save_dir)


def analyze_mail_url(url: str) -> Dict[str, Any]:
    """
    分析邮箱中转站 URL（不下载）

    Returns:
        分析结果字典
    """
    result = {
        'url': url,
        'is_mail_download': False,
        'provider': None,
        'download_url': None,
        'error': None,
    }

    provider = detect_mail_provider(url)
    if not provider:
        result['error'] = '非邮箱中转站链接'
        return result

    result['is_mail_download'] = True
    result['provider'] = provider

    # 获取真实下载链接
    if provider == '163':
        downloader = NetEasyDownloader()
        download_url, error = downloader.get_download_url(url)
    else:
        downloader = QQDownloader()
        download_url, error = downloader.get_download_url(url)

    if error:
        result['error'] = error
    else:
        result['download_url'] = download_url

    return result


# ============================================================
# 格式化输出
# ============================================================

def format_result(result: DownloadResult) -> str:
    """格式化下载结果"""
    lines = []
    lines.append("=" * 60)
    lines.append("邮箱中转站文件下载报告")
    lines.append("=" * 60)
    lines.append("")

    lines.append("【基本信息】")
    lines.append(f"  原始链接: {result.url}")
    lines.append(f"  服务商: {result.provider.upper() if result.provider else 'N/A'}")
    lines.append(f"  状态: {'[+] 成功' if result.success else '[-] 失败'}")
    if result.error:
        lines.append(f"  错误: {result.error}")
    lines.append("")

    if result.download_url:
        lines.append("【下载链接】")
        lines.append(f"  真实下载 URL: {result.download_url[:80]}...")
        lines.append("")

    if result.success:
        lines.append("【文件信息】")
        lines.append(f"  文件名: {result.filename}")
        lines.append(f"  大小: {format_size(result.size)}")
        lines.append(f"  类型: {result.content_type}")
        lines.append(f"  MD5: {result.md5}")
        lines.append(f"  SHA256: {result.sha256}")
        lines.append(f"  保存路径: {result.path}")
        lines.append("")

    lines.append("=" * 60)
    return '\n'.join(lines)


def format_size(size: int) -> str:
    """格式化文件大小"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


# ============================================================
# 命令行入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='邮箱文件中转站下载工具 (支持 163/QQ 邮箱)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 分析链接（不下载）
  python mail_downloader.py "https://mail.163.com/large-attachment-download/index.html?file=xxx" --analyze

  # 下载文件
  python mail_downloader.py "https://wx.mail.qq.com/ftn/download?..." -d ./downloads

  # JSON 输出
  python mail_downloader.py "https://..." -o json

支持的邮箱中转站:
  - 163 邮箱: mail.163.com, dashi.163.com
  - QQ 邮箱: wx.mail.qq.com, mail.qq.com
        """
    )
    parser.add_argument('url', help='邮箱中转站分享链接')
    parser.add_argument('-d', '--save-dir', help='保存目录')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='超时时间(秒)')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text',
                        help='输出格式')
    parser.add_argument('--analyze', action='store_true',
                        help='仅分析链接，不下载文件')

    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("错误: 需要安装 requests 库", file=sys.stderr)
        print("运行: pip install requests", file=sys.stderr)
        sys.exit(1)

    # 检测是否为邮箱中转站链接
    provider = detect_mail_provider(args.url)
    if not provider:
        print(f"错误: 不是已知的邮箱中转站链接", file=sys.stderr)
        print(f"支持: 163 邮箱, QQ 邮箱", file=sys.stderr)
        sys.exit(1)

    if args.analyze:
        # 仅分析
        analysis = analyze_mail_url(args.url)
        if args.output == 'json':
            print(json.dumps(analysis, ensure_ascii=False, indent=2))
        else:
            print(f"邮箱服务商: {analysis['provider']}")
            print(f"是否可下载: {'是' if analysis['is_mail_download'] else '否'}")
            if analysis['download_url']:
                print(f"真实下载链接: {analysis['download_url']}")
            if analysis['error']:
                print(f"错误: {analysis['error']}")
    else:
        # 下载文件
        result = download_from_mail(args.url, args.save_dir, args.timeout)

        if args.output == 'json':
            output = {
                'success': result.success,
                'url': result.url,
                'provider': result.provider,
                'download_url': result.download_url,
                'filename': result.filename,
                'size': result.size,
                'content_type': result.content_type,
                'md5': result.md5,
                'sha256': result.sha256,
                'path': result.path,
                'error': result.error,
            }
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            print(format_result(result))

        if not result.success:
            sys.exit(1)


if __name__ == '__main__':
    main()
