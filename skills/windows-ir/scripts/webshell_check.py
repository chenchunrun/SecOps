#!/usr/bin/env python3
"""
Windows Webshell Deep Detection Script

8层检测机制：时间异常、内容特征、工具指纹、文件名异常、IIS日志关联、进程行为、评分、报告生成
"""

import os
import re
import sys
import glob
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

# 尝试导入 psutil（可选，用于进程分析）
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class Colors:
    """终端颜色"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    RESET = '\033[0m'

    @staticmethod
    def init():
        """Windows 终端颜色支持"""
        if sys.platform == 'win32':
            os.system('')


def print_color(msg: str, color: str = Colors.RESET):
    print(f"{color}{msg}{Colors.RESET}")


# 全局结果存储
results: Dict[str, List] = {
    'Critical': [],
    'High': [],
    'Medium': [],
    'Low': [],
    'Info': []
}


# ========== 模块 1: Web 目录发现 ==========
def get_web_directories(custom_paths: List[str] = None) -> List[str]:
    """获取 Web 目录列表"""
    # 优先使用自定义路径
    if custom_paths:
        return [p for p in custom_paths if os.path.exists(p)]

    # 读取配置文件
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, '..', 'config', 'web_paths.txt')

    if os.path.exists(config_file):
        dirs = []
        with open(config_file, 'r', encoding='utf-8') as f:
            for line in f:
                path = line.strip()
                if path and os.path.exists(path):
                    dirs.append(path)
        if dirs:
            return dirs

    # 默认路径
    print_color("[!] Config file not found, using default paths", Colors.YELLOW)
    print_color("    Suggestion: Run python find_web_dirs.py first", Colors.GRAY)
    return ["C:\\inetpub\\wwwroot"]


# ========== 模块 2: 时间异常检测 ==========
def test_file_time_anomaly(file_path: str, days_back: int) -> Dict:
    """检测文件时间异常"""
    score = 0
    reasons = []

    try:
        stat = os.stat(file_path)
        mtime = datetime.fromtimestamp(stat.st_mtime)
        ctime = datetime.fromtimestamp(stat.st_ctime)
        now = datetime.now()

        # 最近修改
        if mtime > now - timedelta(days=days_back):
            score += 10
            reasons.append(f"Modified within last {days_back} days")

        # 凌晨创建 (2-5 AM)
        if 2 <= ctime.hour <= 5:
            score += 20
            reasons.append("Created during suspicious hours (2-5 AM)")

        # 创建时间等于修改时间（一次性上传）
        time_diff = abs((mtime - ctime).total_seconds())
        if time_diff < 5:
            score += 15
            reasons.append("Not modified after creation (possible upload)")
    except Exception:
        pass

    return {'Score': score, 'Reasons': reasons}


# ========== 模块 3: 内容特征检测 ==========

# 按语言分类的特征模式
PATTERNS_PHP = [
    # 命令执行 - 精确匹配函数调用形式
    (r'(?<![.\w])(system|passthru|shell_exec|popen|proc_open)\s*\(', 30, 'php_cmd_exec'),
    (r'(?<![.\w])exec\s*\(', 25, 'php_exec()'),
    # 代码执行
    (r'eval\s*\(\s*[\$\'"]', 30, 'eval($var)'),
    (r'assert\s*\(\s*[\$\'"]', 25, 'assert()'),
    (r'create_function\s*\(', 25, 'create_function()'),
    (r'preg_replace\s*\([^)]*[\'\"]/[^/]*e[\'\"]\s*,', 30, 'preg_replace /e'),
    # 编码混淆
    (r'base64_decode\s*\([^)]*\)\s*\)', 20, 'base64_decode'),
    (r'base64_decode.*eval|eval.*base64_decode', 35, 'base64+eval'),
    (r'gzinflate\s*\(|gzuncompress\s*\(|str_rot13\s*\(', 20, 'obfuscation'),
    # 文件操作
    (r'file_put_contents\s*\([^)]*\$_(GET|POST|REQUEST)', 30, 'file_write_input'),
    (r'move_uploaded_file\s*\(', 15, 'file_upload'),
    # 输入获取
    (r'\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\)', 10, 'user_input'),
]

PATTERNS_JSP = [
    # 命令执行 - Runtime.exec
    (r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', 35, 'Runtime.exec()'),
    (r'ProcessBuilder', 30, 'ProcessBuilder'),
    # 反射调用
    (r'Class\s*\.\s*forName\s*\([^)]*\)\s*\.\s*getMethod', 25, 'reflection'),
    (r'\.invoke\s*\(', 15, 'invoke()'),
    # 脚本引擎
    (r'ScriptEngine|ScriptEngineManager', 25, 'ScriptEngine'),
    (r'javax\.script', 20, 'javax.script'),
    # 文件操作
    (r'FileOutputStream|FileWriter', 15, 'file_write'),
    # 请求获取
    (r'request\s*\.\s*getParameter\s*\(', 10, 'request_param'),
]

PATTERNS_ASP = [
    # 命令执行
    (r'(?<![.\w])Execute\s*\(', 30, 'Execute()'),
    (r'(?<![.\w])Eval\s*\(', 30, 'Eval()'),
    (r'ExecuteGlobal\s*\(', 30, 'ExecuteGlobal()'),
    # WScript Shell
    (r'WScript\s*\.\s*Shell|CreateObject\s*\(\s*[\'"]WScript\.Shell', 35, 'WScript.Shell'),
    (r'CreateObject\s*\(\s*[\'"]Scripting\.FileSystemObject', 20, 'FSO'),
    # 命令执行
    (r'\.Run\s*\(|\.Exec\s*\(', 25, 'Shell.Run/Exec'),
    # 请求获取
    (r'Request\s*\(\s*[\'"]|Request\s*\.\s*Form|Request\s*\.\s*QueryString', 10, 'Request'),
]

PATTERNS_ASPX = [
    # 进程启动
    (r'ProcessStartInfo', 30, 'ProcessStartInfo'),
    (r'System\s*\.\s*Diagnostics\s*\.\s*Process', 30, 'Process.Start'),
    # 反射
    (r'System\s*\.\s*Reflection\s*\.\s*Assembly', 25, 'Assembly.Load'),
    (r'Activator\s*\.\s*CreateInstance', 20, 'CreateInstance'),
    # 编译执行
    (r'CompileAssemblyFromSource|CSharpCodeProvider', 30, 'dynamic_compile'),
    # 编码
    (r'FromBase64String', 20, 'Base64'),
    (r'Convert\s*\.\s*FromBase64String', 20, 'Base64'),
    # 网络
    (r'WebClient|HttpWebRequest', 15, 'WebRequest'),
    (r'TcpClient|Socket', 25, 'Socket'),
]

# 通用可疑模式（所有类型都检测）
PATTERNS_COMMON = [
    # 网络连接
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 5, 'hardcoded_ip'),
    # 可疑字符串
    (r'(cmd\.exe|/bin/sh|/bin/bash)', 20, 'shell_path'),
]


def get_file_type(file_path: str) -> str:
    """根据扩展名获取文件类型"""
    ext = os.path.splitext(file_path)[1].lower()
    type_map = {
        '.php': 'php',
        '.php3': 'php',
        '.php4': 'php',
        '.php5': 'php',
        '.phtml': 'php',
        '.jsp': 'jsp',
        '.jspx': 'jsp',
        '.asp': 'asp',
        '.asa': 'asp',
        '.cer': 'asp',
        '.aspx': 'aspx',
        '.ashx': 'aspx',
        '.asmx': 'aspx',
    }
    return type_map.get(ext, 'unknown')


def test_file_content_features(file_path: str) -> Dict:
    """检测文件内容特征（按文件类型分流）"""
    score = 0
    features = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return {'Score': 0, 'Features': []}

    # 根据文件类型选择对应的特征模式
    file_type = get_file_type(file_path)

    patterns_map = {
        'php': PATTERNS_PHP,
        'jsp': PATTERNS_JSP,
        'asp': PATTERNS_ASP,
        'aspx': PATTERNS_ASPX,
    }

    # 获取该类型的特征模式
    patterns = patterns_map.get(file_type, [])

    # 加上通用模式
    patterns = patterns + PATTERNS_COMMON

    for pattern, pts, desc in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            score += pts
            if desc not in features:
                features.append(desc)

    return {'Score': score, 'Features': features}


# ========== 模块 4: Webshell 工具指纹检测 ==========
def test_webshell_signature(file_path: str) -> Optional[Dict]:
    """检测已知 Webshell 工具指纹"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None

    signatures = {
        'China Chopper (Caidao)': r'z0\s*=\s*Request|<%\s*eval\s+request',
        'AntSword (Yijian)': r'@ini_set.*display_errors.*antSword',
        'Behinder (Bingxie)': r'@session_start.*@set_time_limit\(0\).*@set_time_limit',
        'Godzilla (Gesila)': r'\$pass\s*=\s*.+;\s*\$md5\s*=\s*md5\(\$pass\)',
        'Weevely': r'\$kh\s*=\s*\S{32}.*\$kf',
        'C99Shell': r'c99sh_.*surl|c99shell',
        'r57Shell': r'r57shell|r57=',
        'WSO Shell': r'WSO\s+\d+\.\d+|wso\.version',
    }

    for tool, pattern in signatures.items():
        if re.search(pattern, content, re.IGNORECASE):
            return {'Tool': tool, 'Confidence': 95}

    return None


# ========== 模块 5: 文件名异常检测 ==========
def test_filename_anomaly(file_path: str) -> Dict:
    """检测文件名异常"""
    score = 0
    patterns = []
    name = os.path.basename(file_path)

    checks = [
        # 纯数字文件名
        (r'^\d{1,3}\.(asp|aspx|php|jsp)$', 25, 'Pure numeric filename'),
        # 单字母文件名
        (r'^[a-z]\.(asp|php)$', 20, 'Single letter'),
        # 恶意关键词
        (r'shell|cmd|hack|backdoor|spy|trojan|upload.*\.(asp|php)', 30, 'Malicious keywords'),
        # 双扩展名
        (r'\.(asp|php|jsp)\.(jpg|gif|txt|bak)$', 20, 'Double extension'),
    ]

    for pattern, pts, desc in checks:
        if re.search(pattern, name, re.IGNORECASE):
            score += pts
            patterns.append(desc)

    # 隐藏字符
    if any(ord(c) < 32 for c in name):
        score += 25
        patterns.append('Contains invisible characters')

    return {'Score': score, 'Patterns': patterns}


# ========== 模块 6: IIS 日志关联 ==========
def get_iis_log_records(filename: str, deep_scan: bool) -> Optional[Dict]:
    """获取 IIS 日志中的访问记录"""
    if not deep_scan:
        return None

    records = []
    log_base = "C:\\inetpub\\logs\\LogFiles"

    if not os.path.exists(log_base):
        return None

    try:
        for site_dir in glob.glob(os.path.join(log_base, "W3SVC*")):
            log_files = sorted(
                glob.glob(os.path.join(site_dir, "u_ex*.log")),
                key=os.path.getmtime,
                reverse=True
            )[:3]  # 只检查最近 3 个日志文件

            for log_file in log_files:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if filename in line:
                                records.append(line)
                                if len(records) >= 100:
                                    break
                except Exception:
                    pass

                if len(records) >= 100:
                    break
    except Exception:
        return None

    if records:
        summary = {
            'Count': len(records),
            'FirstSeen': records[-1].split()[:2] if records else '',
            'LastSeen': records[0].split()[:2] if records else '',
            'SuspiciousUserAgent': False
        }

        # 检查可疑 User-Agent
        suspicious_ua = ['Behinder', 'antSword', 'Godzilla', 'Python-urllib']
        for record in records:
            if any(ua.lower() in record.lower() for ua in suspicious_ua):
                summary['SuspiciousUserAgent'] = True
                break

        return summary

    return None


# ========== 模块 7: 进程行为关联 ==========
def get_suspicious_processes(deep_scan: bool) -> List[Dict]:
    """检测可疑子进程"""
    if not deep_scan or not HAS_PSUTIL:
        return []

    suspicious = []

    try:
        # 查找 w3wp 进程
        w3wp_pids = set()
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'] and proc.info['name'].lower() == 'w3wp.exe':
                w3wp_pids.add(proc.info['pid'])

        if not w3wp_pids:
            return []

        # 查找可疑子进程
        suspicious_names = ['cmd.exe', 'powershell.exe', 'whoami.exe', 'net.exe', 'ipconfig.exe']

        for proc in psutil.process_iter(['name', 'pid', 'ppid', 'cmdline', 'create_time']):
            try:
                if (proc.info['ppid'] in w3wp_pids and
                    proc.info['name'] and
                    proc.info['name'].lower() in suspicious_names):
                    suspicious.append({
                        'Name': proc.info['name'],
                        'ProcessId': proc.info['pid'],
                        'CommandLine': ' '.join(proc.info['cmdline'] or []),
                        'CreationDate': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass

    return suspicious


# ========== 模块 8: 威胁评分与分级 ==========
def get_threat_level(score: int, signature: Optional[Dict],
                     log_records: Optional[Dict], process_info: List) -> str:
    """根据分数和证据确定威胁等级"""
    # 工具指纹 = Critical
    if signature:
        return 'Critical'

    # 日志关联加权
    if log_records:
        if log_records.get('Count', 0) > 50:
            score += 20
        if log_records.get('SuspiciousUserAgent'):
            score += 25

    # 进程行为加权
    if process_info:
        score += 30

    # 分数分级
    if score >= 80:
        return 'High'
    if score >= 50:
        return 'Medium'
    if score >= 20:
        return 'Low'
    return 'Info'


def get_color_for_level(level: str) -> str:
    """获取威胁等级对应的颜色"""
    return {
        'Critical': Colors.RED,
        'High': Colors.YELLOW,
        'Medium': Colors.MAGENTA,
        'Low': Colors.CYAN,
        'Info': Colors.GRAY
    }.get(level, Colors.GRAY)


# ========== 主检测流程 ==========
def scan_directory(dir_path: str, days_back: int, quick_scan: bool,
                   deep_scan: bool, suspicious_processes: List) -> tuple:
    """扫描目录中的 Web 脚本文件"""
    total_files = 0
    suspicious_files = 0

    if not os.path.exists(dir_path):
        print_color(f"[SKIP] {dir_path} (not found)", Colors.RED)
        return 0, 0

    print_color(f"[SCAN] {dir_path}", Colors.GREEN)

    # 查找 Web 脚本文件
    extensions = ['*.asp', '*.aspx', '*.php', '*.jsp', '*.asa', '*.cer']
    files = []

    for ext in extensions:
        for root, dirs, filenames in os.walk(dir_path):
            # 限制递归深度为 5 层
            depth = root.replace(dir_path, '').count(os.sep)
            if depth > 5:
                dirs.clear()
                continue

            for filename in filenames:
                if any(filename.lower().endswith(e.replace('*', '')) for e in extensions):
                    files.append(os.path.join(root, filename))

    # 去重
    files = list(set(files))
    total_files = len(files)
    print_color(f"  Found {total_files} web script files (depth: 5)", Colors.GRAY)

    for file_path in files:
        # 模块调用
        time_result = test_file_time_anomaly(file_path, days_back)
        content_result = test_file_content_features(file_path)
        name_result = test_filename_anomaly(file_path)
        signature = None
        log_records = None

        # 深度扫描：工具指纹 + 日志关联
        preliminary_score = time_result['Score'] + content_result['Score'] + name_result['Score']
        if deep_scan or preliminary_score > 30:
            signature = test_webshell_signature(file_path)
            if deep_scan:
                log_records = get_iis_log_records(os.path.basename(file_path), deep_scan)

        # 计算总分
        total_score = time_result['Score'] + content_result['Score'] + name_result['Score']

        # 确定威胁等级
        threat_level = get_threat_level(total_score, signature, log_records, suspicious_processes)

        # 收集结果（阈值：最低 10 分）
        if signature or total_score >= 10:
            suspicious_files += 1

            try:
                stat = os.stat(file_path)
                file_size = stat.st_size
                created = datetime.fromtimestamp(stat.st_ctime).isoformat()
                modified = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except Exception:
                file_size = 0
                created = ''
                modified = ''

            result = {
                'Path': file_path,
                'Name': os.path.basename(file_path),
                'Score': total_score,
                'Level': threat_level,
                'Size': file_size,
                'Created': created,
                'Modified': modified,
                'TimeReasons': ', '.join(time_result['Reasons']),
                'Features': ', '.join(content_result['Features']),
                'NamePatterns': ', '.join(name_result['Patterns']),
                'Signature': signature['Tool'] if signature else '',
                'LogAccessCount': log_records['Count'] if log_records else 0,
                'LogSuspiciousUA': log_records.get('SuspiciousUserAgent', False) if log_records else False
            }

            results[threat_level].append(result)

            # 控制台输出
            color = get_color_for_level(threat_level)
            display_info = f"[{threat_level}] {os.path.basename(file_path)} (Score: {total_score})"
            if signature:
                display_info += f" [Tool: {signature['Tool']}]"
            if log_records and log_records.get('Count', 0) > 0:
                display_info += f" [Access: {log_records['Count']}x]"

            print_color(f"  {display_info}", color)

    return total_files, suspicious_files


def main():
    parser = argparse.ArgumentParser(description='Windows Webshell Deep Detection Script')
    parser.add_argument('-p', '--paths', nargs='+', help='Custom scan paths')
    parser.add_argument('-d', '--days', type=int, default=30, help='Detection time range (default: 30 days)')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan mode')
    parser.add_argument('--deep', action='store_true', help='Deep scan mode (all 8 layers)')
    parser.add_argument('-o', '--output', help='Output report path (JSON format)')
    args = parser.parse_args()

    Colors.init()

    scan_mode = 'Quick' if args.quick else ('Deep' if args.deep else 'Standard')

    print_color("=== Windows Webshell Detection Tool ===", Colors.CYAN)
    print_color(f"Scan mode: {scan_mode}", Colors.YELLOW)
    print_color(f"Time range: Last {args.days} days\n", Colors.YELLOW)

    # 深度模式：检测可疑进程
    suspicious_processes = []
    if args.deep:
        print_color("[Process Check] Detecting w3wp.exe suspicious child processes...", Colors.CYAN)
        suspicious_processes = get_suspicious_processes(args.deep)
        if suspicious_processes:
            print_color(f"  [!] Found {len(suspicious_processes)} suspicious child processes", Colors.RED)
            for proc in suspicious_processes:
                print_color(f"    - {proc['Name']}: {proc['CommandLine']}", Colors.YELLOW)
        else:
            print_color("  [+] No suspicious child processes found", Colors.GREEN)
        print()

    # 获取扫描目录
    web_dirs = get_web_directories(args.paths)
    print_color("Scan directories:", Colors.CYAN)
    for d in web_dirs:
        print_color(f"  - {d}", Colors.GRAY)
    print()

    # 扫描
    total_files = 0
    suspicious_files = 0

    for dir_path in web_dirs:
        t, s = scan_directory(dir_path, args.days, args.quick, args.deep, suspicious_processes)
        total_files += t
        suspicious_files += s

    # ========== 结果汇总 ==========
    print_color("\n========================================", Colors.CYAN)
    print_color("Detection Results Summary", Colors.CYAN)
    print_color("========================================", Colors.CYAN)
    print(f"Total files scanned: {total_files}")
    print(f"Suspicious files found: {suspicious_files}")
    print()
    print_color("Classification by threat level:", Colors.YELLOW)
    print_color(f"  Critical: {len(results['Critical'])}", Colors.RED)
    print_color(f"  High:     {len(results['High'])}", Colors.YELLOW)
    print_color(f"  Medium:   {len(results['Medium'])}", Colors.MAGENTA)
    print_color(f"  Low:      {len(results['Low'])}", Colors.CYAN)
    print_color(f"  Info:     {len(results['Info'])}", Colors.GRAY)

    # 显示详情（Critical 和 High）
    if results['Critical']:
        print_color("\nCritical Threat Details:", Colors.RED)
        for r in results['Critical']:
            print(f"  {r['Name']}: {r['Path']}")
            print(f"    Signature: {r['Signature']}, Features: {r['Features']}")

    if results['High']:
        print_color("\nHigh Threat Details:", Colors.YELLOW)
        for r in results['High']:
            print(f"  {r['Name']}: {r['Path']}")
            print(f"    Score: {r['Score']}, Features: {r['Features']}")

    # ========== 报告输出 ==========
    if args.output:
        report_data = {
            'ScanTime': datetime.now().isoformat(),
            'ScanMode': scan_mode,
            'DaysBack': args.days,
            'Directories': web_dirs,
            'TotalFiles': total_files,
            'SuspiciousFiles': suspicious_files,
            'Results': results,
            'ProcessInfo': suspicious_processes
        }

        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        print_color(f"\n[+] Report saved: {args.output}", Colors.GREEN)

    # ========== 建议 ==========
    if suspicious_files > 0:
        print_color("\n========================================", Colors.CYAN)
        print_color("Recommendations:", Colors.YELLOW)
        print_color("  1. Manually analyze code of Critical and High threat files", Colors.GRAY)
        print_color("  2. Review IIS logs to confirm file access records", Colors.GRAY)
        print_color("  3. Refer to references/webshell-detection.md for incident response", Colors.GRAY)
        if not args.deep:
            print_color("  4. Run deep scan for more information: --deep", Colors.GRAY)

    print()


if __name__ == '__main__':
    main()
