#!/usr/bin/env python3
"""
Web Directory Auto-Discovery Tool

通过多层检测机制发现 IIS、Apache、Nginx、Tomcat 等 Web 服务器的根目录
默认自动保存到 config/web_paths.txt 供后续使用
"""

import os
import re
import sys
import glob
import json
import argparse
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

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
    GRAY = '\033[90m'
    RESET = '\033[0m'

    @staticmethod
    def init():
        """Windows 终端颜色支持"""
        if sys.platform == 'win32':
            os.system('')  # 启用 ANSI 转义序列


def print_color(msg: str, color: str = Colors.RESET):
    print(f"{color}{msg}{Colors.RESET}")


def expand_env_vars(path: str) -> str:
    """展开环境变量"""
    return os.path.expandvars(path)


def is_tomcat_install(path: str) -> bool:
    """检查目录是否是有效的 Tomcat 安装（特征：存在 conf/server.xml）"""
    server_xml = os.path.join(path, 'conf', 'server.xml')
    return os.path.exists(server_xml)


def get_tomcat_webapps(tomcat_home: str) -> str:
    """从 Tomcat 安装目录获取 webapps 路径"""
    webapps = os.path.join(tomcat_home, 'webapps')
    if os.path.exists(webapps):
        return webapps
    return None


# ========== 层次 1: 读取 IIS 配置文件 ==========
def find_iis_directories() -> list:
    print_color("[1/5] Analyzing IIS configuration files...", Colors.YELLOW)
    dirs = []

    # 读取 applicationHost.config
    iis_config = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'),
                               'System32', 'inetsrv', 'config', 'applicationHost.config')

    if os.path.exists(iis_config):
        try:
            tree = ET.parse(iis_config)
            root = tree.getroot()

            # 查找所有站点的物理路径
            # 命名空间处理
            ns = {'': 'http://schemas.microsoft.com/.NetConfiguration/v2.0'}

            # 尝试不带命名空间的查找
            for site in root.iter('site'):
                site_name = site.get('name', 'Unknown')
                for app in site.iter('application'):
                    for vdir in app.iter('virtualDirectory'):
                        physical_path = vdir.get('physicalPath')
                        if physical_path:
                            expanded_path = expand_env_vars(physical_path)
                            if os.path.exists(expanded_path) and expanded_path not in dirs:
                                dirs.append(expanded_path)
                                print_color(f"  [+] IIS site: {site_name} -> {expanded_path}", Colors.GREEN)
        except ET.ParseError:
            print_color("  [-] Unable to parse IIS configuration", Colors.GRAY)
        except Exception as e:
            print_color(f"  [-] Error reading IIS config: {e}", Colors.GRAY)

    if not dirs:
        print_color("  [ ] No IIS sites found", Colors.GRAY)

    return dirs


# ========== 层次 2: 读取其他 Web 服务器配置 ==========
def find_other_webserver_directories() -> list:
    print_color("[2/5] Analyzing other web server configurations...", Colors.YELLOW)
    dirs = []

    # Apache httpd.conf
    apache_configs = [
        "C:/Apache24/conf/httpd.conf",
        "C:/Apache2/conf/httpd.conf",
    ]
    # 使用 glob 扩展通配符路径
    apache_configs.extend(glob.glob("C:/Program Files/Apache*/conf/httpd.conf"))
    apache_configs.extend(glob.glob("C:/Program Files (x86)/Apache*/conf/httpd.conf"))

    for config_path in apache_configs:
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # 匹配 DocumentRoot
                matches = re.findall(r'^\s*DocumentRoot\s+["]?([^"\n]+)', content, re.MULTILINE)
                for path in matches:
                    path = path.strip().strip('"')
                    if os.path.exists(path) and path not in dirs:
                        dirs.append(path)
                        print_color(f"  [+] Apache: {path}", Colors.GREEN)
            except Exception:
                pass

    # Nginx nginx.conf
    nginx_configs = [
        "C:/nginx/conf/nginx.conf",
        "C:/Program Files/nginx/conf/nginx.conf",
    ]

    for config_path in nginx_configs:
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # 匹配 root
                matches = re.findall(r'^\s*root\s+([^;]+);', content, re.MULTILINE)
                for path in matches:
                    path = path.strip()
                    if os.path.exists(path) and path not in dirs:
                        dirs.append(path)
                        print_color(f"  [+] Nginx: {path}", Colors.GREEN)
            except Exception:
                pass

    # Tomcat - 使用特征发现方式检测
    # 方法 A: 环境变量
    for var in ['CATALINA_HOME', 'CATALINA_BASE', 'TOMCAT_HOME']:
        value = os.environ.get(var)
        if value and os.path.exists(value) and is_tomcat_install(value):
            webapps = get_tomcat_webapps(value)
            if webapps and webapps not in dirs:
                dirs.append(webapps)
                print_color(f"  [+] Tomcat (env {var}): {webapps}", Colors.GREEN)

    # 方法 B: Windows 服务
    try:
        cmd = [
            'powershell.exe', '-Command',
            "Get-WmiObject win32_service | Where-Object {$_.Name -like '*tomcat*' -or $_.DisplayName -like '*tomcat*'} | Select-Object Name, PathName | ConvertTo-Json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            services = json.loads(result.stdout)
            if isinstance(services, dict):
                services = [services]
            for svc in services:
                path_name = svc.get('PathName', '')
                if path_name:
                    match = re.search(r'"?([A-Za-z]:\\[^"]+?)(?:"|$)', path_name)
                    if match:
                        exe_path = match.group(1)
                        if 'bin' in exe_path.lower():
                            tomcat_home = os.path.dirname(os.path.dirname(exe_path))
                            if is_tomcat_install(tomcat_home):
                                webapps = get_tomcat_webapps(tomcat_home)
                                if webapps and webapps not in dirs:
                                    dirs.append(webapps)
                                    print_color(f"  [+] Tomcat (service): {webapps}", Colors.GREEN)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        pass

    # 方法 C: 智能搜索（在磁盘根目录搜索包含 tomcat 关键字的目录）
    search_roots = [f"{d}:/" for d in 'CDEFGH' if os.path.exists(f"{d}:/")]
    for root in search_roots:
        try:
            for item1 in os.listdir(root):
                path1 = os.path.join(root, item1)
                if not os.path.isdir(path1):
                    continue
                # 目录名包含 tomcat
                if 'tomcat' in item1.lower():
                    if is_tomcat_install(path1):
                        webapps = get_tomcat_webapps(path1)
                        if webapps and webapps not in dirs:
                            dirs.append(webapps)
                            print_color(f"  [+] Tomcat: {webapps}", Colors.GREEN)
                    else:
                        # 检查子目录（如 E:\tomcat\apache-tomcat-9.0.2）
                        try:
                            for item2 in os.listdir(path1):
                                path2 = os.path.join(path1, item2)
                                if os.path.isdir(path2) and is_tomcat_install(path2):
                                    webapps = get_tomcat_webapps(path2)
                                    if webapps and webapps not in dirs:
                                        dirs.append(webapps)
                                        print_color(f"  [+] Tomcat: {webapps}", Colors.GREEN)
                        except PermissionError:
                            pass
                # 目录名包含 apache（检查 Apache Software Foundation 等）
                elif 'apache' in item1.lower():
                    try:
                        for item2 in os.listdir(path1):
                            path2 = os.path.join(path1, item2)
                            if os.path.isdir(path2) and 'tomcat' in item2.lower():
                                if is_tomcat_install(path2):
                                    webapps = get_tomcat_webapps(path2)
                                    if webapps and webapps not in dirs:
                                        dirs.append(webapps)
                                        print_color(f"  [+] Tomcat: {webapps}", Colors.GREEN)
                    except PermissionError:
                        pass
        except PermissionError:
            pass

    if not dirs:
        print_color("  [ ] No other web servers found", Colors.GRAY)

    return dirs


# ========== 层次 3: 进程分析 ==========
def find_directories_from_process() -> list:
    print_color("[3/5] Analyzing running web service processes...", Colors.YELLOW)
    dirs = []

    if not HAS_PSUTIL:
        print_color("  [ ] psutil not installed, skipping process analysis", Colors.GRAY)
        return dirs

    web_processes = {
        'w3wp.exe': 'IIS',
        'httpd.exe': 'Apache',
        'nginx.exe': 'Nginx',
        'java.exe': 'Tomcat/Java',
        'php-cgi.exe': 'PHP',
    }

    try:
        for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
            try:
                proc_name = proc.info['name']
                if proc_name and proc_name.lower() in [p.lower() for p in web_processes.keys()]:
                    proc_exe = proc.info['exe']
                    cmdline = proc.info['cmdline'] or []

                    # Java/Tomcat 特殊处理 - 从命令行提取 catalina.base
                    if proc_name.lower() == 'java.exe':
                        cmdline_str = ' '.join(cmdline)
                        match = re.search(r'-Dcatalina\.base=([^\s]+)', cmdline_str)
                        if match:
                            catalina_base = match.group(1).strip('"')
                            webapps_path = os.path.join(catalina_base, 'webapps')
                            if os.path.exists(webapps_path) and webapps_path not in dirs:
                                dirs.append(webapps_path)
                                print_color(f"  [+] Tomcat (process): {webapps_path}", Colors.GREEN)
                    elif proc_exe:
                        proc_dir = os.path.dirname(proc_exe)
                        server_type = web_processes.get(proc_name, 'Web Server')
                        print_color(f"  [+] {server_type} (process): {proc_dir}", Colors.GREEN)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        print_color(f"  [-] Process analysis error: {e}", Colors.GRAY)

    if not dirs:
        print_color("  [ ] No running web services found", Colors.GRAY)

    return dirs


# ========== 层次 4: 磁盘特征扫描 ==========
def find_directories_by_pattern(scan_depth: int) -> list:
    print_color(f"[4/5] Scanning disk for characteristic directories (depth {scan_depth} levels)...", Colors.YELLOW)
    dirs = []

    web_dir_patterns = ["wwwroot", "htdocs", "www", "webapps", "public_html"]

    # 获取所有磁盘驱动器
    if sys.platform == 'win32':
        drives = [f"{d}:/" for d in 'CDEFGH' if os.path.exists(f"{d}:/")]
    else:
        drives = ['/']

    # Step 1: 检查每个驱动器根目录
    for drive in drives:
        for pattern in web_dir_patterns:
            test_path = os.path.join(drive, pattern)
            if os.path.exists(test_path) and test_path not in dirs:
                dirs.append(test_path)
                print_color(f"  [+] Characteristic directory: {test_path}", Colors.GREEN)

    # Step 2: 检查常见安装路径
    common_paths = [
        "C:/inetpub", "C:/xampp", "C:/phpstudy", "C:/wamp",
        "D:/phpstudy", "E:/phpstudy",
        "C:/Apache24", "C:/nginx",
        "D:/wwwroot", "E:/wwwroot",
        "C:/wampserver",
        "C:/Program Files/Apache Software Foundation",
        "C:/Program Files (x86)/Apache Software Foundation",
    ]

    for base_path in common_paths:
        if os.path.exists(base_path):
            # 检查子目录是否匹配特征模式
            for pattern in web_dir_patterns:
                test_path = os.path.join(base_path, pattern)
                if os.path.exists(test_path) and test_path not in dirs:
                    dirs.append(test_path)
                    print_color(f"  [+] Characteristic directory: {test_path}", Colors.GREEN)

            # 检查 base_path 本身是否匹配模式
            base_name = os.path.basename(base_path)
            if base_name.lower() in [p.lower() for p in web_dir_patterns]:
                if base_path not in dirs:
                    dirs.append(base_path)
                    print_color(f"  [+] Characteristic directory: {base_path}", Colors.GREEN)

            # 对于集成环境 (phpstudy/xampp/wamp)，搜索一层深度
            if base_name.lower() in ['phpstudy', 'xampp', 'wamp', 'wampserver', 'phpstudy_pro']:
                try:
                    for sub_dir in os.listdir(base_path):
                        sub_path = os.path.join(base_path, sub_dir)
                        if os.path.isdir(sub_path):
                            for pattern in web_dir_patterns:
                                test_path = os.path.join(sub_path, pattern)
                                if os.path.exists(test_path) and test_path not in dirs:
                                    dirs.append(test_path)
                                    print_color(f"  [+] Characteristic directory: {test_path}", Colors.GREEN)
                except PermissionError:
                    pass

    if not dirs:
        print_color("  [ ] No characteristic directories found", Colors.GRAY)

    return dirs


# ========== 层次 5: 读取已保存配置 ==========
def get_saved_web_paths() -> list:
    print_color("[5/5] Reading saved configuration...", Colors.YELLOW)
    dirs = []

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, '..', 'config', 'web_paths.txt')

    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                for line in f:
                    path = line.strip()
                    if path and os.path.exists(path):
                        dirs.append(path)
                        print_color(f"  [+] Saved path: {path}", Colors.GREEN)
        except Exception:
            pass

    if not dirs:
        print_color("  [ ] No saved configuration found", Colors.GRAY)

    return dirs


# ========== 主流程 ==========
def main():
    parser = argparse.ArgumentParser(description='Web Directory Auto-Discovery Tool')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Interactive mode, confirm each directory')
    parser.add_argument('-d', '--depth', type=int, default=1,
                        help='Scan depth (default: 1)')
    args = parser.parse_args()

    Colors.init()

    print_color("=== Web Directory Auto-Discovery Tool ===", Colors.CYAN)
    print_color(f"Scan depth: {args.depth} levels\n", Colors.YELLOW)

    # 收集所有发现的目录
    all_directories = []

    # 执行所有发现方法
    all_directories.extend(find_iis_directories())
    all_directories.extend(find_other_webserver_directories())
    all_directories.extend(find_directories_from_process())
    all_directories.extend(find_directories_by_pattern(args.depth))
    all_directories.extend(get_saved_web_paths())

    # 去重并验证路径存在
    unique_dirs = []
    seen = set()
    for d in all_directories:
        normalized = os.path.normpath(d).rstrip(os.sep)
        if normalized not in seen and os.path.exists(normalized):
            seen.add(normalized)
            unique_dirs.append(normalized)

    unique_dirs.sort()

    # 显示结果
    print_color("\n========================================", Colors.CYAN)

    if not unique_dirs:
        print_color("No web directories found", Colors.RED)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(script_dir, '..', 'config', 'web_paths.txt')
        print_color(f"Please manually edit config file: {config_file}", Colors.YELLOW)
        return []

    print_color(f"Found {len(unique_dirs)} web directories:", Colors.GREEN)
    for d in unique_dirs:
        print(f"  - {d}")

    # 交互模式
    if args.interactive:
        print_color("\nStarting confirmation mode...", Colors.YELLOW)
        confirmed = []
        for d in unique_dirs:
            choice = input(f"\nConfirm '{d}' as web directory? (Y/n): ").strip().lower()
            if choice != 'n':
                confirmed.append(d)
        unique_dirs = confirmed
        print_color(f"\n[+] Confirmed {len(unique_dirs)} directories", Colors.GREEN)

    # 保存配置
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = os.path.join(script_dir, '..', 'config')
    config_file = os.path.join(config_dir, 'web_paths.txt')

    os.makedirs(config_dir, exist_ok=True)

    if unique_dirs:
        with open(config_file, 'w', encoding='utf-8') as f:
            for d in unique_dirs:
                f.write(d + '\n')

        print_color("\n========================================", Colors.CYAN)
        print_color(f"[+] Saved to config file: {config_file}", Colors.GREEN)
        print_color("\nYou can use the following commands:", Colors.YELLOW)
        print_color(f"  - View config: cat \"{config_file}\"", Colors.GRAY)
        print_color(f"  - Quick scan: python webshell_check.py", Colors.GRAY)
    else:
        print_color("\nNo directories confirmed, config file not updated", Colors.YELLOW)

    # 输出目录列表（供其他脚本使用）
    for d in unique_dirs:
        print(d)

    return unique_dirs


if __name__ == '__main__':
    main()
