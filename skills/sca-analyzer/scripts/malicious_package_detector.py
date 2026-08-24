#!/usr/bin/env python3
"""
malicious_package_detector.py — 恶意开源包检测器

扫描项目的依赖清单，检测可能的供应链攻击指标：
- Typosquatting 包名
- 可疑 postinstall/install 脚本
- 已知恶意包模式

用法:
    python3 malicious_package_detector.py --project /path/to/project
    python3 malicious_package_detector.py --lockfile package-lock.json
"""

import json
import re
import argparse
import os
from pathlib import Path

# 已知恶意包模式（示例，实际应从 OSV/npm advisory 获取）
KNOWN_MALICIOUS_PACKAGES = {
    "event-stream", "flatmap-stream", "ua-parser-js", "coa", "rc",
    "node-ipc", "peacestorm", "colors-2", "faker-5",
}

# Typosquatting 检测：常见字母交换/重复
TYPOSQUAT_PATTERNS = {
    "lodash": ["lodas", "lodasH", "l0dash", "lodahs"],
    "react": ["reactt", "reac", "rceact", "reactjs"],
    "express": ["expres", "expresss", "xpress", "exprss"],
    "request": ["requets", "reqeust", "requestt"],
    "axios": ["axois", "axos", "axxios"],
    "chalk": ["chak", "chalkk", "cahalk"],
    "commander": ["comander", "commandr", "commnder"],
    "moment": ["momment", "momentt", "mment"],
    "webpack": ["webpak", "webpcak", "webpackk"],
    "typescript": ["typescrit", "typscript", "typescriptt"],
}

# 可疑安装脚本模式
SUSPICIOUS_SCRIPT_PATTERNS = [
    r"curl\s+https?://",
    r"wget\s+https?://",
    r"eval\s*\(",
    r"base64\s+-d",
    r"/dev/tcp/",
    r"python\s+-c\s+['\"]exec",
    r"require\s*\(\s*['\"]child_process['\"]\s*\)",
    r"discord\.com/api/webhooks",
    r"pastebin\.com",
    r"\.ssh/id_rsa",
    r"process\.env\.(AWS_|GITHUB_|NPM_|NODE_)",
    r"ngrok\.io",
    r"ngrok\.app",
]


def detect_typosquatting(package_name):
    """检测 Typosquatting 包名"""
    hits = []
    name_lower = package_name.lower()
    
    # 检查已知恶意包
    if name_lower in KNOWN_MALICIOUS_PACKAGES:
        hits.append({"type": "known_malicious", "package": package_name, "severity": "critical"})
    
    # 检查 typosquat 模式
    for legit, typos in TYPOSQUAT_PATTERNS.items():
        if name_lower in [t.lower() for t in typos]:
            hits.append({
                "type": "typosquatting",
                "package": package_name,
                "target": legit,
                "severity": "high",
            })
    
    # 通用 typosquat 启发式检测
    if len(package_name) > 3:
        # 检查双字母结尾（如 reactt, expresss）
        if package_name[-1] == package_name[-2] and package_name[-1] == package_name[-3]:
            hits.append({
                "type": "suspicious_repeat",
                "package": package_name,
                "severity": "medium",
            })
    
    return hits


def detect_suspicious_scripts(scripts_content):
    """检测可疑的安装脚本"""
    hits = []
    for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
        matches = re.finditer(pattern, scripts_content, re.IGNORECASE)
        for match in matches:
            # 获取上下文
            start = max(0, match.start() - 30)
            end = min(len(scripts_content), match.end() + 30)
            context = scripts_content[start:end].replace("\n", " ")
            hits.append({
                "type": "suspicious_script",
                "pattern": pattern,
                "context": context,
                "severity": "high",
            })
    return hits


def parse_package_lock(lockfile_path):
    """解析 package-lock.json"""
    with open(lockfile_path) as f:
        data = json.load(f)
    
    packages = []
    if "packages" in data:
        for name, info in data["packages"].items():
            if name and name != "":
                clean_name = name.replace("node_modules/", "")
                if clean_name:
                    packages.append({
                        "name": clean_name,
                        "version": info.get("version", ""),
                        "resolved": info.get("resolved", ""),
                    })
    elif "dependencies" in data:
        for name, info in data["dependencies"].items():
            packages.append({
                "name": name,
                "version": info.get("version", ""),
                "resolved": info.get("resolved", ""),
            })
    return packages


def parse_requirements(requirements_path):
    """解析 requirements.txt"""
    packages = []
    with open(requirements_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                # 解析 package==version 格式
                match = re.match(r"^([a-zA-Z0-9_-]+)\s*[=<>~!]+", line)
                if match:
                    packages.append({
                        "name": match.group(1),
                        "version": line[len(match.group(0)):].strip(),
                        "resolved": "",
                    })
                else:
                    packages.append({"name": line, "version": "", "resolved": ""})
    return packages


def scan_project(project_path):
    """扫描项目依赖"""
    project = Path(project_path)
    findings = []
    
    # package-lock.json
    lockfile = project / "package-lock.json"
    if lockfile.exists():
        packages = parse_package_lock(lockfile)
        for pkg in packages:
            hits = detect_typosquatting(pkg["name"])
            findings.extend([{**h, "source": "package-lock.json"} for h in hits])
        
        # 检查 package.json 中的 scripts
        pkg_json = project / "package.json"
        if pkg_json.exists():
            with open(pkg_json) as f:
                pkg_data = json.load(f)
            scripts = pkg_data.get("scripts", {})
            scripts_str = json.dumps(scripts)
            hits = detect_suspicious_scripts(scripts_str)
            findings.extend([{**h, "source": "package.json scripts"} for h in hits])
    
    # requirements.txt
    reqfile = project / "requirements.txt"
    if reqfile.exists():
        packages = parse_requirements(reqfile)
        for pkg in packages:
            hits = detect_typosquatting(pkg["name"])
            findings.extend([{**h, "source": "requirements.txt"} for h in hits])
    
    # poetry.lock
    poetry_lock = project / "poetry.lock"
    if poetry_lock.exists():
        content = poetry_lock.read_text()
        # 简单提取包名
        names = re.findall(r'name = "([^"]+)"', content)
        for name in names:
            hits = detect_typosquatting(name)
            findings.extend([{**h, "source": "poetry.lock"} for h in hits])
    
    return findings


def print_report(findings):
    """打印检测报告"""
    if not findings:
        print("\n✅ 未检测到可疑包或脚本模式")
        return
    
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))
    
    print(f"\n{'='*60}")
    print(f"🚨 供应链安全检测结果")
    print(f"{'='*60}")
    print(f"发现 {len(findings)} 个风险项:\n")
    
    for f in findings:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        print(f"  {emoji.get(f.get('severity'), '?')} [{f['severity'].upper()}] {f['type']}")
        print(f"    来源: {f.get('source', 'unknown')}")
        if "package" in f:
            print(f"    包名: {f['package']}")
        if "target" in f:
            print(f"    仿冒目标: {f['target']}")
        if "context" in f:
            print(f"    上下文: ...{f['context']}...")
        if "pattern" in f:
            print(f"    匹配模式: {f['pattern']}")
        print()
    
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="恶意开源包检测器")
    parser.add_argument("--project", "-p", help="项目根目录路径")
    parser.add_argument("--lockfile", "-l", help="锁文件路径 (package-lock.json)")
    parser.add_argument("--json", action="store_true", help="JSON 格式输出")
    args = parser.parse_args()
    
    findings = []
    
    if args.lockfile:
        if "package-lock" in args.lockfile:
            packages = parse_package_lock(args.lockfile)
        elif "requirements" in args.lockfile:
            packages = parse_requirements(args.lockfile)
        else:
            print(f"❌ 不支持的锁文件类型", file=sys.stderr)
            return
        for pkg in packages:
            hits = detect_typosquatting(pkg["name"])
            findings.extend(hits)
    elif args.project:
        findings = scan_project(args.project)
    else:
        parser.print_help()
        return
    
    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
    else:
        print_report(findings)


if __name__ == "__main__":
    main()
