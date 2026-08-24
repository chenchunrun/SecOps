#!/usr/bin/env python3
"""
vuln_triage.py — 漏洞扫描结果快速分诊脚本

将 Nuclei JSON 输出按风险等级分类，生成处置建议。
支持读取 Nuclei JSON 文件或 stdin。

用法:
    python3 vuln_triage.py -i nuclei_results.json
    cat results.json | python3 vuln_triage.py
    python3 vuln_triage.py -i results.json -o triaged.csv
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path

RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

ATTACK_MAPPING = {
    "sql-injection": ("T1190.001", "A03 Injection (CWE-89)"),
    "xss": ("T1190.002", "A03 Injection (CWE-79)"),
    "ssrf": ("T1190.003", "A10 SSRF (CWE-918)"),
    "rce": ("T1190", "A03 Injection"),
    "lfi": ("T1190.004", "A01 Broken Access Control"),
    "rfi": ("T1190.004", "A01 Broken Access Control"),
    "misconfiguration": ("T1190", "A05 Security Misconfiguration"),
    "exposure": ("T1592", "A04 Insecure Design"),
    "takeover": ("T1568", "A01 Broken Access Control"),
    "default-login": ("T1078", "A07 Auth Failures"),
    "dns": ("T1071.004", "A04 Insecure Design"),
    "backup": ("T1005", "A04 Insecure Design"),
}

FIX_PRIORITY = {
    "critical": "P0 - 立即修复 (24h内)",
    "high": "P1 - 优先修复 (72h内)",
    "medium": "P2 - 计划修复 (1周内)",
    "low": "P3 - 评估后处理",
    "info": "P4 - 信息记录",
}


def triage_nuclei_results(results):
    """分诊 Nuclei 扫描结果"""
    triaged = []
    for finding in results:
        severity = finding.get("info", {}).get("severity", "info").lower()
        template_id = finding.get("template-id", finding.get("templateID", "unknown"))
        match = finding.get("matched-at", finding.get("matched_at", "unknown"))
        vuln_name = finding.get("info", {}).get("name", template_id)
        tags = finding.get("info", {}).get("tags", {})
        cve_tags = [t for t in (tags if isinstance(tags, list) else []) if t.lower().startswith("cve")]
        
        # ATT&CK 映射
        attack_id, owasp_mapping = ("T1190", "A03 Injection")
        vuln_lower = vuln_name.lower() + " " + template_id.lower()
        for keyword, (aid, owasp) in ATTACK_MAPPING.items():
            if keyword in vuln_lower:
                attack_id, owasp_mapping = aid, owasp
                break

        triaged.append({
            "severity": severity,
            "risk_score": RISK_ORDER.get(severity, 0),
            "vuln_name": vuln_name,
            "template_id": template_id,
            "matched_at": match,
            "cve": cve_tags[0] if cve_tags else "",
            "attack_id": attack_id,
            "owasp": owasp_mapping,
            "fix_priority": FIX_PRIORITY.get(severity, "P4"),
            "timestamp": finding.get("timestamp", ""),
            "raw": finding,
        })
    
    triaged.sort(key=lambda x: x["risk_score"], reverse=True)
    return triaged


def print_summary(triaged):
    """打印分诊摘要"""
    total = len(triaged)
    by_severity = {}
    for t in triaged:
        by_severity[t["severity"]] = by_severity.get(t["severity"], 0) + 1
    
    print(f"\n{'='*60}")
    print(f"📊 漏洞扫描分诊报告 — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}")
    print(f"\n总计发现: {total} 个漏洞\n")
    
    print("风险分布:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = by_severity.get(sev, 0)
        if count > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}
            print(f"  {emoji.get(sev, '?')} {sev.upper():10s}: {count}")
    
    print(f"\n{'─'*60}")
    print(f"{'严重性':<10} {'漏洞名称':<35} {'ATT&CK':<12} {'OWASP':<25} {'位置':<30}")
    print(f"{'─'*60}")
    
    for t in triaged[:30]:  # Top 30
        print(f"{t['severity']:<10} {t['vuln_name'][:34]:<35} {t['attack_id']:<12} {t['owasp'][:24]:<25} {t['matched_at'][:29]:<30}")
    
    if total > 30:
        print(f"\n... 还有 {total - 30} 个漏洞未显示")
    
    print(f"\n{'='*60}")
    print("处置建议:")
    for sev in ["critical", "high"]:
        count = by_severity.get(sev, 0)
        if count > 0:
            print(f"  {FIX_PRIORITY[sev]}")
    print(f"{'='*60}\n")


def to_csv(triaged, filepath):
    """导出为 CSV"""
    import csv
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "severity", "vuln_name", "template_id", "matched_at",
            "cve", "attack_id", "owasp", "fix_priority", "timestamp"
        ])
        writer.writeheader()
        for t in triaged:
            writer.writerow({k: t[k] for k in [
                "severity", "vuln_name", "template_id", "matched_at",
                "cve", "attack_id", "owasp", "fix_priority", "timestamp"
            ]})
    print(f"✅ CSV 导出: {filepath}")


def main():
    parser = argparse.ArgumentParser(description="Nuclei 漏洞扫描结果分诊工具")
    parser.add_argument("-i", "--input", help="Nuclei JSON 输出文件")
    parser.add_argument("-o", "--output", help="导出 CSV 文件路径")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    args = parser.parse_args()
    
    # 读取数据
    if args.input:
        with open(args.input, "r") as f:
            content = f.read()
    else:
        content = sys.stdin.read()
    
    # Nuclei JSON 是每行一个 JSON 对象（JSONL）
    results = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                # 尝试作为 JSON 数组
                try:
                    results = json.loads(content)
                    break
                except json.JSONDecodeError:
                    continue
    
    if not results:
        print("❌ 未找到有效的扫描结果", file=sys.stderr)
        sys.exit(1)
    
    # 分诊
    triaged = triage_nuclei_results(results)
    
    # 输出
    if args.json:
        print(json.dumps(triaged, indent=2, ensure_ascii=False, default=str))
    else:
        print_summary(triaged)
    
    if args.output:
        to_csv(triaged, args.output)


if __name__ == "__main__":
    main()
