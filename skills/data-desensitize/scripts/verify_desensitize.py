#!/usr/bin/env python3
"""脱敏完整性验证工具 - 确保脱敏输出中无残留敏感数据"""

import argparse
import json
import re
import sys
from pathlib import Path
from datetime import datetime

# 导入主脱敏器的检测模式
sys.path.insert(0, str(Path(__file__).parent))
from desensitizer import SENSITIVE_PATTERNS, detect_sensitive_data

def verify_desensitize(output_file: str, original_file: str = None) -> dict:
    """
    验证脱敏输出的完整性
    返回验证报告 dict
    """
    output_content = Path(output_file).read_text(errors='ignore')
    
    # 1. 检查输出中是否还有敏感数据残留
    residual_findings = detect_sensitive_data(output_content)
    
    # 2. 检查占位符格式正确性
    placeholder_pattern = re.compile(r'\[(?:PUBLIC_IP|PRIVATE_IP|DOMAIN|EMAIL|PHONE|IDCARD|BANKCARD|CREDITCARD|APIKEY|CREDENTIAL|JWT|PRIVATE_KEY|CONNSTR|ORG|PRODUCT|HOST|MAC|PERSON|SSN)_\d+\]')
    placeholders_found = set(placeholder_pattern.findall(output_content))
    
    # 3. 如果有原始文件，对比覆盖率
    coverage = None
    if original_file:
        original_content = Path(original_file).read_text(errors='ignore')
        original_findings = detect_sensitive_data(original_content)
        
        # 检查每个原始敏感值是否在输出中被替换
        original_values = set(f['value'] for f in original_findings)
        remaining_values = set()
        for val in original_values:
            if val in output_content:
                remaining_values.add(val)
        
        coverage = {
            "total_sensitive": len(original_values),
            "replaced": len(original_values) - len(remaining_values),
            "remaining": len(remaining_values),
            "coverage_rate": round((len(original_values) - len(remaining_values)) / max(len(original_values), 1) * 100, 1),
            "remaining_values": list(remaining_values)[:10],  # 最多显示10个
        }
    
    # 4. 统计占位符类型
    placeholder_types = {}
    for ph in placeholders_found:
        ptype = re.match(r'\[(\w+)_', ph).group(1)
        placeholder_types[ptype] = placeholder_types.get(ptype, 0) + 1
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "output_file": output_file,
        "original_file": original_file,
        "status": "PASS" if len(residual_findings) == 0 else "FAIL",
        "residual_findings": len(residual_findings),
        "residual_details": [
            {"type": f['type'], "label": f['label'], "value": f['masked']}
            for f in residual_findings[:20]
        ],
        "placeholders_found": len(placeholders_found),
        "placeholder_types": placeholder_types,
        "coverage": coverage,
    }
    
    return report

def main():
    parser = argparse.ArgumentParser(description='脱敏完整性验证工具')
    parser.add_argument('-o', '--output', required=True, help='脱敏后的输出文件')
    parser.add_argument('--original', help='原始文件（可选，用于覆盖率对比）')
    parser.add_argument('--json', action='store_true', help='JSON 输出')
    args = parser.parse_args()
    
    report = verify_desensitize(args.output, args.original)
    
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        status_icon = "✅" if report["status"] == "PASS" else "❌"
        print(f"\n{'='*50}")
        print(f"{status_icon} 脱敏验证报告")
        print(f"{'='*50}")
        print(f"状态: {report['status']}")
        print(f"残留敏感数据: {report['residual_findings']}")
        print(f"占位符数量: {report['placeholders_found']}")
        
        if report['placeholder_types']:
            print(f"\n占位符分布:")
            for ptype, count in sorted(report['placeholder_types'].items()):
                print(f"  [{ptype}] × {count}")
        
        if report['residual_findings'] > 0:
            print(f"\n⚠️ 残留详情:")
            for f in report['residual_details']:
                print(f"  🔴 [{f['label']}] {f['value']}")
        
        if report['coverage']:
            c = report['coverage']
            print(f"\n覆盖率: {c['coverage_rate']}% ({c['replaced']}/{c['total_sensitive']})")
            if c['remaining'] > 0:
                print(f"⚠️ 未替换的敏感值: {c['remaining']}")
                for v in c['remaining_values']:
                    masked = v[:4] + '*' * (len(v) - 8) + v[-4:] if len(v) > 8 else '****'
                    print(f"  → {masked}")
        
        print()
    
    sys.exit(0 if report["status"] == "PASS" else 1)

if __name__ == '__main__':
    main()
