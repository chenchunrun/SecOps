#!/usr/bin/env python3
"""漏洞研究工具 - 多源漏洞信息聚合与影响评估"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

def search_nvd(cve_id: str) -> Optional[Dict]:
    """查询NVD数据库"""
    try:
        import requests
        resp = requests.get(
            f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}',
            timeout=15
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get('vulnerabilities', [])
            if vulns:
                cve = vulns[0].get('cve', {})
                metrics = cve.get('metrics', {})
                cvss_data = {}
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics:
                        cvss_data = metrics[version][0]
                        break

                return {
                    'id': cve_id,
                    'description': next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), ''),
                    'cvss': cvss_data.get('cvssData', {}).get('baseScore', 'N/A'),
                    'severity': cvss_data.get('cvssData', {}).get('baseSeverity', 'N/A'),
                    'vector': cvss_data.get('cvssData', {}).get('vectorString', ''),
                    'published': cve.get('published', ''),
                    'modified': cve.get('lastModified', ''),
                    'references': [{'url': r['url'], 'source': r.get('source', '')} for r in cve.get('references', [])],
                    'cwe': next((w.get('description', [{}])[0].get('value', '') for w in cve.get('weaknesses', [])), ''),
                }
    except Exception as e:
        return {'error': str(e)}
    return None

def search_exploitdb(keyword: str) -> List[Dict]:
    """搜索ExploitDB"""
    results = []
    try:
        import subprocess
        proc = subprocess.run(
            ['searchsploit', '--json', keyword],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            for item in data.get('RESULTS_EXPLOIT', [])[:20]:
                results.append({
                    'title': item.get('Title', ''),
                    'type': item.get('Type', ''),
                    'platform': item.get('Platform', ''),
                    'date': item.get('Date', ''),
                    'path': item.get('Path', ''),
                })
    except Exception:
        pass
    return results

def assess_impact(vuln_data: Dict, context: Dict = None) -> Dict:
    """评估漏洞影响"""
    score = 0
    factors = []
    recommendations = []

    desc = vuln_data.get('description', '').lower()
    cvss = vuln_data.get('cvss', 0)

    # CVSS评分影响
    if isinstance(cvss, (int, float)):
        if cvss >= 9.0:
            score += 4
            factors.append(f'CVSS {cvss} (Critical)')
            recommendations.append('立即修复')
        elif cvss >= 7.0:
            score += 3
            factors.append(f'CVSS {cvss} (High)')
            recommendations.append('30天内修复')
        elif cvss >= 4.0:
            score += 2
            factors.append(f'CVSS {cvss} (Medium)')
            recommendations.append('90天内修复')

    # 攻击向量
    vector = vuln_data.get('vector', '')
    if 'AV:N' in vector:
        score += 2
        factors.append('远程可利用')
    if 'PR:N' in vector:
        score += 1
        factors.append('无需权限')
    if 'UI:N' in vector:
        score += 1
        factors.append('无需用户交互')

    # 关键词
    critical_kw = ['remote code execution', 'rce', 'arbitrary code', 'sql injection', 'authentication bypass']
    for kw in critical_kw:
        if kw in desc:
            score += 2
            factors.append(f'关键词: {kw}')
            break

    # 上下文评估
    if context:
        if context.get('internet_facing'):
            score += 2
            factors.append('面向互联网')
        if context.get('sensitive_data'):
            score += 1
            factors.append('处理敏感数据')

    priority = 'P0-紧急' if score >= 8 else 'P1-高' if score >= 5 else 'P2-中' if score >= 3 else 'P3-低'

    return {
        'priority': priority,
        'score': score,
        'factors': factors,
        'recommendations': recommendations or ['评估后决定修复优先级'],
    }

def main():
    parser = argparse.ArgumentParser(description='漏洞研究工具')
    parser.add_argument('query', help='CVE编号或关键词')
    parser.add_argument('--json', action='store_true', help='JSON输出')
    parser.add_argument('--impact-only', action='store_true', help='仅显示影响评估')
    parser.add_argument('--internet-facing', action='store_true', help='目标面向互联网')
    parser.add_argument('--sensitive-data', action='store_true', help='目标处理敏感数据')
    args = parser.parse_args()

    result = {
        'query': args.query,
        'timestamp': datetime.now().isoformat(),
    }

    # CVE查询
    cve_match = CVE_PATTERN.search(args.query)
    if cve_match:
        cve_id = cve_match.group(0).upper()
        nvd_data = search_nvd(cve_id)
        if nvd_data:
            result['nvd'] = nvd_data
            context = {
                'internet_facing': args.internet_facing,
                'sensitive_data': args.sensitive_data,
            }
            result['impact'] = assess_impact(nvd_data, context)

    # ExploitDB搜索
    edb = search_exploitdb(args.query)
    if edb:
        result['exploitdb'] = edb

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{'='*60}")
        print(f"🔍 漏洞研究: {args.query}")
        print(f"{'='*60}")

        if 'nvd' in result:
            nvd = result['nvd']
            if 'error' not in nvd:
                print(f"\n📋 NVD信息:")
                print(f"  描述: {nvd.get('description', '')[:200]}")
                print(f"  CVSS: {nvd.get('cvss', 'N/A')} ({nvd.get('severity', 'N/A')})")
                print(f"  CWE: {nvd.get('cwe', 'N/A')}")
                print(f"  发布: {nvd.get('published', '')[:10]}")

        if 'impact' in result:
            imp = result['impact']
            print(f"\n⚡ 影响评估: {imp['priority']} (评分: {imp['score']})")
            for f in imp['factors']:
                print(f"  • {f}")
            for r in imp['recommendations']:
                print(f"  → {r}")

        if 'exploitdb' in result:
            print(f"\n💣 ExploitDB ({len(result['exploitdb'])} 个exploit):")
            for e in result['exploitdb'][:10]:
                print(f"  [{e['type']}] {e['title']}")

    return result

if __name__ == '__main__':
    main()
