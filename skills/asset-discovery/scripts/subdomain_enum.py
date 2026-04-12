#!/usr/bin/env python3
"""
子域名枚举工具
支持多种数据源：DNS 爆破、CT Logs、搜索引擎
"""

import argparse
import json
import sys
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# 常见子域名字典
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "admin", "administrator",
    "api", "dev", "staging", "test", "beta", "portal", "secure", "login",
    "mobile", "m", "app", "apps", "blog", "shop", "store", "support", "help",
    "docs", "doc", "wiki", "forum", "community", "static", "assets", "cdn",
    "img", "images", "media", "video", "files", "download", "uploads",
    "gateway", "gw", "proxy", "cache", "db", "database", "mysql", "postgres",
    "redis", "mongo", "elastic", "es", "kibana", "grafana", "prometheus",
    "jenkins", "gitlab", "github", "git", "svn", "ci", "cd", "deploy",
    "k8s", "kubernetes", "docker", "registry", "harbor", "nexus",
    "oa", "erp", "crm", "hr", "finance", "internal", "intranet", "extranet",
    "vpn", "ssl", "sso", "auth", "oauth", "cas", "ldap", "ad",
    "backup", "bak", "old", "new", "v1", "v2", "v3", "demo", "sandbox",
    "uat", "qa", "prod", "production", "stage", "pre", "preprod"
]


def resolve_domain(domain: str, record_type: str = "A") -> List[str]:
    """解析域名"""
    if not HAS_DNSPYTHON:
        try:
            if record_type == "A":
                return [socket.gethostbyname(domain)]
        except socket.gaierror:
            return []
        return []

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def check_subdomain(subdomain: str, domain: str) -> Optional[Dict]:
    """检查子域名是否存在"""
    fqdn = f"{subdomain}.{domain}"
    ips = resolve_domain(fqdn)

    if ips:
        return {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "ips": ips,
            "source": "dns_bruteforce"
        }
    return None


def dns_bruteforce(domain: str, wordlist: List[str] = None, threads: int = 10) -> List[Dict]:
    """DNS 爆破枚举子域名"""
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_subdomain, sub, domain): sub
            for sub in wordlist
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                print(f"[+] Found: {result['fqdn']} -> {', '.join(result['ips'])}")

    return results


def query_crtsh(domain: str) -> List[Dict]:
    """从 crt.sh 查询 CT Logs"""
    if not HAS_REQUESTS:
        print("[-] requests 库未安装，跳过 CT Logs 查询")
        return []

    results = []
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            seen = set()

            for entry in data:
                name = entry.get("name_value", "")
                # 处理多行证书名称
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(domain) and n not in seen:
                        seen.add(n)
                        # 提取子域名部分
                        if n == domain:
                            subdomain = "@"
                        else:
                            subdomain = n.replace(f".{domain}", "")

                        results.append({
                            "subdomain": subdomain,
                            "fqdn": n,
                            "source": "ct_logs",
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", "")
                        })

            print(f"[+] CT Logs 发现 {len(results)} 个子域名")
    except Exception as e:
        print(f"[-] CT Logs 查询失败: {e}")

    return results


def merge_results(results_list: List[List[Dict]]) -> List[Dict]:
    """合并去重结果"""
    seen = {}

    for results in results_list:
        for r in results:
            fqdn = r["fqdn"]
            if fqdn not in seen:
                seen[fqdn] = r
            else:
                # 合并来源
                existing = seen[fqdn]
                if "sources" not in existing:
                    existing["sources"] = [existing.get("source", "unknown")]
                if r.get("source") not in existing["sources"]:
                    existing["sources"].append(r.get("source"))
                # 合并 IP
                if "ips" in r and "ips" in existing:
                    existing["ips"] = list(set(existing["ips"] + r["ips"]))

    return list(seen.values())


def resolve_all(results: List[Dict], threads: int = 10) -> List[Dict]:
    """解析所有发现的域名"""
    def resolve_one(r):
        if "ips" not in r or not r["ips"]:
            ips = resolve_domain(r["fqdn"])
            r["ips"] = ips
            r["alive"] = len(ips) > 0
        else:
            r["alive"] = True
        return r

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = list(executor.map(resolve_one, results))

    return results


def main():
    parser = argparse.ArgumentParser(description="子域名枚举工具")
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("-w", "--wordlist", help="自定义字典文件")
    parser.add_argument("-t", "--threads", type=int, default=10, help="并发线程数")
    parser.add_argument("--no-bruteforce", action="store_true", help="跳过 DNS 爆破")
    parser.add_argument("--no-ct", action="store_true", help="跳过 CT Logs 查询")
    parser.add_argument("-o", "--output", help="输出文件 (JSON)")
    parser.add_argument("--alive-only", action="store_true", help="仅输出存活域名")

    args = parser.parse_args()

    domain = args.domain.lower().strip()
    print(f"[*] 目标域名: {domain}")

    all_results = []

    # CT Logs 查询
    if not args.no_ct:
        print("[*] 查询 CT Logs...")
        ct_results = query_crtsh(domain)
        all_results.append(ct_results)

    # DNS 爆破
    if not args.no_bruteforce:
        print("[*] DNS 爆破枚举...")
        wordlist = COMMON_SUBDOMAINS
        if args.wordlist:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [line.strip() for line in f if line.strip()]

        brute_results = dns_bruteforce(domain, wordlist, args.threads)
        all_results.append(brute_results)

    # 合并结果
    merged = merge_results(all_results)
    print(f"[*] 合并后共 {len(merged)} 个唯一子域名")

    # 解析所有域名
    print("[*] 解析域名...")
    resolved = resolve_all(merged, args.threads)

    # 统计
    alive = [r for r in resolved if r.get("alive")]
    print(f"[+] 存活域名: {len(alive)}/{len(resolved)}")

    # 输出
    if args.alive_only:
        output_data = alive
    else:
        output_data = resolved

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        print(f"[+] 结果已保存到: {args.output}")
    else:
        print("\n=== 枚举结果 ===")
        for r in output_data:
            status = "[+]" if r.get("alive") else "[-]"
            ips = ", ".join(r.get("ips", [])) or "N/A"
            print(f"{status} {r['fqdn']} -> {ips}")


if __name__ == "__main__":
    main()
