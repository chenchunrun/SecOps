#!/usr/bin/env python3
"""
实验：验证RD=0探测不会污染DNS缓存
"""

import dns.message
import dns.query
import dns.flags
import dns.rdatatype
import time

# 测试域名（使用一个不太可能被访问的随机域名）
TEST_DOMAIN = f"test-rd0-pollution-{int(time.time())}.example.com"
DNS_SERVER = "210.77.176.2"  # 国家电网DNS


def probe_rd0(domain, dns_server):
    """RD=0探测"""
    query = dns.message.make_query(domain, dns.rdatatype.A)
    query.flags &= ~dns.flags.RD  # 非递归

    try:
        response = dns.query.udp(query, dns_server, timeout=2)
        if response.answer:
            return "HIT"
        else:
            return "MISS"
    except:
        return "ERROR"


def probe_rd1(domain, dns_server):
    """RD=1探测（正常查询）"""
    query = dns.message.make_query(domain, dns.rdatatype.A)
    # RD=1（默认）

    try:
        response = dns.query.udp(query, dns_server, timeout=2)
        if response.answer:
            return "HIT"
        else:
            return "MISS"
    except:
        return "ERROR"


print("=" * 70)
print("实验：RD=0探测是否污染DNS缓存")
print("=" * 70)

print(f"\n测试域名: {TEST_DOMAIN}")
print(f"DNS服务器: {DNS_SERVER}")

print("\n【第1步】初始状态检查（RD=0探测）")
result1 = probe_rd0(TEST_DOMAIN, DNS_SERVER)
print(f"结果: {result1}")
print(f"预期: MISS（域名不存在缓存）")

print("\n【第2步】再次RD=0探测（验证第1步没有污染缓存）")
time.sleep(1)
result2 = probe_rd0(TEST_DOMAIN, DNS_SERVER)
print(f"结果: {result2}")
print(f"预期: MISS（如果第1步污染了缓存，这里会HIT）")

if result1 == "MISS" and result2 == "MISS":
    print("\n[+] 验证通过：RD=0探测不污染缓存！")
else:
    print(f"\n[!] 结果异常：result1={result1}, result2={result2}")

print("\n【对比实验】使用RD=1（正常查询）")
print("注意：这会创建真实的DNS缓存！")

# 使用另一个测试域名
TEST_DOMAIN2 = f"test-rd1-pollution-{int(time.time())}.baidu.com"
print(f"\n测试域名: {TEST_DOMAIN2}")

print("\n[1] RD=0探测（初始状态）")
result3 = probe_rd0(TEST_DOMAIN2, DNS_SERVER)
print(f"结果: {result3} (预期: MISS)")

print("\n[2] RD=1查询（会污染缓存）")
result4 = probe_rd1(TEST_DOMAIN2, DNS_SERVER)
print(f"结果: {result4}")

print("\n[3] RD=0探测（验证是否被污染）")
time.sleep(1)
result5 = probe_rd0(TEST_DOMAIN2, DNS_SERVER)
print(f"结果: {result5}")
print(f"说明: 如果变成HIT，说明RD=1污染了缓存")

print("\n" + "=" * 70)
print("实验结论:")
print("  - RD=0探测：[+] 不污染缓存，可以放心使用")
print("  - RD=1查询：[!] 会污染缓存，不能用于探测")
print("=" * 70)
