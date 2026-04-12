#!/usr/bin/env python3
"""
PCAP 流量分析 - Scapy 纯 Python 兜底方案

当 tshark 不可用时，使用 scapy 进行基础分析。
注意：scapy 是 Python 实现，性能低于 tshark，不支持某些高级字段。

用法: python3 pcap_scapy_fallback.py [选项] <file.pcap>
"""

import sys
import json
import re
import platform
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any, Optional

IS_WINDOWS = platform.system() == "Windows"

# =============================================================================
# scapy 导入（带友好提示）
# =============================================================================

def _try_import_scapy():
    """尝试导入 scapy，失败时给出友好提示"""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        return True
    except ImportError:
        return False


HAS_SCAPY = _try_import_scapy()

if not HAS_SCAPY:
    print("Error: scapy not installed.", file=sys.stderr)
    print("", file=sys.stderr)
    if IS_WINDOWS:
        print("Install scapy:", file=sys.stderr)
        print("  pip install scapy", file=sys.stderr)
    else:
        print("Install scapy:", file=sys.stderr)
        print("  pip install scapy", file=sys.stderr)
        print("  # or: pip3 install scapy", file=sys.stderr)
    print("", file=sys.stderr)
    print("Alternatively, install Wireshark for full functionality:", file=sys.stderr)
    print("  Windows: Download from https://www.wireshark.org/download.html", file=sys.stderr)
    print("  macOS:   brew install wireshark", file=sys.stderr)
    print("  Linux:   sudo apt install wireshark", file=sys.stderr)
    sys.exit(1)

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

# =============================================================================
# 分析函数
# =============================================================================

def get_basic_stats(packets) -> Dict[str, Any]:
    """获取基本统计"""
    stats = {}
    stats["packet_count"] = len(packets)

    if packets:
        first_ts = packets[0].time if hasattr(packets[0], 'time') else 0
        last_ts = packets[-1].time if hasattr(packets[-1], 'time') else first_ts
        if first_ts and last_ts:
            stats["duration_seconds"] = round(last_ts - first_ts, 3)
        stats["total_bytes"] = sum(
            len(p) for p in packets if hasattr(p, 'len')
        )

    return stats


def get_protocol_stats(packets) -> Dict[str, int]:
    """协议分布统计"""
    protocols = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            if pkt.haslayer(TCP):
                protocols["tcp"] += 1
            elif pkt.haslayer(UDP):
                if pkt.haslayer(DNS):
                    protocols["dns"] += 1
                else:
                    protocols["udp"] += 1
            elif pkt.haslayer(ICMP):
                protocols["icmp"] += 1
            else:
                protocols["ip"] += 1
        elif pkt.haslayer(ICMP):
            protocols["icmp"] += 1

    return dict(protocols.most_common(15))


def get_ip_stats(packets, limit: int = 20) -> Dict[str, List]:
    """IP 地址统计"""
    src_ips = Counter()
    dst_ips = Counter()

    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if not src.startswith(("10.", "192.168.", "172.16.", "172.17.",
                                   "172.18.", "172.19.", "172.20.", "172.21.",
                                   "172.22.", "172.23.", "172.24.", "172.25.",
                                   "172.26.", "172.27.", "172.28.", "172.29.",
                                   "172.30.", "172.31.")):
                src_ips[src] += 1
            if not dst.startswith(("10.", "192.168.", "172.16.", "172.17.",
                                   "172.18.", "172.19.", "172.20.", "172.21.",
                                   "172.22.", "172.23.", "172.24.", "172.25.",
                                   "172.26.", "172.27.", "172.28.", "172.29.",
                                   "172.30.", "172.31.")):
                dst_ips[dst] += 1

    return {
        "top_src_ips": [{"ip": ip, "count": c} for ip, c in src_ips.most_common(limit)],
        "top_dst_ips": [{"ip": ip, "count": c} for ip, c in dst_ips.most_common(limit)],
    }


def get_port_stats(packets, limit: int = 20) -> Dict[str, List]:
    """端口统计（TCP/UDP）"""
    dst_ports = Counter()

    for pkt in packets:
        if pkt.haslayer(IP):
            if pkt.haslayer(TCP):
                if pkt[TCP].dport:
                    dst_ports[pkt[TCP].dport] += 1
            elif pkt.haslayer(UDP):
                if pkt[UDP].dport:
                    dst_ports[pkt[UDP].dport] += 1

    return {
        "top_dst_ports": [{"port": port, "count": c} for port, c in dst_ports.most_common(limit)]
    }


def get_dns_queries(packets, limit: int = 50) -> List[str]:
    """DNS 查询提取"""
    domains = set()
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qr = pkt[DNSQR]
            if hasattr(qr, 'qname') and qr.qname:
                try:
                    domain = qr.qname.decode('utf-8', errors='replace').rstrip('.')
                    if domain:
                        domains.add(domain)
                except Exception:
                    pass
    return list(domains)[:limit]


def get_http_requests(packets, limit: int = 50) -> List[Dict]:
    """HTTP 请求提取（通过载荷搜索）"""
    requests = []
    seen = set()
    http_methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH "]

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            payload = bytes(pkt[TCP].payload)
            if not payload:
                continue
            for method in http_methods:
                if payload.startswith(method):
                    try:
                        text = payload.decode('utf-8', errors='replace')
                        lines = text.split('\r\n')
                        if lines:
                            request_line = lines[0]
                            host = ""
                            ua = ""
                            for line in lines[1:]:
                                if line.lower().startswith("host:"):
                                    host = line.split(":", 1)[1].strip()
                                elif line.lower().startswith("user-agent:"):
                                    ua = line.split(":", 1)[1].strip()[:100]
                                if host and ua:
                                    break

                            uri_match = request_line.split(" ", 2)
                            req_method = uri_match[0] if len(uri_match) > 0 else "?"
                            uri = uri_match[1] if len(uri_match) > 1 else "/"

                            key = f"{req_method}|{host}|{uri}"
                            if key not in seen and host:
                                seen.add(key)
                                req = {"host": host, "method": req_method, "uri": uri}
                                if ua:
                                    req["user_agent"] = ua
                                requests.append(req)
                                if len(requests) >= limit:
                                    return requests
                    except Exception:
                        pass
                    break

    return requests


def get_tls_info(packets, limit: int = 50) -> Dict[str, Any]:
    """TLS SNI 提取"""
    sni_domains = set()
    ja3_list = []

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            payload = bytes(pkt[TCP].payload)
            if len(payload) < 6:
                continue
            # TLS ClientHello detection: 0x16 = Handshake, 0x01 = ClientHello
            if payload[0] == 0x16 and payload[5] == 0x01:
                try:
                    text = payload.decode('latin-1', errors='replace')
                    # Look for SNI in ServerName extension (0x00)
                    sni_match = re.findall(r'(?:sni|server_name|host)[=:][^\x00]+([a-zA-Z0-9][-a-zA-Z0-9.*]{2,254})',
                                           text, re.IGNORECASE)
                    for s in sni_match:
                        if '.' in s and len(s) < 255:
                            sni_domains.add(s)
                except Exception:
                    pass

    return {
        "sni_domains": list(sni_domains)[:limit],
        "ja3_fingerprints": ja3_list[:20]
    }


def get_conversations(packets, limit: int = 20) -> List[Dict]:
    """TCP 会话统计"""
    conversations = Counter()
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            key = f"{pkt[IP].src}:{pkt[TCP].sport} <-> {pkt[IP].dst}:{pkt[TCP].dport}"
            conversations[key] += 1

    return [
        {"endpoints": endpoints, "packets": str(count)}
        for endpoints, count in conversations.most_common(limit)
    ]


def extract_iocs(result: Dict) -> Dict[str, List]:
    """提取 IOC"""
    iocs = {"ips": [], "domains": [], "urls": []}

    for item in result.get("ip_stats", {}).get("top_dst_ips", []):
        ip = item.get("ip", "")
        if ip and not ip.startswith("127."):
            iocs["ips"].append(ip)

    iocs["domains"] = result.get("dns_queries", [])[:30]

    for sni in result.get("tls_info", {}).get("sni_domains", []):
        if sni and sni not in iocs["domains"]:
            iocs["domains"].append(sni)

    for req in result.get("http_requests", []):
        host = req.get("host", "")
        uri = req.get("uri", "")
        if host and uri:
            iocs["urls"].append(f"http://{host}{uri}")

    return iocs


# =============================================================================
# 主分析流程
# =============================================================================

def analyze_pcap(filepath: str) -> Dict[str, Any]:
    """分析 PCAP 文件"""
    path = Path(filepath)

    if not path.exists():
        return {"error": f"File not found: {filepath}"}

    if not HAS_SCAPY:
        return {
            "error": "scapy not installed. Run: pip install scapy"
        }

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        return {"error": f"Failed to read PCAP: {e}"}

    result = {
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "engine": "scapy (fallback mode)",
        "note": "scapy-based analysis, some fields may be unavailable",
    }

    result["basic_stats"] = get_basic_stats(packets)
    result["protocol_stats"] = get_protocol_stats(packets)
    result["ip_stats"] = get_ip_stats(packets)
    result["port_stats"] = get_port_stats(packets)
    result["dns_queries"] = get_dns_queries(packets)
    result["http_requests"] = get_http_requests(packets)
    result["tls_info"] = get_tls_info(packets)
    result["conversations"] = get_conversations(packets)
    result["iocs"] = extract_iocs(result)

    summary = []
    bs = result["basic_stats"]
    if bs.get("packet_count"):
        summary.append(f"Packets: {bs['packet_count']}")
    if bs.get("duration_seconds"):
        summary.append(f"Duration: {bs['duration_seconds']}s")
    if result["dns_queries"]:
        summary.append(f"DNS queries: {len(result['dns_queries'])} domains")
    if result["http_requests"]:
        summary.append(f"HTTP requests: {len(result['http_requests'])}")
    if result["tls_info"].get("sni_domains"):
        summary.append(f"TLS connections: {len(result['tls_info']['sni_domains'])} domains")

    result["summary"] = " | ".join(summary) if summary else "Unable to extract summary"
    return result


# =============================================================================
# 输出
# =============================================================================

def print_result(result: Dict):
    """打印结果"""
    if "error" in result:
        print(f"Error: {result['error']}")
        return

    print(f"\n{'=' * 60}")
    print(f"File: {result['filename']} ({result['size_bytes']} bytes)")
    print(f"Engine: {result.get('engine', 'unknown')}")
    if result.get("note"):
        print(f"Note: {result['note']}")
    print(f"{'=' * 60}")

    stats = result.get("basic_stats", {})
    if stats:
        print(f"\n[*] Basic Statistics")
        print(f"    Packets: {stats.get('packet_count', 'N/A')}")
        print(f"    Total bytes: {stats.get('total_bytes', 'N/A')}")
        dur = stats.get('duration_seconds')
        print(f"    Duration: {f'{dur:.3f}' if dur else 'N/A'} seconds")

    protos = result.get("protocol_stats", {})
    if protos:
        print(f"\n[*] Protocol Distribution")
        for proto, count in sorted(protos.items(), key=lambda x: -x[1])[:10]:
            print(f"    {proto}: {count}")

    dst_ips = result.get("ip_stats", {}).get("top_dst_ips", [])
    if dst_ips:
        print(f"\n[*] Top Destination IPs")
        for p in dst_ips[:10]:
            print(f"    {p['ip']} - {p['count']} packets")

    ports = result.get("port_stats", {}).get("top_dst_ports", [])
    if ports:
        print(f"\n[*] Top Destination Ports")
        for p in ports[:10]:
            print(f"    :{p['port']} - {p['count']} packets")

    dns = result.get("dns_queries", [])
    if dns:
        print(f"\n[*] DNS Queries ({len(dns)} total)")
        for d in dns[:15]:
            print(f"    {d}")
        if len(dns) > 15:
            print(f"    ... and {len(dns) - 15} more")

    http = result.get("http_requests", [])
    if http:
        print(f"\n[*] HTTP Requests ({len(http)} total)")
        for r in http[:10]:
            host = r.get("host", "")
            uri = r.get("uri", "")
            print(f"    {r.get('method', 'GET')} {host}{uri[:60]}")
        if len(http) > 10:
            print(f"    ... and {len(http) - 10} more")

    tls = result.get("tls_info", {})
    sni = tls.get("sni_domains", [])
    if sni:
        print(f"\n[*] TLS SNI Domains ({len(sni)} total)")
        for s in sni[:15]:
            print(f"    {s}")
        if len(sni) > 15:
            print(f"    ... and {len(sni) - 15} more")

    iocs = result.get("iocs", {})
    print(f"\n[*] IOC Summary")
    ips = iocs.get("ips", [])
    if ips:
        print(f"    IPs ({len(ips)}): {', '.join(ips[:10])}")
        if len(ips) > 10:
            print(f"      ... and {len(ips) - 10} more")
    domains = iocs.get("domains", [])
    if domains:
        print(f"    Domains ({len(domains)}): {', '.join(domains[:10])}")
        if len(domains) > 10:
            print(f"      ... and {len(domains) - 10} more")

    print(f"\n{'=' * 60}")
    print(f"Summary: {result.get('summary', '')}")
    print()


# =============================================================================
# 入口
# =============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="PCAP traffic analysis - scapy fallback (no tshark required)"
    )
    parser.add_argument("file", help="PCAP file path")
    parser.add_argument("-j", "--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    result = analyze_pcap(args.file)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_result(result)


if __name__ == "__main__":
    main()
