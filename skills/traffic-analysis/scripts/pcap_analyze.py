#!/usr/bin/env python3
"""
PCAP 流量分析 - 基于 tshark / capinfos

优先级（从高到低）：
1. CYBERSEC_TSHARK_PATH / CYBERSEC_CAPINFOS_PATH 环境变量（由应用注入）
2. shutil.which() PATH 查找
3. 标准安装路径（Windows: C:\\Program Files\\Wireshark\\）

用法: python3 pcap_analyze.py [选项] <file.pcap>
"""

import os
import subprocess
import sys
import json
import re
import shutil
import platform
from pathlib import Path
from collections import Counter
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

IS_WINDOWS = platform.system() == "Windows"

# =============================================================================
# 工具路径发现
# =============================================================================

def _resolve_tool(name: str, env_var: str, std_paths: List[str]) -> Optional[str]:
    """
    按优先级解析工具路径。

    优先级：
    1. CYBERSEC_*_PATH 环境变量（应用注入）
    2. shutil.which() PATH 查找
    3. Windows 标准安装路径
    """
    # 1. 环境变量（最高优先级）
    env_path = os.environ.get(env_var)
    if env_path:
        p = Path(env_path)
        if p.exists() and p.is_file():
            return str(p)

    # 2. shutil.which PATH 查找
    found = shutil.which(name)
    if found:
        return found

    # 3. Windows 标准安装路径
    if IS_WINDOWS:
        for base in std_paths:
            p = Path(base)
            if p.exists() and p.is_file():
                return str(p)

    return None


def _resolve_tshark() -> Optional[str]:
    """解析 tshark 路径"""
    std_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    return _resolve_tool("tshark", "CYBERSEC_TSHARK_PATH", std_paths)


def _resolve_capinfos() -> Optional[str]:
    """解析 capinfos 路径"""
    std_paths = [
        r"C:\Program Files\Wireshark\capinfos.exe",
        r"C:\Program Files (x86)\Wireshark\capinfos.exe",
    ]
    return _resolve_tool("capinfos", "CYBERSEC_CAPINFOS_PATH", std_paths)


# =============================================================================
# 工具检查
# =============================================================================

def check_tshark() -> Tuple[bool, Optional[str]]:
    """检查 tshark 是否可用，返回 (是否可用, 路径)"""
    path = _resolve_tshark()
    return (path is not None, path)


def check_capinfos() -> Tuple[bool, Optional[str]]:
    """检查 capinfos 是否可用，返回 (是否可用, 路径)"""
    path = _resolve_capinfos()
    return (path is not None, path)


# =============================================================================
# 命令执行
# =============================================================================

def run_tshark(pcap: str, args: List[str], timeout: int = 60) -> str:
    """运行 tshark 命令"""
    tshark_path = _resolve_tshark()
    if not tshark_path:
        return ""
    cmd = [tshark_path, "-r", pcap] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def run_capinfos(pcap: str, args: List[str], timeout: int = 30) -> str:
    """运行 capinfos 命令"""
    capinfos_path = _resolve_capinfos()
    if not capinfos_path:
        return ""
    cmd = [capinfos_path, pcap] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


# =============================================================================
# 分析函数
# =============================================================================

def get_basic_stats(pcap: str) -> Dict[str, Any]:
    """获取基本统计"""
    stats = {}

    # 包数量和时间（capinfos 更可靠）
    output = run_capinfos(pcap, ["-c", "-e", "-a"])
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("Number of packets:"):
            try:
                stats["packet_count"] = int(line.split(":")[-1].strip())
            except ValueError:
                pass
        elif "Duration" in line.lower() and ":" in line:
            # 格式: HH:MM:SS 或秒
            parts = line.split(":")
            if len(parts) == 3:
                try:
                    h, m, s = float(parts[0]), float(parts[1]), float(parts[2])
                    stats["duration_seconds"] = h * 3600 + m * 60 + s
                except ValueError:
                    pass

    # 通过 tshark 补充字节数
    output2 = run_tshark(pcap, ["-q", "-z", "io,stat,0"])
    for line in output2.split("\n"):
        if "<>" in line and "|" in line:
            parts = line.split("|")
            if len(parts) >= 4:
                try:
                    stats["packet_count"] = int(parts[2].strip())
                    # 解析字节数（可能有 K/M/G 后缀）
                    byte_str = parts[3].strip()
                    if byte_str.endswith("k") or byte_str.endswith("K"):
                        stats["total_bytes"] = int(float(byte_str[:-1]) * 1024)
                    elif byte_str.endswith("M"):
                        stats["total_bytes"] = int(float(byte_str[:-1]) * 1024 * 1024)
                    elif byte_str.endswith("G"):
                        stats["total_bytes"] = int(float(byte_str[:-1]) * 1024 * 1024 * 1024)
                    else:
                        stats["total_bytes"] = int(byte_str)
                except (ValueError, IndexError):
                    pass

    return stats


def get_protocol_stats(pcap: str) -> Dict[str, int]:
    """协议分布统计"""
    output = run_tshark(pcap, ["-q", "-z", "io,phs"])
    protocols = {}

    for line in output.split("\n"):
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("Protocol") or line.startswith("Filter"):
            continue
        match = re.match(r'(\w+)\s+frames:(\d+)', line)
        if match:
            proto = match.group(1).lower()
            count = int(match.group(2))
            protocols[proto] = count

    main_protos = ["tcp", "udp", "icmp", "http", "dns", "tls", "ssh", "ftp", "smtp", "smb", "arp", "sctp"]
    return {k: v for k, v in protocols.items() if k in main_protos}


def get_ip_stats(pcap: str, limit: int = 20) -> Dict[str, List]:
    """IP 地址统计"""
    src_output = run_tshark(pcap, ["-T", "fields", "-e", "ip.src"])
    src_ips = [
        ip for ip in src_output.strip().split("\n")
        if ip and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.")
    ]

    dst_output = run_tshark(pcap, ["-T", "fields", "-e", "ip.dst"])
    dst_ips = [
        ip for ip in dst_output.strip().split("\n")
        if ip and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.")
    ]

    return {
        "top_src_ips": [{"ip": ip, "count": c} for ip, c in Counter(src_ips).most_common(limit)],
        "top_dst_ips": [{"ip": ip, "count": c} for ip, c in Counter(dst_ips).most_common(limit)],
    }


def get_port_stats(pcap: str, limit: int = 20) -> Dict[str, List]:
    """端口统计"""
    output = run_tshark(pcap, ["-T", "fields", "-e", "tcp.dstport", "-e", "udp.dstport"])
    ports = []
    for line in output.strip().split("\n"):
        for port in line.split("\t"):
            if port.strip():
                ports.append(port.strip())

    return {
        "top_dst_ports": [
            {"port": int(p), "count": c}
            for p, c in Counter(ports).most_common(limit)
            if p.isdigit()
        ]
    }


def get_dns_queries(pcap: str, limit: int = 50) -> List[str]:
    """DNS 查询"""
    output = run_tshark(pcap, ["-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"])
    domains = list(set(d.strip() for d in output.strip().split("\n") if d.strip()))
    return domains[:limit]


def get_http_requests(pcap: str, limit: int = 50) -> List[Dict]:
    """HTTP 请求"""
    output = run_tshark(pcap, [
        "-Y", "http.request",
        "-T", "fields",
        "-E", "separator=|",
        "-e", "http.host",
        "-e", "http.request.method",
        "-e", "http.request.uri",
        "-e", "http.user_agent"
    ])

    requests = []
    seen = set()
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("|")
        host = parts[0].strip() if len(parts) > 0 else ""
        method = parts[1].strip() if len(parts) > 1 else "GET"
        uri = parts[2].strip() if len(parts) > 2 else "/"
        ua = parts[3].strip()[:100] if len(parts) > 3 and parts[3] else ""

        key = f"{method}|{host}|{uri}"
        if key not in seen and host:
            seen.add(key)
            req = {"host": host, "method": method, "uri": uri}
            if ua:
                req["user_agent"] = ua
            requests.append(req)

    return requests[:limit]


def get_tls_info(pcap: str, limit: int = 50) -> Dict[str, Any]:
    """TLS/SSL 信息"""
    # SNI
    sni_output = run_tshark(pcap, [
        "-Y", "tls.handshake.extensions_server_name",
        "-T", "fields",
        "-e", "tls.handshake.extensions_server_name"
    ])
    sni_list = list(set(s.strip() for s in sni_output.strip().split("\n") if s.strip()))

    # JA3
    ja3_output = run_tshark(pcap, [
        "-Y", "tls.handshake.type == 1",
        "-T", "fields",
        "-e", "tls.handshake.ja3"
    ])
    ja3_list = list(set(j.strip() for j in ja3_output.strip().split("\n") if j.strip()))

    return {
        "sni_domains": sni_list[:limit],
        "ja3_fingerprints": ja3_list[:20] if ja3_list else []
    }


def get_conversations(pcap: str, limit: int = 20) -> List[Dict]:
    """TCP 会话"""
    output = run_tshark(pcap, ["-q", "-z", "conv,tcp"])
    convs = []

    for line in output.split("\n"):
        line = line.strip()
        if not line or "<->" not in line:
            continue
        parts = line.split()
        if len(parts) >= 5:
            convs.append({
                "endpoints": parts[0] + " <-> " + parts[2],
                "packets": parts[4] if len(parts) > 4 else "",
                "bytes": parts[5] if len(parts) > 5 else ""
            })

    return convs[:limit]


def extract_iocs(result: Dict) -> Dict[str, List]:
    """提取 IOC"""
    iocs = {
        "ips": [],
        "domains": [],
        "urls": []
    }

    # IPs
    for item in result.get("ip_stats", {}).get("top_dst_ips", []):
        ip = item.get("ip", "")
        if ip and not ip.startswith("127."):
            iocs["ips"].append(ip)

    # Domains from DNS
    iocs["domains"] = result.get("dns_queries", [])[:30]

    # Domains from TLS SNI
    for sni in result.get("tls_info", {}).get("sni_domains", []):
        if sni and sni not in iocs["domains"]:
            iocs["domains"].append(sni)

    # URLs from HTTP
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

    tshark_ok, tshark_path = check_tshark()
    if not tshark_ok:
        # 尝试 scapy 兜底
        return _analyze_with_scapy(filepath)

    result = {
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "tshark_path": tshark_path,
    }

    capinfos_ok, capinfos_path = check_capinfos()
    if capinfos_ok:
        result["capinfos_path"] = capinfos_path

    # 收集各类信息
    result["basic_stats"] = get_basic_stats(filepath)
    result["protocol_stats"] = get_protocol_stats(filepath)
    result["ip_stats"] = get_ip_stats(filepath)
    result["port_stats"] = get_port_stats(filepath)
    result["dns_queries"] = get_dns_queries(filepath)
    result["http_requests"] = get_http_requests(filepath)
    result["tls_info"] = get_tls_info(filepath)
    result["conversations"] = get_conversations(filepath)
    result["iocs"] = extract_iocs(result)

    # 摘要
    summary = []
    if result["basic_stats"].get("packet_count"):
        summary.append(f"Packets: {result['basic_stats']['packet_count']}")
    if result["basic_stats"].get("duration_seconds"):
        summary.append(f"Duration: {result['basic_stats']['duration_seconds']}s")
    if result["dns_queries"]:
        summary.append(f"DNS queries: {len(result['dns_queries'])} domains")
    if result["http_requests"]:
        summary.append(f"HTTP requests: {len(result['http_requests'])}")
    if result["tls_info"].get("sni_domains"):
        summary.append(f"TLS connections: {len(result['tls_info']['sni_domains'])} domains")

    result["summary"] = " | ".join(summary) if summary else "Unable to extract summary"

    return result


def _analyze_with_scapy(filepath: str) -> Dict[str, Any]:
    """使用 scapy 进行兜底分析（当 tshark 不可用时）"""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR
    except ImportError:
        msg = "tshark not found. Install Wireshark, or install scapy: pip install scapy"
        if IS_WINDOWS:
            msg += "\nAlternatively download: https://www.wireshark.org/download.html"
        else:
            msg += "\nInstall Wireshark: brew install wireshark (macOS) or sudo apt install wireshark (Linux)"
        return {"error": msg}

    path = Path(filepath)
    try:
        packets = rdpcap(str(path))
    except Exception as e:
        return {"error": f"Failed to read PCAP with scapy: {e}"}

    from collections import Counter

    def _basic_stats():
        stats = {"packet_count": len(packets)}
        if packets:
            first_ts = packets[0].time if hasattr(packets[0], 'time') else 0
            last_ts = packets[-1].time if hasattr(packets[-1], 'time') else first_ts
            if first_ts and last_ts:
                stats["duration_seconds"] = round(last_ts - first_ts, 3)
            stats["total_bytes"] = sum(len(p) for p in packets if hasattr(p, 'len'))
        return stats

    def _proto_stats():
        protocols = Counter()
        for pkt in packets:
            if pkt.haslayer(TCP):
                protocols["tcp"] += 1
            elif pkt.haslayer(UDP):
                protocols["dns" if pkt.haslayer(DNS) else "udp"] += 1
            elif pkt.haslayer(ICMP):
                protocols["icmp"] += 1
        return dict(protocols.most_common(10))

    def _ip_stats():
        src_ips = Counter()
        dst_ips = Counter()
        priv_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                         "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                         "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                         "172.29.", "172.30.", "172.31.")
        for pkt in packets:
            if pkt.haslayer(IP):
                s, d = pkt[IP].src, pkt[IP].dst
                if not s.startswith(priv_prefixes): src_ips[s] += 1
                if not d.startswith(priv_prefixes): dst_ips[d] += 1
        return {
            "top_src_ips": [{"ip": ip, "count": c} for ip, c in src_ips.most_common(20)],
            "top_dst_ips": [{"ip": ip, "count": c} for ip, c in dst_ips.most_common(20)],
        }

    def _port_stats():
        ports = Counter()
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt[TCP].dport:
                ports[pkt[TCP].dport] += 1
            elif pkt.haslayer(UDP) and pkt[UDP].dport:
                ports[pkt[UDP].dport] += 1
        return {"top_dst_ports": [{"port": p, "count": c} for p, c in ports.most_common(20)]}

    def _dns_queries():
        domains = set()
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qr = pkt[DNSQR]
                if hasattr(qr, 'qname') and qr.qname:
                    try:
                        d = qr.qname.decode('utf-8', errors='replace').rstrip('.')
                        if d: domains.add(d)
                    except Exception:
                        pass
        return list(domains)[:50]

    def _extract_iocs(ip_stats, dns, tls_sni, http_reqs):
        iocs = {"ips": [], "domains": [], "urls": []}
        for item in ip_stats.get("top_dst_ips", []):
            ip = item.get("ip", "")
            if ip and not ip.startswith("127."):
                iocs["ips"].append(ip)
        iocs["domains"] = dns[:30]
        for sni in tls_sni:
            if sni not in iocs["domains"]:
                iocs["domains"].append(sni)
        for req in http_reqs:
            host, uri = req.get("host", ""), req.get("uri", "")
            if host and uri:
                iocs["urls"].append(f"http://{host}{uri}")
        return iocs

    # TLS SNI + HTTP
    tls_sni = []
    http_reqs = []
    seen_http = set()
    for pkt in packets:
        if pkt.haslayer(TCP):
            payload = bytes(pkt[TCP].payload)
            if len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01:
                try:
                    text = payload.decode('latin-1', errors='replace')
                    import re as _re
                    for m in _re.findall(r'(?:sni|server_name|host)[=:][^\x00]+([a-zA-Z0-9][-a-zA-Z0-9.*]{2,254})', text, _re.IGNORECASE):
                        if '.' in m and len(m) < 255:
                            tls_sni.append(m)
                except Exception:
                    pass
            if payload:
                for method in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD "):
                    if payload.startswith(method):
                        try:
                            text = payload.decode('utf-8', errors='replace')
                            lines = text.split('\r\n')
                            if lines:
                                parts = lines[0].split(" ", 2)
                                host = next((l.split(":", 1)[1].strip() for l in lines[1:]
                                             if l.lower().startswith("host:")), "")
                                key = f"{parts[0]}|{host}|{parts[1] if len(parts) > 1 else '/'}"
                                if key not in seen_http and host:
                                    seen_http.add(key)
                                    http_reqs.append({"host": host, "method": parts[0],
                                                      "uri": parts[1] if len(parts) > 1 else "/"})
                                    if len(http_reqs) >= 50:
                                        break
                        except Exception:
                            pass
                        break

    dns_q = _dns_queries()
    ip_s = _ip_stats()
    iocs = _extract_iocs(ip_s, dns_q, tls_sni, http_reqs)

    bs = _basic_stats()
    summary = []
    if bs.get("packet_count"):
        summary.append(f"Packets: {bs['packet_count']}")
    if bs.get("duration_seconds"):
        summary.append(f"Duration: {bs['duration_seconds']}s")
    if dns_q:
        summary.append(f"DNS queries: {len(dns_q)} domains")
    if http_reqs:
        summary.append(f"HTTP requests: {len(http_reqs)}")
    if tls_sni:
        summary.append(f"TLS connections: {len(tls_sni)} domains")

    return {
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "engine": "scapy (fallback mode)",
        "note": "tshark not available, used scapy. Some fields may be limited.",
        "basic_stats": bs,
        "protocol_stats": _proto_stats(),
        "ip_stats": ip_s,
        "port_stats": _port_stats(),
        "dns_queries": dns_q,
        "http_requests": http_reqs,
        "tls_info": {"sni_domains": list(set(tls_sni))[:50], "ja3_fingerprints": []},
        "conversations": [],
        "iocs": iocs,
        "summary": " | ".join(summary) if summary else "Unable to extract summary",
    }


# =============================================================================
# 输出
# =============================================================================

def print_result(result: Dict):
    """打印结果"""
    if "error" in result:
        print(f"Error: {result['error']}")
        return

    tshark_path = result.get("tshark_path", "unknown")
    print(f"\n{'=' * 60}")
    print(f"File: {result['filename']} ({result['size_bytes']} bytes)")
    print(f"tshark: {tshark_path}")
    if result.get("capinfos_path"):
        print(f"capinfos: {result['capinfos_path']}")
    print(f"{'=' * 60}")

    # 基本统计
    stats = result.get("basic_stats", {})
    if stats:
        print(f"\n[*] Basic Statistics")
        print(f"    Packets: {stats.get('packet_count', 'N/A')}")
        print(f"    Total bytes: {stats.get('total_bytes', 'N/A')}")
        print(f"    Duration: {stats.get('duration_seconds', 'N/A')} seconds")

    # 协议分布
    protos = result.get("protocol_stats", {})
    if protos:
        print(f"\n[*] Protocol Distribution")
        for proto, count in sorted(protos.items(), key=lambda x: -x[1])[:10]:
            print(f"    {proto}: {count}")

    # 目标 IP
    dst_ips = result.get("ip_stats", {}).get("top_dst_ips", [])
    if dst_ips:
        print(f"\n[*] Top Destination IPs")
        for p in dst_ips[:10]:
            print(f"    {p['ip']} - {p['count']} packets")

    # 端口统计
    ports = result.get("port_stats", {}).get("top_dst_ports", [])
    if ports:
        print(f"\n[*] Top Destination Ports")
        for p in ports[:10]:
            print(f"    :{p['port']} - {p['count']} packets")

    # DNS
    dns = result.get("dns_queries", [])
    if dns:
        print(f"\n[*] DNS Queries ({len(dns)} total)")
        for d in dns[:15]:
            print(f"    {d}")
        if len(dns) > 15:
            print(f"    ... and {len(dns) - 15} more")

    # HTTP
    http = result.get("http_requests", [])
    if http:
        print(f"\n[*] HTTP Requests ({len(http)} total)")
        for r in http[:10]:
            host = r.get("host", "")
            uri = r.get("uri", "")
            if uri.startswith("http://") or uri.startswith("https://"):
                print(f"    {r.get('method', 'GET')} {uri[:70]}")
            else:
                print(f"    {r.get('method', 'GET')} {host}{uri[:60]}")
        if len(http) > 10:
            print(f"    ... and {len(http) - 10} more")

    # TLS
    tls = result.get("tls_info", {})
    sni = tls.get("sni_domains", [])
    if sni:
        print(f"\n[*] TLS SNI Domains ({len(sni)} total)")
        for s in sni[:15]:
            print(f"    {s}")
        if len(sni) > 15:
            print(f"    ... and {len(sni) - 15} more")

    # IOC 摘要
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
        description="PCAP traffic analysis tool (tshark + capinfos)"
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
