# CDN 检测与误报规避

## 概述

CDN（内容分发网络）使用 GeoDNS 技术，根据用户地理位置返回最近的边缘节点 IP。这导致同一域名在不同时间/地点查询会返回不同 IP，**这是正常行为，不是威胁指标**。

## CDN 识别方法

### 1. IP 段识别（首选）

常见 CDN 提供商 IP 段：

| CDN 提供商 | ASN | IP 段前缀 | 说明 |
|-----------|-----|----------|------|
| **Akamai** | AS20940 | `23.0.0.0/8` (部分), `104.64.0.0/10` | 全球最大 CDN |
| **Cloudflare** | AS13335 | `104.16.0.0/12`, `172.64.0.0/13`, `173.245.48.0/20` | 常见免费 CDN |
| **Fastly** | AS54113 | `151.101.0.0/16`, `199.232.0.0/16` | 高性能 CDN |
| **Amazon CloudFront** | AS16509 | `13.32.0.0/15`, `52.84.0.0/14`, `99.84.0.0/16` | AWS CDN |
| **Google Cloud CDN** | AS15169 | `34.0.0.0/8` (部分) | GCP CDN |
| **Microsoft Azure CDN** | AS8075 | `13.107.0.0/16`, `104.40.0.0/13` | Azure CDN |
| **阿里云 CDN** | AS45102 | `47.88.0.0/14`, `47.74.0.0/15` | 中国主流 |
| **腾讯云 CDN** | AS45090 | `119.28.0.0/15`, `129.204.0.0/14` | 中国主流 |
| **网宿 CDN** | AS17816 | `36.27.0.0/16`, `42.236.0.0/14` | 中国老牌 CDN |

### 2. CNAME 链检测

CDN 域名通常有特征性 CNAME：

```bash
# 查询 CNAME 链
dig +short CNAME m.tiktok.shop

# 常见 CDN CNAME 后缀
*.akamaiedge.net      → Akamai
*.cloudflare.net      → Cloudflare
*.fastly.net          → Fastly
*.cloudfront.net      → Amazon CloudFront
*.azureedge.net       → Azure CDN
*.kunlunaq.com        → 阿里云 CDN
*.cdntip.com          → 腾讯云 CDN
*.wscdns.com          → 网宿 CDN
```

### 3. HTTP 响应头检测

```bash
curl -sI https://example.com | grep -iE "server|x-cache|cf-ray|x-cdn"

# 常见 CDN 响应头
Server: cloudflare           → Cloudflare
X-Cache: Hit from cloudfront → CloudFront
cf-ray: xxx                  → Cloudflare
X-Served-By: cache-xxx       → Fastly
X-CDN: Akamai                → Akamai
```

## DNS 历史分析调整

### 传统分析（不区分 CDN）

| DNS 变化频率 | 传统判断 | 问题 |
|-------------|---------|------|
| 每天变化 | 🔴 高度可疑 | CDN 误报 |
| 每周变化 | 🟠 可疑 | CDN 误报 |
| 每月变化 | 🟡 关注 | 可能误报 |

### 优化后分析

```
DNS 历史分析流程：
1. 检查是否为 CDN IP 段
   ├─ 是 CDN → 跳过"IP 频繁变化"检查
   └─ 非 CDN → 继续传统分析

2. CDN 域名的真实威胁指标：
   - Quad9/VirusTotal 恶意标记（仍然有效）
   - 域名年龄（仍然有效）
   - 同形字攻击（仍然有效）
   - DGA 检测（仍然有效）
```

### 分析权重调整

| 指标 | 非 CDN 权重 | CDN 域名权重 | 原因 |
|------|------------|-------------|------|
| IP 频繁变化 | +15 | **0** | CDN 正常行为 |
| 多 IP 解析 | +10 | **0** | CDN 负载均衡 |
| VPN Provider 标签 | +10 | **-5** | CDN 节点常被误标 |
| Quad9 恶意标记 | +25 | +25 | 仍然有效 |
| 域名年龄 < 30天 | +20 | +20 | 仍然有效 |
| 同形字攻击 | +30 | +30 | 仍然有效 |

## CDN 检测脚本

```python
# scripts/cdn_detector.py
import ipaddress

CDN_RANGES = {
    "Akamai": [
        "23.0.0.0/8",      # 部分属于 Akamai
        "104.64.0.0/10",
        "184.24.0.0/13",
        "184.50.0.0/15",
    ],
    "Cloudflare": [
        "104.16.0.0/12",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
    ],
    "Fastly": [
        "151.101.0.0/16",
        "199.232.0.0/16",
    ],
    "CloudFront": [
        "13.32.0.0/15",
        "13.35.0.0/16",
        "52.84.0.0/14",
        "99.84.0.0/16",
        "143.204.0.0/16",
    ],
}

def detect_cdn(ip: str) -> tuple[bool, str]:
    """
    检测 IP 是否属于已知 CDN
    返回: (是否CDN, CDN名称)
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cdn_name, ranges in CDN_RANGES.items():
            for cidr in ranges:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True, cdn_name
        return False, ""
    except ValueError:
        return False, ""

def analyze_dns_history(records: list, domain: str) -> dict:
    """
    分析 DNS 历史记录，区分 CDN 和非 CDN 场景
    """
    cdn_ips = []
    non_cdn_ips = []
    cdn_providers = set()

    for record in records:
        ip = record.get("value", "")
        is_cdn, cdn_name = detect_cdn(ip)
        if is_cdn:
            cdn_ips.append(ip)
            cdn_providers.add(cdn_name)
        else:
            non_cdn_ips.append(ip)

    is_cdn_domain = len(cdn_ips) > len(non_cdn_ips) * 2  # CDN IP 占主导

    return {
        "is_cdn": is_cdn_domain,
        "cdn_providers": list(cdn_providers),
        "cdn_ip_count": len(cdn_ips),
        "non_cdn_ip_count": len(non_cdn_ips),
        "analysis_note": "CDN 域名，IP 变化为正常行为" if is_cdn_domain else "非 CDN 域名，IP 变化需关注"
    }
```

## 报告输出调整

### CDN 域名报告示例

```markdown
## DNS 解析分析

**CDN 检测**: ✅ 检测到 Akamai CDN
**IP 变化**: 50 条记录（正常 CDN 行为，不计入风险评分）

| 特征 | 值 | 风险调整 |
|------|-----|---------|
| CDN 提供商 | Akamai | -10 (降低误报) |
| IP 变化频率 | 每日 | 0 (CDN 正常) |
| 解析 IP 数 | 50+ | 0 (CDN 正常) |
```

### 非 CDN 域名报告示例

```markdown
## DNS 解析分析

**CDN 检测**: ❌ 未检测到 CDN
**IP 变化**: 50 条记录（异常，可能为 Fast-Flux）

| 特征 | 值 | 风险评分 |
|------|-----|---------|
| IP 变化频率 | 每日 | +15 |
| 解析 IP 数 | 50+ | +10 |
| Fast-Flux 可能 | 高 | +20 |
```

## 常见 CDN 域名模式

以下域名模式通常使用 CDN，应降低 IP 变化的风险权重：

| 域名模式 | 说明 |
|---------|------|
| `m.*`, `www.*` | 移动端/主站 |
| `static.*`, `cdn.*`, `assets.*` | 静态资源 |
| `*.shop`, `*.store` | 电商类 |
| `api.*`, `edge.*` | API/边缘服务 |

## 误报修正清单

当域名满足以下**任一**条件时，应降低"IP 频繁变化"的风险评分：

- [ ] IP 属于已知 CDN 段
- [ ] CNAME 指向 CDN 域名
- [ ] HTTP 响应头包含 CDN 标识
- [ ] 域名属于知名品牌/企业

## 参考资料

**官方来源（2025年1月验证）**：

| CDN | 官方 IP 列表 |
|-----|-------------|
| Cloudflare | https://www.cloudflare.com/ips-v4 |
| Fastly | https://api.fastly.com/public-ip-list |
| CloudFront | https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips |
| Akamai | AS20940 (无官方公开列表，通过 BGP 数据获取) |

**ASN 查询工具**：
- [IPinfo.io ASN 查询](https://ipinfo.io/) - 查询 IP 归属 ASN
- [NetworksDB](https://networksdb.io/) - CDN IP 段数据库
- [BGP.Tools](https://bgp.tools/) - BGP 路由数据

**注意**：中国 CDN（阿里云、腾讯云、网宿）不提供官方 IP 列表，需通过 API 动态获取或使用社区整理数据。
