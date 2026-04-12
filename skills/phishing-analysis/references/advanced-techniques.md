# 高级钓鱼检测技术

## AI/机器学习检测方法

### 深度学习架构（2024-2025研究前沿）

**混合深度学习模型架构：**
1. **BERT上下文嵌入** - 捕获邮件文本的语义含义
2. **CNN特征提取** - 识别局部模式和关键词组合
3. **GRU时序依赖** - 分析文本序列中的异常
4. **多头注意力机制** - 聚焦关键欺骗特征

**模型输入特征：**
- 邮件主题和正文文本
- 发件人域名特征
- URL结构特征
- 附件元数据
- 时间戳模式

### 可解释AI（XAI）

在钓鱼检测中应用XAI增强用户信任：
- SHAP值解释每个特征的贡献
- 注意力权重可视化
- 决策边界解释
- 关键词高亮

### 开源工具

| 工具 | 用途 | 链接 |
|------|------|------|
| PhishTank API | 已知钓鱼URL查询 | phishtank.org |
| OpenPhish | 钓鱼URL情报源 | openphish.com |
| URLhaus | 恶意URL数据库 | urlhaus.abuse.ch |

## 高级邮件头取证

### ARC（认证接收链）分析

当邮件经过转发时，原始的SPF/DKIM可能失效。ARC提供信任链：

```
ARC-Seal: i=1; a=rsa-sha256; cv=none; d=forwarder.com
ARC-Message-Signature: i=1; a=rsa-sha256; d=forwarder.com
ARC-Authentication-Results: i=1; dmarc=pass
```

**分析要点：**
- `cv=none` - 第一个ARC签名
- `cv=pass` - 之前的ARC验证通过
- `cv=fail` - 之前的ARC验证失败（高度可疑）

### DMARC对齐检查

```
From: sender@company.com
Return-Path: bounce@company.com
DKIM-Signature: d=company.com

DMARC对齐: ✓ Pass (From域与DKIM域匹配)
```

**对齐失败的常见原因：**
- 使用第三方邮件服务
- 邮件列表转发
- 域名欺骗（最危险）

### 接收头链完整性

```python
def analyze_received_chain(headers):
    """
    检查Received头链的完整性和一致性
    """
    hops = []
    for received in headers.get_all('Received', []):
        hop = parse_received(received)
        hops.append(hop)

    # 检查时间顺序（应该递增）
    for i in range(1, len(hops)):
        if hops[i].timestamp < hops[i-1].timestamp:
            return "ANOMALY: Time travel detected"

    # 检查地理位置跳跃
    locations = [geoip(hop.ip) for hop in hops]
    # 异常：同一秒内从不同大洲发送
```

## IDN同形字攻击深度分析

### Unicode技术标准#39 (UTS#39)

UTS#39定义了混淆字符检测的标准方法：

**混淆等级：**
1. **单脚本** - 所有字符来自同一脚本
2. **高度限制** - 仅允许推荐的脚本组合
3. **中度限制** - 允许更多脚本组合
4. **最小限制** - 几乎允许所有组合

**ASCII骨架（Skeleton）算法：**
```python
def to_skeleton(domain):
    """
    将域名转换为ASCII骨架以进行比较
    """
    # 1. NFKD规范化
    nfkd = unicodedata.normalize('NFKD', domain)
    # 2. 应用混淆字符映射
    skeleton = apply_confusable_mapping(nfkd)
    # 3. 再次NFKD规范化
    return unicodedata.normalize('NFKD', skeleton)
```

### 常见同形字替换表

| ASCII | Cyrillic | Greek | 其他 |
|-------|----------|-------|------|
| a | а (U+0430) | α (U+03B1) | ɑ (U+0251) |
| e | е (U+0435) | ε (U+03B5) | ℮ (U+212E) |
| o | о (U+043E) | ο (U+03BF) | ⲟ (U+2C9F) |
| c | с (U+0441) | ϲ (U+03F2) | ⅽ (U+217D) |
| p | р (U+0440) | ρ (U+03C1) | ⲣ (U+2CA3) |

### Punycode解码

```python
def decode_punycode(domain):
    """
    解码Punycode域名
    """
    parts = domain.split('.')
    decoded = []
    for part in parts:
        if part.startswith('xn--'):
            decoded.append(part.encode().decode('idna'))
        else:
            decoded.append(part)
    return '.'.join(decoded)

# 示例
# xn--pple-43d.com -> аpple.com (西里尔字母a)
```

## 二维码钓鱼（Quishing）高级分析

### 图像预处理技术

增强二维码检测率的预处理步骤：

```python
import cv2
import numpy as np

def preprocess_for_qr(image):
    """
    预处理图像以提高QR码检测率
    """
    # 转换为灰度
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # 自适应阈值
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 11, 2
    )

    # 形态学操作去噪
    kernel = np.ones((3, 3), np.uint8)
    cleaned = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)

    return cleaned
```

### 多尺度扫描

某些QR码可能需要缩放才能检测：

```python
def multi_scale_qr_scan(image):
    """
    多尺度扫描检测QR码
    """
    scales = [0.5, 0.75, 1.0, 1.5, 2.0]
    results = []

    for scale in scales:
        scaled = cv2.resize(image, None, fx=scale, fy=scale)
        codes = decode(scaled)
        if codes:
            results.extend(codes)

    return deduplicate(results)
```

### PDF中的QR码检测

使用pdf2image提取PDF页面后扫描：

```python
from pdf2image import convert_from_path

def scan_pdf_for_qr(pdf_path):
    """
    扫描PDF中的QR码
    """
    pages = convert_from_path(pdf_path)
    qr_codes = []

    for i, page in enumerate(pages):
        codes = decode(page)
        for code in codes:
            qr_codes.append({
                'page': i + 1,
                'data': code.data.decode(),
                'type': code.type
            })

    return qr_codes
```

## 威胁情报集成

### STIX/TAXII集成

```python
from stix2 import Indicator, Bundle
from taxii2client import Server

def create_phishing_indicator(url, confidence):
    """
    创建钓鱼URL的STIX指标
    """
    indicator = Indicator(
        name="Phishing URL",
        pattern=f"[url:value = '{url}']",
        pattern_type="stix",
        confidence=confidence,
        labels=["malicious-activity", "phishing"]
    )
    return indicator

def share_to_taxii(indicators, server_url, collection_id):
    """
    将指标分享到TAXII服务器
    """
    server = Server(server_url)
    collection = server.default.collections[collection_id]
    bundle = Bundle(objects=indicators)
    collection.add_objects(bundle)
```

### 开源情报源API

```python
# VirusTotal API
def check_virustotal(url, api_key):
    import requests
    headers = {"x-apikey": api_key}
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    return response.json()

# URLhaus API (无需认证)
def check_urlhaus(url):
    import requests
    response = requests.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url}
    )
    return response.json()
```

## 行为分析

### 邮件发送模式分析

```python
def analyze_sender_behavior(sender, emails):
    """
    分析发件人的历史行为模式
    """
    patterns = {
        'typical_send_times': [],
        'typical_recipients': [],
        'typical_subjects': [],
        'typical_attachment_types': []
    }

    for email in emails:
        patterns['typical_send_times'].append(email.time.hour)
        patterns['typical_recipients'].extend(email.recipients)
        # ...

    return patterns

def detect_anomaly(current_email, patterns):
    """
    检测当前邮件是否偏离正常模式
    """
    anomalies = []

    # 异常发送时间
    if current_email.time.hour not in patterns['typical_send_times']:
        anomalies.append("Unusual send time")

    # 新收件人
    new_recipients = set(current_email.recipients) - set(patterns['typical_recipients'])
    if new_recipients:
        anomalies.append(f"New recipients: {new_recipients}")

    return anomalies
```

### 链接点击追踪检测

识别追踪像素和点击追踪：

```python
def detect_tracking(html_content):
    """
    检测追踪像素和点击追踪链接
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')

    findings = []

    # 1x1 像素图片
    for img in soup.find_all('img'):
        width = img.get('width', '').replace('px', '')
        height = img.get('height', '').replace('px', '')
        if width == '1' and height == '1':
            findings.append({
                'type': 'tracking_pixel',
                'src': img.get('src')
            })

    # URL重定向追踪
    for a in soup.find_all('a'):
        href = a.get('href', '')
        if any(tracker in href for tracker in ['click', 'track', 'redirect']):
            findings.append({
                'type': 'click_tracking',
                'url': href
            })

    return findings
```

## 参考资源

### 学术研究
- [Improving phishing email detection through deep learning](https://www.nature.com/articles/s41598-025-20668-5) - Nature Scientific Reports 2025
- MITRE ATT&CK T1566 技术文档

### 工具和API
- [VirusTotal](https://www.virustotal.com) - 多引擎扫描
- [URLhaus](https://urlhaus.abuse.ch) - 恶意URL数据库
- [PhishTank](https://phishtank.org) - 钓鱼URL社区验证
- [Hybrid Analysis](https://www.hybrid-analysis.com) - 沙箱分析

### 标准和规范
- RFC 7208 - SPF规范
- RFC 6376 - DKIM规范
- RFC 7489 - DMARC规范
- Unicode UTS#39 - 安全机制
