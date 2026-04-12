# Threat Intelligence Sources

## Free Online Tools

### URL/Domain Analysis

| Service | URL | Use Case |
|---------|-----|----------|
| VirusTotal | https://www.virustotal.com | URL, domain, file, IP scanning |
| URLScan.io | https://urlscan.io | Website screenshot, technologies |
| URLhaus | https://urlhaus.abuse.ch | Malware URL database |
| PhishTank | https://phishtank.org | Phishing URL database |
| Google Safe Browsing | https://transparencyreport.google.com/safe-browsing | URL safety check |
| Talos Intelligence | https://talosintelligence.com | Cisco threat intelligence |
| AbuseIPDB | https://www.abuseipdb.com | IP reputation |

### Domain/WHOIS

| Service | URL | Use Case |
|---------|-----|----------|
| WHOIS | https://whois.domaintools.com | Domain registration |
| SecurityTrails | https://securitytrails.com | Historical DNS, WHOIS |
| ViewDNS | https://viewdns.info | DNS tools |
| DNSdumpster | https://dnsdumpster.com | DNS reconnaissance |
| Shodan | https://www.shodan.io | Internet-connected devices |

### File/Hash Analysis

| Service | URL | Use Case |
|---------|-----|----------|
| VirusTotal | https://www.virustotal.com | Multi-engine scanning |
| Hybrid Analysis | https://www.hybrid-analysis.com | Sandbox analysis |
| Any.Run | https://any.run | Interactive sandbox |
| Joe Sandbox | https://www.joesandbox.com | Malware analysis |
| MalwareBazaar | https://bazaar.abuse.ch | Malware samples |

### Email Analysis

| Service | URL | Use Case |
|---------|-----|----------|
| MXToolbox | https://mxtoolbox.com | SPF/DKIM/DMARC checks |
| Mail-Tester | https://www.mail-tester.com | Email deliverability |
| DMARC Analyzer | https://www.dmarcanalyzer.com | DMARC analysis |

## Threat Intelligence Feeds

### Open Source Feeds

```
# Malware domains
https://urlhaus.abuse.ch/downloads/csv/

# Phishing URLs
https://openphish.com/feed.txt
https://phishtank.org/data/online-valid.json

# Malicious IPs
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
https://feodotracker.abuse.ch/downloads/ipblocklist.txt

# C2 servers
https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
```

### Commercial Feeds
- CrowdStrike Falcon X
- Recorded Future
- Mandiant Threat Intelligence
- ThreatConnect
- Anomali ThreatStream
- Palo Alto Unit 42

## API Integration

### VirusTotal API
```python
import requests

VT_API_KEY = "your_api_key"

def check_url(url):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    return response.json()

def check_hash(file_hash):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers=headers
    )
    return response.json()
```

### AbuseIPDB API
```python
import requests

ABUSEIPDB_KEY = "your_api_key"

def check_ip(ip):
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params=params
    )
    return response.json()
```

## IOC Defanging

When sharing IOCs, defang to prevent accidental clicks:

### URL Defanging
```
Original: https://malicious.com/payload
Defanged: hxxps://malicious[.]com/payload
```

### IP Defanging
```
Original: 192.168.1.1
Defanged: 192[.]168[.]1[.]1
```

### Email Defanging
```
Original: attacker@malicious.com
Defanged: attacker[@]malicious[.]com
```

### Defanging Script
```python
def defang_url(url):
    return url.replace("http", "hxxp").replace(".", "[.]")

def defang_ip(ip):
    return ip.replace(".", "[.]")

def defang_email(email):
    return email.replace("@", "[@]").replace(".", "[.]")

def refang(text):
    return text.replace("hxxp", "http").replace("[.]", ".").replace("[@]", "@")
```

## OSINT Investigation Workflow

### Phase 1: Initial Triage
1. Extract all URLs, IPs, domains, hashes
2. Defang all IOCs for safe handling
3. Document timestamp and source

### Phase 2: Passive Analysis
1. Query VirusTotal for all IOCs
2. Check domain WHOIS and age
3. Lookup IP reputation
4. Search threat intel platforms

### Phase 3: Active Analysis (Sandboxed)
1. Submit URLs to URLScan.io
2. Analyze files in sandbox
3. Follow redirect chains
4. Capture network traffic

### Phase 4: Correlation
1. Search for related campaigns
2. Check internal threat intel
3. Correlate with known APT patterns
4. Document TTPs (MITRE ATT&CK)

### Phase 5: Reporting
1. Compile IOCs
2. Generate STIX/TAXII format if needed
3. Share with threat intel team
4. Update detection rules

## MITRE ATT&CK Mapping

### Initial Access - Phishing (T1566)
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
- T1566.003 - Spearphishing via Service

### Execution
- T1204.001 - Malicious Link
- T1204.002 - Malicious File

### Common Phishing TTPs
- T1598 - Phishing for Information
- T1534 - Internal Spearphishing
- T1586 - Compromise Accounts

## Reference Commands

### Hash Calculation
```bash
# MD5
md5sum file.exe

# SHA256
sha256sum file.exe

# All common hashes
sha256sum file.exe && sha1sum file.exe && md5sum file.exe
```

### Header Extraction
```bash
# Extract headers from .eml
sed -n '1,/^$/p' email.eml

# Using Python
python -c "import email; print(email.message_from_file(open('email.eml')).items())"
```

### DNS Lookups
```bash
# MX records
dig +short MX domain.com

# SPF record
dig +short TXT domain.com | grep spf

# DMARC record
dig +short TXT _dmarc.domain.com
```
