#!/usr/bin/env python3
"""
IOC (Indicators of Compromise) Extractor
Extracts security-relevant indicators from email content.
"""

import sys
import re
import json
import hashlib
import email
from email import policy
from email.parser import Parser
from typing import Dict, List, Set
from urllib.parse import urlparse, unquote
import base64

class IOCExtractor:
    # Regex patterns for IOC extraction
    PATTERNS = {
        "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "cve": r'CVE-\d{4}-\d{4,7}',
    }

    # Common benign domains to filter
    BENIGN_DOMAINS = {
        "google.com", "microsoft.com", "apple.com", "gmail.com",
        "outlook.com", "office.com", "windows.com", "live.com",
        "cloudflare.com", "amazonaws.com", "azure.com"
    }

    def __init__(self, content: str, include_benign: bool = False):
        self.content = content
        self.include_benign = include_benign
        self.iocs: Dict[str, Set[str]] = {
            "urls": set(),
            "domains": set(),
            "ips": set(),
            "emails": set(),
            "hashes": {"md5": set(), "sha1": set(), "sha256": set()},
            "cves": set(),
            "attachments": [],
            "subjects": set(),
        }

    def extract_all(self) -> Dict:
        """Extract all IOCs from content."""
        self._extract_urls()
        self._extract_ips()
        self._extract_emails()
        self._extract_hashes()
        self._extract_domains()
        self._extract_cves()

        # Try to parse as email for additional extraction
        try:
            self._extract_from_email()
        except Exception:
            pass

        return self._format_results()

    def _extract_urls(self):
        """Extract and analyze URLs."""
        urls = set(re.findall(self.PATTERNS["url"], self.content, re.IGNORECASE))

        for url in urls:
            # Clean URL
            url = url.rstrip(".,;:\"')")

            # Decode URL encoding
            try:
                decoded = unquote(url)
                if decoded != url:
                    self.iocs["urls"].add(decoded)
            except Exception:
                pass

            self.iocs["urls"].add(url)

            # Extract domain from URL
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    self.iocs["domains"].add(parsed.netloc.lower())
            except Exception:
                pass

    def _extract_ips(self):
        """Extract IPv4 addresses."""
        ips = set(re.findall(self.PATTERNS["ipv4"], self.content))

        for ip in ips:
            # Filter private/special IPs unless requested
            if not self.include_benign:
                octets = [int(x) for x in ip.split(".")]
                if octets[0] == 10:  # Private
                    continue
                if octets[0] == 172 and 16 <= octets[1] <= 31:  # Private
                    continue
                if octets[0] == 192 and octets[1] == 168:  # Private
                    continue
                if octets[0] == 127:  # Loopback
                    continue
                if octets[0] == 0:  # Invalid
                    continue

            self.iocs["ips"].add(ip)

    def _extract_emails(self):
        """Extract email addresses."""
        emails = set(re.findall(self.PATTERNS["email"], self.content, re.IGNORECASE))
        self.iocs["emails"] = {e.lower() for e in emails}

    def _extract_hashes(self):
        """Extract file hashes."""
        # Extract in order of specificity (longer first)
        sha256_hashes = set(re.findall(self.PATTERNS["sha256"], self.content, re.IGNORECASE))
        self.iocs["hashes"]["sha256"] = {h.lower() for h in sha256_hashes}

        # Remove sha256 from content to avoid partial matches
        temp_content = self.content
        for h in sha256_hashes:
            temp_content = temp_content.replace(h, "")

        sha1_hashes = set(re.findall(self.PATTERNS["sha1"], temp_content, re.IGNORECASE))
        self.iocs["hashes"]["sha1"] = {h.lower() for h in sha1_hashes}

        for h in sha1_hashes:
            temp_content = temp_content.replace(h, "")

        md5_hashes = set(re.findall(self.PATTERNS["md5"], temp_content, re.IGNORECASE))
        self.iocs["hashes"]["md5"] = {h.lower() for h in md5_hashes}

    # Common file extensions to filter (these are not domains)
    FILE_EXTENSIONS = {
        ".exe", ".dll", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".jpg", ".jpeg", ".png", ".gif",
        ".mp3", ".mp4", ".avi", ".mov", ".txt", ".csv", ".json", ".xml", ".html",
        ".js", ".css", ".py", ".java", ".cpp", ".h", ".bat", ".sh", ".ps1",
        ".iso", ".img", ".dmg", ".apk", ".ipa", ".msi", ".deb", ".rpm"
    }

    # Valid TLDs (common ones to reduce false positives)
    VALID_TLDS = {
        "com", "org", "net", "edu", "gov", "mil", "int",
        "cn", "uk", "de", "jp", "fr", "au", "ca", "ru", "br", "in", "kr",
        "io", "co", "me", "tv", "cc", "biz", "info", "xyz", "top", "wang",
        "club", "online", "site", "tech", "app", "dev", "cloud"
    }

    def _extract_domains(self):
        """Extract domain names."""
        domains = set(re.findall(self.PATTERNS["domain"], self.content, re.IGNORECASE))

        for domain in domains:
            domain = domain.lower()

            # Filter common benign domains
            if not self.include_benign:
                is_benign = False
                for benign in self.BENIGN_DOMAINS:
                    if domain == benign or domain.endswith("." + benign):
                        is_benign = True
                        break
                if is_benign:
                    continue

            # Filter file extensions that match pattern (e.g., "1.zip", "file.exe")
            if domain.startswith("."):
                continue
            # Check if it looks like a filename (ends with known extension)
            is_filename = False
            for ext in self.FILE_EXTENSIONS:
                if domain.endswith(ext):
                    is_filename = True
                    break
            if is_filename:
                continue

            # Validate TLD - must end with a valid TLD
            parts = domain.split(".")
            if len(parts) < 2:
                continue
            tld = parts[-1]
            if tld not in self.VALID_TLDS and len(tld) > 6:
                # Skip if TLD is not recognized and too long (likely not a real TLD)
                continue

            self.iocs["domains"].add(domain)

    def _extract_cves(self):
        """Extract CVE identifiers."""
        cves = set(re.findall(self.PATTERNS["cve"], self.content, re.IGNORECASE))
        self.iocs["cves"] = {c.upper() for c in cves}

    def _extract_from_email(self):
        """Extract IOCs specific to email format."""
        msg = Parser(policy=policy.default).parsestr(self.content)

        # Subject
        subject = msg.get("Subject", "")
        if subject:
            self.iocs["subjects"].add(subject)

        # Attachments
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    content = part.get_payload(decode=True)
                    attachment_info = {
                        "filename": filename,
                        "content_type": part.get_content_type(),
                        "size": len(content) if content else 0,
                    }

                    # Calculate hashes for attachments
                    if content:
                        attachment_info["md5"] = hashlib.md5(content).hexdigest()
                        attachment_info["sha256"] = hashlib.sha256(content).hexdigest()

                    self.iocs["attachments"].append(attachment_info)

    def _format_results(self) -> Dict:
        """Format results for output."""
        return {
            "urls": sorted(self.iocs["urls"]),
            "domains": sorted(self.iocs["domains"]),
            "ips": sorted(self.iocs["ips"]),
            "emails": sorted(self.iocs["emails"]),
            "hashes": {
                "md5": sorted(self.iocs["hashes"]["md5"]),
                "sha1": sorted(self.iocs["hashes"]["sha1"]),
                "sha256": sorted(self.iocs["hashes"]["sha256"]),
            },
            "cves": sorted(self.iocs["cves"]),
            "attachments": self.iocs["attachments"],
            "subjects": sorted(self.iocs["subjects"]),
            "summary": {
                "total_urls": len(self.iocs["urls"]),
                "total_domains": len(self.iocs["domains"]),
                "total_ips": len(self.iocs["ips"]),
                "total_emails": len(self.iocs["emails"]),
                "total_attachments": len(self.iocs["attachments"]),
            }
        }


def defang(text: str) -> str:
    """Defang URLs and IPs for safe sharing."""
    # Defang URLs
    text = re.sub(r'https?://', lambda m: m.group(0).replace('http', 'hxxp'), text)
    # Defang dots in IPs and domains
    text = re.sub(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', r'\1[.]\2[.]\3[.]\4', text)
    return text


def format_output(results: Dict, output_format: str = "text", defanged: bool = False) -> str:
    """Format IOC results."""
    if output_format == "json":
        if defanged:
            return defang(json.dumps(results, indent=2))
        return json.dumps(results, indent=2)

    lines = []
    lines.append("=" * 60)
    lines.append("IOC EXTRACTION REPORT")
    lines.append("=" * 60)

    lines.append(f"\n[SUMMARY]")
    for key, value in results["summary"].items():
        lines.append(f"  {key.replace('_', ' ').title()}: {value}")

    if results["urls"]:
        lines.append(f"\n[URLS] ({len(results['urls'])})")
        for url in results["urls"][:20]:
            display = defang(url) if defanged else url
            lines.append(f"  {display}")
        if len(results["urls"]) > 20:
            lines.append(f"  ... and {len(results['urls']) - 20} more")

    if results["domains"]:
        lines.append(f"\n[DOMAINS] ({len(results['domains'])})")
        for domain in results["domains"][:20]:
            display = defang(domain) if defanged else domain
            lines.append(f"  {display}")

    if results["ips"]:
        lines.append(f"\n[IP ADDRESSES] ({len(results['ips'])})")
        for ip in results["ips"]:
            display = defang(ip) if defanged else ip
            lines.append(f"  {display}")

    if results["emails"]:
        lines.append(f"\n[EMAIL ADDRESSES] ({len(results['emails'])})")
        for email_addr in results["emails"][:10]:
            lines.append(f"  {email_addr}")

    if any(results["hashes"].values()):
        lines.append(f"\n[HASHES]")
        for hash_type, hashes in results["hashes"].items():
            if hashes:
                lines.append(f"  {hash_type.upper()}:")
                for h in hashes[:5]:
                    lines.append(f"    {h}")

    if results["attachments"]:
        lines.append(f"\n[ATTACHMENTS]")
        for att in results["attachments"]:
            lines.append(f"  Filename: {att['filename']}")
            lines.append(f"    Type: {att['content_type']}")
            lines.append(f"    Size: {att['size']} bytes")
            if "sha256" in att:
                lines.append(f"    SHA256: {att['sha256']}")

    if results["cves"]:
        lines.append(f"\n[CVEs]")
        for cve in results["cves"]:
            lines.append(f"  {cve}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract IOCs from email or text content")
    parser.add_argument("file", nargs="?", help="File to analyze (or use stdin)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--defang", action="store_true", help="Defang URLs and IPs in output")
    parser.add_argument("--include-benign", action="store_true", help="Include benign/private IPs and domains")
    args = parser.parse_args()

    # Read content
    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    else:
        content = sys.stdin.read()

    if not content.strip():
        print("Error: No content provided.", file=sys.stderr)
        sys.exit(1)

    extractor = IOCExtractor(content, include_benign=args.include_benign)
    results = extractor.extract_all()
    print(format_output(results, args.format, args.defang))


if __name__ == "__main__":
    main()
