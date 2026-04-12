#!/usr/bin/env python3
"""
URL Analyzer for Phishing Detection
Analyzes URLs for suspicious characteristics.
"""

import sys
import re
import json
from urllib.parse import urlparse, unquote, parse_qs
from typing import Dict, List, Optional
import base64

# Load configuration
try:
    from config_loader import get_shorteners, get_suspicious_tlds, get_phishing_platforms, get_brands
    SHORTENERS = get_shorteners()
    SUSPICIOUS_TLDS = get_suspicious_tlds()
    PHISHING_PLATFORMS = get_phishing_platforms()
    KNOWN_BRANDS = get_brands()
except ImportError:
    # Fallback to minimal defaults if config not available
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl"}
    SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top"}
    PHISHING_PLATFORMS = {"knowbe4.com", "cofense.com", "gophish.com"}
    KNOWN_BRANDS = {}


class URLAnalyzer:
    """Analyze URLs for phishing indicators."""

    def __init__(self, url: str):
        self.original_url = url
        self.url = self._normalize_url(url)
        self.parsed = urlparse(self.url)
        self.findings: List[str] = []
        self.risk_score = 0

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for analysis."""
        # Remove defanging
        url = url.replace("hxxp", "http").replace("[.]", ".").replace("[@]", "@")
        # URL decode
        try:
            url = unquote(url)
        except Exception:
            pass
        return url

    def analyze(self) -> Dict:
        """Run complete URL analysis."""
        results = {
            "original": self.original_url,
            "normalized": self.url,
            "parsed": {
                "scheme": self.parsed.scheme,
                "netloc": self.parsed.netloc,
                "path": self.parsed.path,
                "query": self.parsed.query,
                "fragment": self.parsed.fragment,
            },
            "domain_analysis": self._analyze_domain(),
            "path_analysis": self._analyze_path(),
            "query_analysis": self._analyze_query(),
            "security_indicators": self._check_security_indicators(),
            "findings": self.findings,
            "risk_score": self.risk_score,
            "risk_level": self._calculate_risk_level(),
            "defanged": self._defang(self.url),
        }
        return results

    def _analyze_domain(self) -> Dict:
        """Analyze domain characteristics."""
        domain = self.parsed.netloc.lower()
        result = {
            "domain": domain,
            "is_ip": False,
            "is_shortener": False,
            "suspicious_tld": False,
            "subdomain_count": 0,
            "homograph_detected": False,
            "typosquatting_candidate": False,
        }

        # Check if IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            result["is_ip"] = True
            self.findings.append("URL uses IP address instead of domain name")
            self.risk_score += 25
            return result

        # Remove port if present
        domain_only = domain.split(":")[0]

        # Check for URL shortener
        if domain_only in SHORTENERS or any(domain_only.endswith("." + s) for s in SHORTENERS):
            result["is_shortener"] = True
            self.findings.append(f"URL uses shortener service: {domain_only}")
            self.risk_score += 15

        # Check TLD
        parts = domain_only.split(".")
        if parts:
            tld = parts[-1]
            if tld in SUSPICIOUS_TLDS:
                result["suspicious_tld"] = True
                self.findings.append(f"Suspicious TLD: .{tld}")
                self.risk_score += 10

        # Count subdomains
        if len(parts) > 2:
            result["subdomain_count"] = len(parts) - 2
            if result["subdomain_count"] >= 3:
                self.findings.append(f"Excessive subdomains: {result['subdomain_count']}")
                self.risk_score += 10

        # Check for homograph attacks (mixed scripts)
        if self._has_homograph(domain_only):
            result["homograph_detected"] = True
            self.findings.append("Potential homograph attack detected (mixed character sets)")
            self.risk_score += 30

        # Check for typosquatting patterns
        typosquat = self._check_typosquatting(domain_only)
        if typosquat:
            result["typosquatting_candidate"] = True
            result["typosquatting_target"] = typosquat
            self.findings.append(f"Possible typosquatting of: {typosquat}")
            self.risk_score += 25

        # Check for legitimate domain buried in subdomain
        if self._check_subdomain_abuse(domain_only):
            self.findings.append("Legitimate domain name used in subdomain (subdomain abuse)")
            self.risk_score += 20

        return result

    def _has_homograph(self, domain: str) -> bool:
        """Check for mixed character scripts (homograph attack)."""
        # Check for non-ASCII characters
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True

    def _check_typosquatting(self, domain: str) -> Optional[str]:
        """Check if domain is typosquatting a known brand."""
        known_brands = {
            "microsoft": ["micros0ft", "mircosoft", "microsft", "micosoft", "microsofr"],
            "google": ["g00gle", "googel", "gogle", "googIe", "goog1e"],
            "apple": ["app1e", "appIe", "aple", "applle"],
            "amazon": ["amaz0n", "amazn", "amazom", "arnazon"],
            "paypal": ["paypa1", "paypaI", "paypai", "peypal", "paypol"],
            "netflix": ["netf1ix", "netfIix", "netfilx", "neflix"],
            "facebook": ["faceb00k", "facebok", "faceboook", "faecbook"],
            "linkedin": ["1inkedin", "linkedln", "Iinkedin"],
            "dropbox": ["dr0pbox", "dropb0x", "dropbax"],
            "office365": ["0ffice365", "office36S", "0ff1ce365"],
        }

        domain_lower = domain.lower()
        for brand, typos in known_brands.items():
            if any(typo in domain_lower for typo in typos):
                return brand
            # Check if brand appears with extra characters
            if brand in domain_lower and domain_lower != f"{brand}.com" and domain_lower != brand:
                if not any(legit in domain_lower for legit in [f"{brand}.com", f"{brand}.net", f"{brand}.org"]):
                    return brand
        return None

    def _check_subdomain_abuse(self, domain: str) -> bool:
        """Check for legitimate brands used in subdomain."""
        known_brands = ["microsoft", "google", "apple", "amazon", "paypal", "bank", "secure", "login", "account"]
        parts = domain.split(".")

        if len(parts) >= 3:
            subdomain_part = ".".join(parts[:-2])
            for brand in known_brands:
                if brand in subdomain_part.lower():
                    return True
        return False

    def _analyze_path(self) -> Dict:
        """Analyze URL path."""
        path = self.parsed.path
        result = {
            "path": path,
            "suspicious_extensions": [],
            "encoded_content": False,
            "excessive_depth": False,
        }

        # Check for suspicious file extensions
        suspicious_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"]
        for ext in suspicious_exts:
            if ext in path.lower():
                result["suspicious_extensions"].append(ext)
                self.findings.append(f"Suspicious file extension in path: {ext}")
                self.risk_score += 20

        # Check for encoded content
        if "%" in path or any(x in path for x in ["base64", "eval", "script"]):
            result["encoded_content"] = True
            self.findings.append("Potentially encoded content in URL path")
            self.risk_score += 10

        # Check path depth
        if path.count("/") > 8:
            result["excessive_depth"] = True
            self.findings.append("Excessively deep URL path")
            self.risk_score += 5

        return result

    def _analyze_query(self) -> Dict:
        """Analyze URL query parameters."""
        query = self.parsed.query
        result = {
            "parameters": {},
            "suspicious_params": [],
            "encoded_urls": [],
            "base64_content": [],
        }

        if not query:
            return result

        try:
            params = parse_qs(query)
            result["parameters"] = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        except Exception:
            result["raw_query"] = query
            return result

        # Check for suspicious parameter names
        suspicious_names = ["redirect", "url", "goto", "return", "next", "target", "dest", "redir"]
        for name in suspicious_names:
            if name.lower() in [p.lower() for p in params.keys()]:
                result["suspicious_params"].append(name)
                self.findings.append(f"Suspicious redirect parameter: {name}")
                self.risk_score += 10

        # Check for URLs in parameters
        for key, values in params.items():
            for value in values:
                if re.match(r'https?://', value, re.IGNORECASE):
                    result["encoded_urls"].append({key: value})
                    self.findings.append(f"URL embedded in parameter: {key}")
                    self.risk_score += 15

                # Check for base64 content
                if self._is_base64(value):
                    result["base64_content"].append({key: value[:50] + "..."})
                    self.findings.append(f"Base64 content in parameter: {key}")
                    self.risk_score += 10

        return result

    def _is_base64(self, s: str) -> bool:
        """Check if string appears to be base64 encoded."""
        if len(s) < 20:
            return False
        if not re.match(r'^[A-Za-z0-9+/]+=*$', s):
            return False
        try:
            base64.b64decode(s)
            return True
        except Exception:
            return False

    def _check_security_indicators(self) -> Dict:
        """Check security-related indicators."""
        result = {
            "uses_https": self.parsed.scheme == "https",
            "has_port": bool(re.search(r':\d+', self.parsed.netloc)),
            "is_data_uri": self.parsed.scheme == "data",
            "is_javascript": self.parsed.scheme == "javascript",
            "contains_at_symbol": "@" in self.parsed.netloc,
            "is_phishing_platform": False,
        }

        # Non-HTTPS
        if not result["uses_https"] and self.parsed.scheme == "http":
            self.findings.append("Uses HTTP instead of HTTPS")
            self.risk_score += 5

        # Data URI (potential HTML smuggling)
        if result["is_data_uri"]:
            self.findings.append("Data URI detected (potential HTML smuggling)")
            self.risk_score += 30

        # JavaScript URI
        if result["is_javascript"]:
            self.findings.append("JavaScript URI detected")
            self.risk_score += 25

        # @ symbol in URL (credential confusion)
        if result["contains_at_symbol"]:
            self.findings.append("@ symbol in URL (credential confusion technique)")
            self.risk_score += 25

        # Check for phishing simulation platforms
        domain = self.parsed.netloc.lower()
        for platform in PHISHING_PLATFORMS:
            if platform in domain:
                result["is_phishing_platform"] = True
                self.findings.append(f"Known phishing simulation platform: {platform}")
                self.risk_score -= 20  # Reduce score, likely a test

        return result

    def _calculate_risk_level(self) -> str:
        """Calculate risk level."""
        if self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 25:
            return "MEDIUM"
        elif self.risk_score > 0:
            return "LOW"
        return "NONE"

    def _defang(self, url: str) -> str:
        """Defang URL for safe sharing."""
        url = re.sub(r'https?://', lambda m: m.group(0).replace('http', 'hxxp'), url)
        url = url.replace(".", "[.]")
        return url


def format_output(results: Dict, output_format: str = "text") -> str:
    """Format analysis results."""
    if output_format == "json":
        return json.dumps(results, indent=2)

    lines = []
    lines.append("=" * 60)
    lines.append("URL ANALYSIS REPORT")
    lines.append("=" * 60)

    lines.append(f"\n[URL]")
    lines.append(f"  Original: {results['original']}")
    lines.append(f"  Defanged: {results['defanged']}")

    lines.append(f"\n[PARSED COMPONENTS]")
    for key, value in results["parsed"].items():
        if value:
            lines.append(f"  {key}: {value}")

    lines.append(f"\n[DOMAIN ANALYSIS]")
    da = results["domain_analysis"]
    lines.append(f"  Domain: {da['domain']}")
    lines.append(f"  Is IP: {da['is_ip']}")
    lines.append(f"  Is Shortener: {da['is_shortener']}")
    lines.append(f"  Suspicious TLD: {da['suspicious_tld']}")
    lines.append(f"  Subdomain Count: {da['subdomain_count']}")
    lines.append(f"  Homograph Attack: {da['homograph_detected']}")
    lines.append(f"  Typosquatting: {da['typosquatting_candidate']}")

    lines.append(f"\n[SECURITY INDICATORS]")
    si = results["security_indicators"]
    lines.append(f"  Uses HTTPS: {si['uses_https']}")
    lines.append(f"  Has Port: {si['has_port']}")
    lines.append(f"  Data URI: {si['is_data_uri']}")
    lines.append(f"  JavaScript URI: {si['is_javascript']}")
    lines.append(f"  Contains @: {si['contains_at_symbol']}")

    lines.append(f"\n[FINDINGS]")
    if results["findings"]:
        for finding in results["findings"]:
            lines.append(f"  [!] {finding}")
    else:
        lines.append("  No suspicious indicators found")

    lines.append(f"\n[RISK ASSESSMENT]")
    lines.append(f"  Score: {results['risk_score']}")
    lines.append(f"  Level: {results['risk_level']}")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Analyze URL for phishing indicators")
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()

    analyzer = URLAnalyzer(args.url)
    results = analyzer.analyze()
    print(format_output(results, args.format))


if __name__ == "__main__":
    main()
