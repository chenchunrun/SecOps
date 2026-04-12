#!/usr/bin/env python3
"""
Email Header Parser and Analyzer
Parses email headers and performs security analysis.
"""

import sys
import email
import re
import json
from email import policy
from email.parser import BytesParser, Parser
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class EmailHeaderAnalyzer:
    def __init__(self, raw_email: str):
        self.msg = Parser(policy=policy.default).parsestr(raw_email)
        self.findings = []
        self.risk_score = 0

    def analyze(self) -> Dict:
        """Run complete header analysis."""
        results = {
            "basic_info": self._extract_basic_info(),
            "authentication": self._check_authentication(),
            "routing": self._analyze_routing(),
            "anomalies": self._detect_anomalies(),
            "findings": self.findings,
            "risk_score": self.risk_score,
            "risk_level": self._calculate_risk_level()
        }
        return results

    def _extract_basic_info(self) -> Dict:
        """Extract basic email information."""
        return {
            "from": self.msg.get("From", ""),
            "to": self.msg.get("To", ""),
            "subject": self.msg.get("Subject", ""),
            "date": self.msg.get("Date", ""),
            "reply_to": self.msg.get("Reply-To", ""),
            "return_path": self.msg.get("Return-Path", ""),
            "message_id": self.msg.get("Message-ID", ""),
            "x_mailer": self.msg.get("X-Mailer", "") or self.msg.get("User-Agent", ""),
        }

    def _check_authentication(self) -> Dict:
        """Check SPF, DKIM, and DMARC results."""
        auth_results = self.msg.get("Authentication-Results", "")
        spf = self.msg.get("Received-SPF", "")

        results = {
            "spf": self._parse_auth_result(auth_results, "spf") or self._parse_spf_header(spf),
            "dkim": self._parse_auth_result(auth_results, "dkim"),
            "dmarc": self._parse_auth_result(auth_results, "dmarc"),
            "raw_auth_results": auth_results
        }

        # Score authentication failures
        for auth_type, result in [("SPF", results["spf"]), ("DKIM", results["dkim"]), ("DMARC", results["dmarc"])]:
            if result and "fail" in result.lower():
                self.findings.append(f"{auth_type} authentication failed: {result}")
                self.risk_score += 20
            elif result and "pass" in result.lower():
                pass  # Good
            elif not result or "none" in str(result).lower():
                self.findings.append(f"{auth_type} not configured or missing")
                self.risk_score += 5

        return results

    def _parse_auth_result(self, auth_results: str, auth_type: str) -> Optional[str]:
        """Parse specific auth result from Authentication-Results header."""
        pattern = rf'{auth_type}=(\w+)'
        match = re.search(pattern, auth_results, re.IGNORECASE)
        return match.group(1) if match else None

    def _parse_spf_header(self, spf_header: str) -> Optional[str]:
        """Parse Received-SPF header."""
        if not spf_header:
            return None
        parts = spf_header.split()
        return parts[0] if parts else None

    def _analyze_routing(self) -> Dict:
        """Analyze Received headers for routing information."""
        received_headers = self.msg.get_all("Received", [])
        hops = []

        for i, header in enumerate(reversed(received_headers)):  # Oldest first
            hop = self._parse_received_header(header)
            hop["hop_number"] = i + 1
            hops.append(hop)

        # Extract origin IP
        origin_ip = None
        x_originating_ip = self.msg.get("X-Originating-IP", "")
        if x_originating_ip:
            origin_ip = re.search(r'\[?([\d.]+)\]?', x_originating_ip)
            origin_ip = origin_ip.group(1) if origin_ip else None
        elif hops:
            origin_ip = hops[0].get("from_ip")

        return {
            "total_hops": len(hops),
            "hops": hops,
            "origin_ip": origin_ip,
            "x_originating_ip": x_originating_ip
        }

    def _parse_received_header(self, header: str) -> Dict:
        """Parse a single Received header."""
        result = {"raw": header[:200]}

        # Extract 'from' part
        from_match = re.search(r'from\s+(\S+)', header, re.IGNORECASE)
        if from_match:
            result["from_host"] = from_match.group(1)

        # Extract IP addresses
        ip_match = re.search(r'\[?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\]?', header)
        if ip_match:
            result["from_ip"] = ip_match.group(1)

        # Extract 'by' part
        by_match = re.search(r'by\s+(\S+)', header, re.IGNORECASE)
        if by_match:
            result["by_host"] = by_match.group(1)

        # Extract timestamp
        timestamp_patterns = [
            r';\s*(.+?)(?:\s*\(|$)',
            r'(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})'
        ]
        for pattern in timestamp_patterns:
            time_match = re.search(pattern, header)
            if time_match:
                result["timestamp"] = time_match.group(1).strip()
                break

        return result

    def _detect_anomalies(self) -> List[str]:
        """Detect header anomalies that indicate phishing."""
        anomalies = []

        # Check From vs Reply-To mismatch
        from_addr = self.msg.get("From", "")
        reply_to = self.msg.get("Reply-To", "")
        if reply_to and from_addr:
            from_domain = self._extract_domain(from_addr)
            reply_domain = self._extract_domain(reply_to)
            if from_domain and reply_domain and from_domain.lower() != reply_domain.lower():
                anomalies.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")
                self.risk_score += 25

        # Check Return-Path mismatch
        return_path = self.msg.get("Return-Path", "")
        if return_path and from_addr:
            rp_domain = self._extract_domain(return_path)
            from_domain = self._extract_domain(from_addr)
            if rp_domain and from_domain and rp_domain.lower() != from_domain.lower():
                anomalies.append(f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})")
                self.risk_score += 15

        # Check for missing Message-ID
        if not self.msg.get("Message-ID"):
            anomalies.append("Missing Message-ID header")
            self.risk_score += 10

        # Check Message-ID domain consistency
        message_id = self.msg.get("Message-ID", "")
        if message_id:
            mid_domain = self._extract_domain(message_id)
            from_domain = self._extract_domain(from_addr)
            if mid_domain and from_domain and mid_domain.lower() != from_domain.lower():
                anomalies.append(f"Message-ID domain ({mid_domain}) differs from From domain ({from_domain})")
                self.risk_score += 10

        # Check for encoded display name
        if "=?" in from_addr:
            anomalies.append("Encoded display name in From header (potential obfuscation)")
            self.risk_score += 5

        # Check for high priority (often used in phishing)
        priority = self.msg.get("X-Priority", "") or self.msg.get("Importance", "")
        if priority and ("1" in priority or "high" in priority.lower()):
            anomalies.append("High priority/importance set (common in phishing)")
            self.risk_score += 5

        self.findings.extend(anomalies)
        return anomalies

    def _extract_domain(self, address: str) -> Optional[str]:
        """Extract domain from email address or Message-ID."""
        match = re.search(r'@([a-zA-Z0-9.-]+)', address)
        return match.group(1) if match else None

    def _calculate_risk_level(self) -> str:
        """Calculate risk level based on score."""
        if self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 25:
            return "MEDIUM"
        elif self.risk_score > 0:
            return "LOW"
        return "NONE"


def format_output(results: Dict, output_format: str = "text") -> str:
    """Format analysis results."""
    if output_format == "json":
        return json.dumps(results, indent=2)

    lines = []
    lines.append("=" * 60)
    lines.append("EMAIL HEADER ANALYSIS REPORT")
    lines.append("=" * 60)

    lines.append("\n[BASIC INFORMATION]")
    for key, value in results["basic_info"].items():
        if value:
            lines.append(f"  {key.replace('_', ' ').title()}: {value[:80]}")

    lines.append("\n[AUTHENTICATION]")
    auth = results["authentication"]
    lines.append(f"  SPF:   {auth['spf'] or 'Not found'}")
    lines.append(f"  DKIM:  {auth['dkim'] or 'Not found'}")
    lines.append(f"  DMARC: {auth['dmarc'] or 'Not found'}")

    lines.append(f"\n[ROUTING] ({results['routing']['total_hops']} hops)")
    if results['routing']['origin_ip']:
        lines.append(f"  Origin IP: {results['routing']['origin_ip']}")
    for hop in results['routing']['hops'][:5]:  # Show first 5 hops
        lines.append(f"  Hop {hop['hop_number']}: {hop.get('from_host', 'unknown')} -> {hop.get('by_host', 'unknown')}")

    lines.append("\n[FINDINGS]")
    if results["findings"]:
        for finding in results["findings"]:
            lines.append(f"  [!] {finding}")
    else:
        lines.append("  No issues detected")

    lines.append(f"\n[RISK ASSESSMENT]")
    lines.append(f"  Score: {results['risk_score']}")
    lines.append(f"  Level: {results['risk_level']}")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Analyze email headers for security issues")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()

    # Read from stdin
    raw_email = sys.stdin.read()

    if not raw_email.strip():
        print("Error: No email content provided. Pipe email content to stdin.", file=sys.stderr)
        sys.exit(1)

    analyzer = EmailHeaderAnalyzer(raw_email)
    results = analyzer.analyze()
    print(format_output(results, args.format))


if __name__ == "__main__":
    main()
