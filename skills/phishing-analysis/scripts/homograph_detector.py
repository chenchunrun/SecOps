#!/usr/bin/env python3
"""
IDN Homograph Attack Detector
Detects domain names using confusable Unicode characters.
"""

import sys
import json
import re
import unicodedata
from typing import Dict, List, Optional, Set, Tuple

# Load configuration
try:
    from config_loader import get_confusables, get_brands
    CONFUSABLES = get_confusables()
    KNOWN_BRANDS = get_brands()
except ImportError:
    # Fallback to minimal defaults
    CONFUSABLES = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
        '0': 'o', '1': 'l', '!': 'i',
    }
    KNOWN_BRANDS = {
        "google": ["google.com", "gmail.com"],
        "microsoft": ["microsoft.com", "outlook.com"],
        "apple": ["apple.com"],
        "paypal": ["paypal.com"],
    }


class HomographDetector:
    """Detect IDN homograph attacks in domain names."""

    def __init__(self):
        self.findings: List[str] = []
        self.risk_score = 0

    def analyze(self, domain: str) -> Dict:
        """Analyze a domain for homograph attacks."""
        self.findings = []
        self.risk_score = 0

        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith("http://") or domain.startswith("https://"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc

        # Remove port
        domain = domain.split(':')[0]

        result = {
            "domain": domain,
            "is_punycode": False,
            "has_non_ascii": False,
            "has_mixed_scripts": False,
            "confusable_chars": [],
            "ascii_skeleton": "",
            "potential_targets": [],
            "risk_score": 0,
            "risk_level": "NONE",
            "findings": [],
        }

        # Check for Punycode
        if domain.startswith("xn--") or ".xn--" in domain:
            result["is_punycode"] = True
            result["decoded_domain"] = self._decode_punycode(domain)
            self.findings.append(f"Punycode domain detected: {domain}")
            self.risk_score += 20
            # Analyze the decoded version
            domain = result["decoded_domain"]

        # Check for non-ASCII characters
        non_ascii = self._find_non_ascii(domain)
        if non_ascii:
            result["has_non_ascii"] = True
            result["non_ascii_chars"] = non_ascii
            self.findings.append(f"Non-ASCII characters found: {non_ascii}")
            self.risk_score += 25

        # Check for mixed scripts
        scripts = self._detect_scripts(domain)
        if len(scripts) > 1:
            result["has_mixed_scripts"] = True
            result["scripts"] = list(scripts)
            self.findings.append(f"Mixed scripts detected: {list(scripts)}")
            self.risk_score += 30

        # Find confusable characters
        confusables = self._find_confusables(domain)
        if confusables:
            result["confusable_chars"] = confusables
            self.findings.append(f"Confusable characters: {confusables}")
            self.risk_score += 15

        # Generate ASCII skeleton
        skeleton = self._to_ascii_skeleton(domain)
        result["ascii_skeleton"] = skeleton

        # Check for brand impersonation
        targets = self._check_brand_impersonation(skeleton, domain)
        if targets:
            result["potential_targets"] = targets
            self.findings.append(f"Possible impersonation of: {targets}")
            self.risk_score += 25

        # Calculate final risk
        result["risk_score"] = self.risk_score
        result["risk_level"] = self._calculate_risk_level()
        result["findings"] = self.findings

        return result

    def _decode_punycode(self, domain: str) -> str:
        """Decode Punycode domain to Unicode."""
        try:
            parts = domain.split('.')
            decoded_parts = []
            for part in parts:
                if part.startswith("xn--"):
                    decoded_parts.append(part.encode('ascii').decode('idna'))
                else:
                    decoded_parts.append(part)
            return '.'.join(decoded_parts)
        except Exception:
            return domain

    def _find_non_ascii(self, domain: str) -> List[Dict]:
        """Find non-ASCII characters in domain."""
        non_ascii = []
        for i, char in enumerate(domain):
            if ord(char) > 127:
                non_ascii.append({
                    "char": char,
                    "position": i,
                    "codepoint": f"U+{ord(char):04X}",
                    "name": unicodedata.name(char, "UNKNOWN"),
                    "script": self._get_script(char),
                })
        return non_ascii

    def _get_script(self, char: str) -> str:
        """Get the Unicode script of a character."""
        try:
            name = unicodedata.name(char, "")
            if "CYRILLIC" in name:
                return "Cyrillic"
            elif "GREEK" in name:
                return "Greek"
            elif "LATIN" in name:
                return "Latin"
            elif "ARABIC" in name:
                return "Arabic"
            elif "CJK" in name or "CHINESE" in name:
                return "CJK"
            elif "HANGUL" in name:
                return "Hangul"
            elif "HIRAGANA" in name or "KATAKANA" in name:
                return "Japanese"
            else:
                return "Other"
        except Exception:
            return "Unknown"

    def _detect_scripts(self, domain: str) -> Set[str]:
        """Detect all scripts used in domain."""
        scripts = set()
        for char in domain:
            if char in '.-':
                continue
            if char.isascii():
                if char.isalpha():
                    scripts.add("Latin")
                continue
            scripts.add(self._get_script(char))
        return scripts

    def _find_confusables(self, domain: str) -> List[Dict]:
        """Find confusable characters in domain."""
        confusables = []
        for i, char in enumerate(domain):
            if char in CONFUSABLES:
                confusables.append({
                    "char": char,
                    "position": i,
                    "looks_like": CONFUSABLES[char],
                    "codepoint": f"U+{ord(char):04X}",
                })
        return confusables

    def _to_ascii_skeleton(self, domain: str) -> str:
        """Convert domain to ASCII skeleton for comparison."""
        skeleton = ""
        for char in domain.lower():
            if char in CONFUSABLES:
                skeleton += CONFUSABLES[char]
            elif char.isascii():
                skeleton += char
            else:
                # Try NFKD normalization
                normalized = unicodedata.normalize('NFKD', char)
                ascii_char = ''.join(c for c in normalized if c.isascii())
                skeleton += ascii_char if ascii_char else char
        return skeleton

    def _check_brand_impersonation(self, skeleton: str, original: str) -> List[str]:
        """Check if domain might be impersonating a known brand."""
        targets = []

        # Remove TLD for comparison
        domain_name = skeleton.split('.')[0]

        for brand, domains in KNOWN_BRANDS.items():
            # Check if skeleton matches brand
            if brand in domain_name or domain_name in brand:
                # But original is different
                if not any(original == d or original.endswith('.' + d) for d in domains):
                    targets.append(brand)

            # Check for typosquatting patterns in skeleton
            if self._is_similar(domain_name, brand):
                if not any(original == d or original.endswith('.' + d) for d in domains):
                    if brand not in targets:
                        targets.append(brand)

        return targets

    def _is_similar(self, s1: str, s2: str) -> bool:
        """Check if two strings are similar (Levenshtein distance <= 2)."""
        if abs(len(s1) - len(s2)) > 2:
            return False

        # Simple Levenshtein distance
        if len(s1) < len(s2):
            s1, s2 = s2, s1

        distances = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            new_distances = [i + 1]
            for j, c2 in enumerate(s2):
                if c1 == c2:
                    new_distances.append(distances[j])
                else:
                    new_distances.append(1 + min((distances[j], distances[j + 1], new_distances[-1])))
            distances = new_distances

        return distances[-1] <= 2

    def _calculate_risk_level(self) -> str:
        """Calculate risk level based on score."""
        if self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 25:
            return "MEDIUM"
        elif self.risk_score > 0:
            return "LOW"
        return "NONE"

    def analyze_batch(self, domains: List[str]) -> List[Dict]:
        """Analyze multiple domains."""
        return [self.analyze(d) for d in domains]

    def generate_homographs(self, domain: str, max_variants: int = 10) -> List[str]:
        """Generate possible homograph variants of a domain."""
        # This is for defensive purposes - to check for existing threats
        variants = []
        domain_lower = domain.lower()

        # Build reverse mapping
        reverse_confusables = {}
        for confusable, ascii_char in CONFUSABLES.items():
            if ascii_char not in reverse_confusables:
                reverse_confusables[ascii_char] = []
            reverse_confusables[ascii_char].append(confusable)

        # Generate single-character substitutions
        for i, char in enumerate(domain_lower):
            if char in reverse_confusables:
                for confusable in reverse_confusables[char][:3]:  # Limit per char
                    variant = domain_lower[:i] + confusable + domain_lower[i+1:]
                    if variant not in variants:
                        variants.append(variant)
                        if len(variants) >= max_variants:
                            return variants

        return variants


def format_output(results: Dict, output_format: str = "text") -> str:
    """Format analysis results."""
    if output_format == "json":
        return json.dumps(results, indent=2, ensure_ascii=False)

    lines = []
    lines.append("=" * 60)
    lines.append("HOMOGRAPH ATTACK DETECTION REPORT")
    lines.append("=" * 60)

    lines.append(f"\n[DOMAIN] {results['domain']}")

    if results.get("decoded_domain"):
        lines.append(f"[DECODED] {results['decoded_domain']}")

    lines.append(f"[ASCII SKELETON] {results['ascii_skeleton']}")

    lines.append(f"\n[DETECTION FLAGS]")
    lines.append(f"  Punycode: {results['is_punycode']}")
    lines.append(f"  Non-ASCII: {results['has_non_ascii']}")
    lines.append(f"  Mixed Scripts: {results['has_mixed_scripts']}")

    if results.get("scripts"):
        lines.append(f"  Scripts Found: {', '.join(results['scripts'])}")

    if results.get("non_ascii_chars"):
        lines.append(f"\n[NON-ASCII CHARACTERS]")
        for char_info in results["non_ascii_chars"][:10]:
            lines.append(f"  '{char_info['char']}' at pos {char_info['position']}: "
                        f"{char_info['codepoint']} ({char_info['script']})")

    if results.get("confusable_chars"):
        lines.append(f"\n[CONFUSABLE CHARACTERS]")
        for char_info in results["confusable_chars"][:10]:
            lines.append(f"  '{char_info['char']}' looks like '{char_info['looks_like']}' "
                        f"({char_info['codepoint']})")

    if results.get("potential_targets"):
        lines.append(f"\n[POTENTIAL IMPERSONATION TARGETS]")
        for target in results["potential_targets"]:
            lines.append(f"  [!] {target}")

    lines.append(f"\n[FINDINGS]")
    if results["findings"]:
        for finding in results["findings"]:
            lines.append(f"  [!] {finding}")
    else:
        lines.append("  No homograph indicators detected")

    lines.append(f"\n[RISK ASSESSMENT]")
    lines.append(f"  Score: {results['risk_score']}")
    lines.append(f"  Level: {results['risk_level']}")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Detect IDN homograph attacks in domain names"
    )
    parser.add_argument("domain", help="Domain name to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                       help="Output format")
    parser.add_argument("--generate", action="store_true",
                       help="Generate possible homograph variants")
    args = parser.parse_args()

    detector = HomographDetector()

    if args.generate:
        variants = detector.generate_homographs(args.domain)
        if args.format == "json":
            print(json.dumps({"domain": args.domain, "variants": variants}, indent=2))
        else:
            print(f"Possible homograph variants of {args.domain}:")
            for v in variants:
                print(f"  {v}")
    else:
        results = detector.analyze(args.domain)
        print(format_output(results, args.format))


if __name__ == "__main__":
    main()
