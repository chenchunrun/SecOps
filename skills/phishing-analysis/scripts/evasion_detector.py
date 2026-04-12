#!/usr/bin/env python3
"""
Evasion Technique Detector for Phishing Emails
Detects techniques used to bypass security scanners and human inspection.
Only extracts information, judgment is done by the skill.
"""

import sys
import json
import re
import email
import base64
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class EvasionDetector:
    """Detect evasion techniques in emails."""

    # Zero-width characters
    ZERO_WIDTH_CHARS = {
        '\u200b': 'ZERO WIDTH SPACE',
        '\u200c': 'ZERO WIDTH NON-JOINER',
        '\u200d': 'ZERO WIDTH JOINER',
        '\u200e': 'LEFT-TO-RIGHT MARK',
        '\u200f': 'RIGHT-TO-LEFT MARK',
        '\u2060': 'WORD JOINER',
        '\u2061': 'FUNCTION APPLICATION',
        '\u2062': 'INVISIBLE TIMES',
        '\u2063': 'INVISIBLE SEPARATOR',
        '\u2064': 'INVISIBLE PLUS',
        '\ufeff': 'ZERO WIDTH NO-BREAK SPACE (BOM)',
        '\u00ad': 'SOFT HYPHEN',
    }

    # Patterns for detection
    ZERO_FONT_PATTERNS = [
        r'font-size\s*:\s*0',
        r'font\s*:\s*0',
        r'font-size\s*:\s*0\.0+\s*px',
        r'font\s*:\s*0\.0+\s*px',
        r'font-size\s*:\s*1px',
    ]

    HIDDEN_ELEMENT_PATTERNS = [
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0[^.]',
        r'height\s*:\s*0[^.]',
        r'width\s*:\s*0[^.]',
        r'overflow\s*:\s*hidden.*height\s*:\s*0',
        r'position\s*:\s*absolute.*left\s*:\s*-\d+',
        r'text-indent\s*:\s*-\d{4,}',
    ]

    # Tracking ID patterns - multiple formats used by phishing platforms
    TRACKING_ID_PATTERNS = [
        (r'@(\d{10,16})#', 'timestamp_at_hash'),           # @1739186157305# 格式
        (r'#(\d{10,16})#', 'timestamp_hash'),              # #1739186157305# 格式
        (r'\[(\d{10,16})\]', 'timestamp_bracket'),         # [1739186157305] 格式
        (r'\b[a-f0-9]{16,32}\b', 'hex_id'),                # 16-32位十六进制
        (r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', 'uuid'),  # UUID
        (r'(?:id|track|ref|uid|cid)[=:_-]([a-zA-Z0-9]{8,32})', 'param_id'),  # id=xxx 格式
        (r'(?<![a-zA-Z])\d{10,13}(?![a-zA-Z\d])', 'timestamp_plain'),  # 10-13位纯数字（时间戳）
    ]

    def __init__(self, email_path: Optional[str] = None, raw_content: Optional[bytes] = None):
        self.email_path = email_path
        self.raw_content = raw_content or b""
        self.msg = None
        self.html_content = ""
        self.text_content = ""
        self.subject = ""

    def load_email(self) -> bool:
        """Load and parse the email file."""
        try:
            if self.email_path:
                path = Path(self.email_path)
                if not path.exists():
                    return False
                with open(path, 'rb') as f:
                    self.raw_content = f.read()

            if not self.raw_content:
                return False

            self.msg = BytesParser(policy=policy.default).parsebytes(self.raw_content)
            if self.msg is None:
                return False

            self.subject = str(self.msg.get("Subject", ""))
            self._extract_body_content()
            return True
        except Exception:
            return False

    def _extract_body_content(self):
        """Extract HTML and text content from email."""
        if self.msg is None:
            return

        try:
            if self.msg.is_multipart():
                for part in self.msg.walk():
                    try:
                        content_type = part.get_content_type()
                        if part.get_content_disposition() == "attachment":
                            continue

                        payload = part.get_payload(decode=True)
                        if not payload:
                            continue

                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            decoded = payload.decode(charset, errors='replace')
                        except Exception:
                            decoded = payload.decode('utf-8', errors='replace')

                        if content_type == "text/plain":
                            self.text_content = decoded
                        elif content_type == "text/html":
                            self.html_content = decoded
                    except Exception:
                        continue
            else:
                payload = self.msg.get_payload(decode=True)
                if payload:
                    charset = self.msg.get_content_charset() or 'utf-8'
                    try:
                        content = payload.decode(charset, errors='replace')
                    except Exception:
                        content = payload.decode('utf-8', errors='replace')

                    if self.msg.get_content_type() == "text/html":
                        self.html_content = content
                    else:
                        self.text_content = content
        except Exception:
            pass

    def detect(self) -> Dict:
        """Run all evasion detection checks."""
        if not self.load_email():
            return {"error": f"Failed to load email: {self.email_path}"}

        result = {
            "file_path": self.email_path,
            "detection_time": datetime.now().isoformat(),
            "evasion_techniques": {
                "zero_font": self._detect_zero_font(),
                "hidden_elements": self._detect_hidden_elements(),
                "tracking_ids": self._detect_tracking_ids(),
                "zero_width_chars": self._detect_zero_width_chars(),
                "html_comments": self._detect_html_comments(),
                "base64_content": self._detect_base64_content(),
                "unicode_obfuscation": self._detect_unicode_obfuscation(),
            },
            "summary": {}
        }

        # Generate summary
        techniques_found = []
        for technique, data in result["evasion_techniques"].items():
            if data.get("found") or data.get("count", 0) > 0:
                techniques_found.append(technique)

        result["summary"] = {
            "total_techniques_found": len(techniques_found),
            "techniques": techniques_found,
            "has_evasion": len(techniques_found) > 0
        }

        return result

    def _detect_zero_font(self) -> Dict:
        """Detect zero-font obfuscation and extract hidden text."""
        findings = []
        all_hidden_texts = []

        for pattern in self.ZERO_FONT_PATTERNS:
            matches = re.finditer(pattern, self.html_content, re.IGNORECASE)
            for match in matches:
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(self.html_content), match.end() + 50)
                context = self.html_content[start:end]

                # Extract hidden text using multiple methods
                hidden_text = self._extract_hidden_text_enhanced(match.start())

                if hidden_text:
                    all_hidden_texts.append(hidden_text)

                findings.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "context": context,
                    "hidden_text": hidden_text
                })

        # Also try regex-based extraction for all zero-font elements
        regex_hidden = self._extract_all_zero_font_text()
        all_hidden_texts.extend(regex_hidden)

        # Remove duplicates and empty strings
        all_hidden_texts = list(set(t for t in all_hidden_texts if t and t.strip()))

        return {
            "found": len(findings) > 0,
            "count": len(findings),
            "findings": findings[:20],
            "all_hidden_texts": all_hidden_texts[:20],
            "hidden_text_combined": " ".join(all_hidden_texts[:10]) if all_hidden_texts else None
        }

    def _extract_hidden_text_enhanced(self, position: int) -> Optional[str]:
        """Enhanced extraction of text hidden by zero-font technique."""
        try:
            # Look for the complete element containing the zero-font style
            # Search backward for opening tag
            search_start = max(0, position - 500)
            before = self.html_content[search_start:position]
            after = self.html_content[position:position + 500]

            # Find the opening tag with style
            tag_match = re.search(r'<(span|div|font|p|a)[^>]*style=["\'][^"\']*$', before, re.IGNORECASE)
            if tag_match:
                tag_name = tag_match.group(1)
                # Find the content and closing tag
                # Pattern: rest of style...>content</tag>
                close_pattern = rf'^[^"\']*["\'][^>]*>([^<]*)</{tag_name}>'
                close_match = re.search(close_pattern, after, re.IGNORECASE)
                if close_match:
                    text = close_match.group(1).strip()
                    if text:
                        return text

            # Alternative: look for any text immediately after the style declaration
            text_after = re.search(r'["\'][^>]*>([^<]{1,100})<', after)
            if text_after:
                text = text_after.group(1).strip()
                if text and len(text) > 1:
                    return text

        except Exception:
            pass
        return None

    def _extract_all_zero_font_text(self) -> List[str]:
        """Extract all text from zero-font styled elements using regex."""
        hidden_texts = []

        # Pattern to match elements with zero-font styles
        patterns = [
            # <span style="font-size: 0px">hidden text</span>
            r'<(?:span|div|font)[^>]*style=["\'][^"\']*(?:font-size\s*:\s*0|font\s*:\s*0)[^"\']*["\'][^>]*>([^<]+)</(?:span|div|font)>',
            # <span style="font: 0">hidden text</span>
            r'<(?:span|div|font)[^>]*style=["\'][^"\']*font\s*:\s*0[^"\']*["\'][^>]*>([^<]+)</(?:span|div|font)>',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE)
            for match in matches:
                text = match.strip()
                if text and len(text) > 0:
                    hidden_texts.append(text)

        return hidden_texts

    def _detect_hidden_elements(self) -> Dict:
        """Detect hidden HTML elements."""
        findings = []

        for pattern in self.HIDDEN_ELEMENT_PATTERNS:
            matches = re.finditer(pattern, self.html_content, re.IGNORECASE)
            for match in matches:
                start = max(0, match.start() - 50)
                end = min(len(self.html_content), match.end() + 100)
                context = self.html_content[start:end]

                # Extract content of hidden element
                hidden_content = self._extract_element_content(match.start())

                findings.append({
                    "pattern": pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "context": context,
                    "hidden_content": hidden_content
                })

        return {
            "found": len(findings) > 0,
            "count": len(findings),
            "findings": findings[:20]
        }

    def _extract_element_content(self, position: int) -> Optional[str]:
        """Extract content from a hidden element."""
        try:
            after = self.html_content[position:position+500]
            # Find content between > and <
            match = re.search(r'>([^<]+)<', after)
            if match and match.group(1).strip():
                return match.group(1).strip()
        except Exception:
            pass
        return None

    def _detect_tracking_ids(self) -> Dict:
        """Detect tracking IDs in subject and body using multiple patterns."""
        findings = {
            "in_subject": [],
            "in_body": [],
            "in_hidden_elements": [],
            "by_type": {}  # Group by pattern type
        }

        # Check subject with all patterns
        for pattern, pattern_type in self.TRACKING_ID_PATTERNS:
            matches = re.findall(pattern, self.subject, re.IGNORECASE)
            for match in matches:
                # match could be a group or full match
                value = match if isinstance(match, str) else match[0] if match else None
                if value:
                    findings["in_subject"].append({
                        "value": value,
                        "type": pattern_type,
                        "context": self.subject
                    })
                    if pattern_type not in findings["by_type"]:
                        findings["by_type"][pattern_type] = []
                    findings["by_type"][pattern_type].append(value)

        # Check visible body text
        combined = self.text_content + " " + re.sub(r'<[^>]+>', ' ', self.html_content)
        for pattern, pattern_type in self.TRACKING_ID_PATTERNS:
            matches = re.finditer(pattern, combined, re.IGNORECASE)
            for match in matches:
                value = match.group(1) if match.lastindex else match.group(0)
                # Get context
                start = max(0, match.start() - 20)
                end = min(len(combined), match.end() + 20)
                context = combined[start:end].strip()

                findings["in_body"].append({
                    "value": value,
                    "type": pattern_type,
                    "context": context
                })

        # Deduplicate by value
        seen_values = set()
        unique_body = []
        for item in findings["in_body"]:
            if item["value"] not in seen_values:
                seen_values.add(item["value"])
                unique_body.append(item)
        findings["in_body"] = unique_body[:15]

        # Check specifically in hidden elements
        hidden_pattern = r'(?:display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>([^<]+)<'
        hidden_matches = re.findall(hidden_pattern, self.html_content, re.IGNORECASE)
        for hidden_text in hidden_matches:
            for pattern, pattern_type in self.TRACKING_ID_PATTERNS:
                ids = re.findall(pattern, hidden_text, re.IGNORECASE)
                for match in ids:
                    value = match if isinstance(match, str) else match[0] if match else None
                    if value and value not in seen_values:
                        seen_values.add(value)
                        findings["in_hidden_elements"].append({
                            "value": value,
                            "type": pattern_type,
                            "hidden_in": hidden_text[:50]
                        })

        findings["in_hidden_elements"] = findings["in_hidden_elements"][:10]

        total = len(findings["in_subject"]) + len(findings["in_body"]) + len(findings["in_hidden_elements"])

        return {
            "found": total > 0,
            "count": total,
            "findings": findings
        }

    def _detect_zero_width_chars(self) -> Dict:
        """Detect zero-width characters."""
        findings = []
        combined = self.subject + self.text_content + self.html_content

        for char, name in self.ZERO_WIDTH_CHARS.items():
            count = combined.count(char)
            if count > 0:
                # Find positions and context
                positions = []
                for i, c in enumerate(combined):
                    if c == char:
                        start = max(0, i - 10)
                        end = min(len(combined), i + 10)
                        context = combined[start:end].replace(char, f'[{name}]')
                        positions.append({
                            "position": i,
                            "context": context
                        })
                        if len(positions) >= 3:
                            break

                findings.append({
                    "character": repr(char),
                    "name": name,
                    "count": count,
                    "sample_positions": positions
                })

        return {
            "found": len(findings) > 0,
            "count": sum(f["count"] for f in findings),
            "findings": findings
        }

    def _detect_html_comments(self) -> Dict:
        """Detect HTML comments that might be used to split keywords."""
        findings = []

        # Find HTML comments
        comment_pattern = r'<!--[\s\S]*?-->'
        matches = re.finditer(comment_pattern, self.html_content)

        for match in matches:
            comment = match.group()
            position = match.start()

            # Check if comment is between word characters (splitting a word)
            before_char = self.html_content[position-1:position] if position > 0 else ""
            after = self.html_content[match.end():match.end()+1]

            is_word_splitting = bool(re.match(r'\w', before_char) and re.match(r'\w', after))

            findings.append({
                "comment": comment[:100],
                "position": position,
                "is_word_splitting": is_word_splitting,
                "before": self.html_content[max(0, position-10):position],
                "after": self.html_content[match.end():match.end()+10]
            })

        # Filter to show potentially suspicious ones first
        suspicious = [f for f in findings if f["is_word_splitting"]]
        normal = [f for f in findings if not f["is_word_splitting"]]

        return {
            "found": len(findings) > 0,
            "count": len(findings),
            "word_splitting_comments": len(suspicious),
            "findings": suspicious[:10] + normal[:5]
        }

    def _detect_base64_content(self) -> Dict:
        """Detect suspicious base64 encoded content."""
        findings = []

        # Pattern for base64 strings (at least 20 chars)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'

        # Check in HTML content (outside of normal base64 image data)
        # Skip data: URLs which are legitimate
        html_without_data_urls = re.sub(r'data:[^;]+;base64,[A-Za-z0-9+/]+=*', '', self.html_content)

        matches = re.finditer(base64_pattern, html_without_data_urls)
        for match in matches:
            b64_string = match.group()
            if len(b64_string) > 200:
                continue  # Skip very long strings

            # Try to decode
            decoded = None
            try:
                decoded = base64.b64decode(b64_string).decode('utf-8', errors='replace')
                # Check if decoded content looks like text
                if not re.search(r'[a-zA-Z]{3,}', decoded):
                    decoded = None
            except Exception:
                pass

            if decoded and len(decoded) > 5:
                findings.append({
                    "encoded": b64_string[:50] + "..." if len(b64_string) > 50 else b64_string,
                    "decoded": decoded[:100],
                    "position": match.start()
                })

        return {
            "found": len(findings) > 0,
            "count": len(findings),
            "findings": findings[:10]
        }

    def _detect_unicode_obfuscation(self) -> Dict:
        """Detect Unicode-based obfuscation techniques."""
        findings = []

        combined = self.subject + self.text_content

        # Check for mixed scripts (Latin + Cyrillic/Greek)
        has_latin = bool(re.search(r'[a-zA-Z]', combined))
        has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', combined))
        has_greek = bool(re.search(r'[\u0370-\u03FF]', combined))

        if has_latin and (has_cyrillic or has_greek):
            findings.append({
                "type": "mixed_scripts",
                "description": "Mixed Latin with Cyrillic/Greek characters",
                "has_cyrillic": has_cyrillic,
                "has_greek": has_greek
            })

        # Check for homoglyphs in URLs
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[a-z]{2,}'
        urls = re.findall(url_pattern, self.html_content + self.text_content, re.IGNORECASE)

        for url in urls:
            # Check for non-ASCII in URL
            non_ascii = [c for c in url if ord(c) > 127]
            if non_ascii:
                findings.append({
                    "type": "non_ascii_url",
                    "url": url,
                    "non_ascii_chars": [repr(c) for c in non_ascii[:5]]
                })

        # Check for look-alike characters in domain-like patterns
        lookalike_chars = {
            'а': 'a (Cyrillic)',
            'е': 'e (Cyrillic)',
            'о': 'o (Cyrillic)',
            'р': 'p (Cyrillic)',
            'с': 'c (Cyrillic)',
            'х': 'x (Cyrillic)',
            'α': 'a (Greek)',
            'ο': 'o (Greek)',
        }

        for char, desc in lookalike_chars.items():
            if char in combined:
                findings.append({
                    "type": "lookalike_character",
                    "character": char,
                    "looks_like": desc,
                    "count": combined.count(char)
                })

        return {
            "found": len(findings) > 0,
            "count": len(findings),
            "findings": findings[:20]
        }


def format_output(result: Dict, output_format: str = "text") -> str:
    """Format detection results."""
    if output_format == "json":
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    lines = []
    lines.append("=" * 60)
    lines.append("EVASION TECHNIQUE DETECTION REPORT")
    lines.append("=" * 60)

    if "error" in result:
        lines.append(f"\n[ERROR] {result['error']}")
        return "\n".join(lines)

    lines.append(f"\nFile: {result['file_path']}")
    lines.append(f"Detection Time: {result['detection_time']}")

    summary = result.get("summary", {})
    lines.append(f"\n[SUMMARY]")
    lines.append(f"  Techniques Found: {summary.get('total_techniques_found', 0)}")

    if summary.get("has_evasion"):
        lines.append(f"  Detected: {', '.join(summary.get('techniques', []))}")
    else:
        lines.append("  No evasion techniques detected")

    techniques = result.get("evasion_techniques", {})

    for technique, data in techniques.items():
        if data.get("found") or data.get("count", 0) > 0:
            lines.append(f"\n[{technique.upper().replace('_', ' ')}]")
            lines.append(f"  Count: {data.get('count', 0)}")

            findings = data.get("findings", [])
            if isinstance(findings, list):
                for i, finding in enumerate(findings[:5]):
                    if isinstance(finding, dict):
                        lines.append(f"  [{i+1}]")
                        for k, v in finding.items():
                            if v and k != "context":
                                lines.append(f"      {k}: {str(v)[:100]}")
            elif isinstance(findings, dict):
                for k, v in findings.items():
                    if v:
                        lines.append(f"  {k}: {v}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Detect evasion techniques in phishing emails"
    )
    parser.add_argument("email", help="Email file (.eml) to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    args = parser.parse_args()

    detector = EvasionDetector(args.email)
    result = detector.detect()
    output = format_output(result, args.format)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Result saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
