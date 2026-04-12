#!/usr/bin/env python3
"""
Email Information Extractor for Phishing Analysis
Only extracts email information, judgment is done by the skill.
"""

import sys
import json
import email
import re
import hashlib
import base64
import quopri
import os
from email import policy
from email.parser import BytesParser, Parser
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# 导入同目录下的模块
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

# Import analysis modules
try:
    from extract_iocs import IOCExtractor
except ImportError:
    IOCExtractor = None

try:
    from archive_analyzer import ArchiveAnalyzer, detect_password_in_text
except ImportError:
    ArchiveAnalyzer = None
    detect_password_in_text = None

try:
    from evasion_detector import EvasionDetector
except ImportError:
    EvasionDetector = None


class EmailExtractor:
    """Extract email information for analysis."""

    def __init__(self, email_path: str):
        self.email_path = email_path
        self.msg = None
        self.raw_content: bytes = b""

    def load_email(self) -> bool:
        """Load and parse the email file."""
        try:
            path = Path(self.email_path)
            if not path.exists():
                return False

            with open(path, 'rb') as f:
                self.raw_content = f.read()
                f.seek(0)
                self.msg = BytesParser(policy=policy.default).parse(f)

            if self.msg is None:
                return False
            return True
        except Exception:
            return False

    def _safe_get_header(self, header_name: str, default: str = "") -> str:
        """Safely get header value."""
        if self.msg is None:
            return default
        try:
            value = self.msg.get(header_name)
            return str(value) if value else default
        except Exception:
            return default

    def extract(self, save_attachments: bool = False,
                output_dir: Optional[str] = None) -> Dict:
        """Extract all email information.

        Args:
            save_attachments: If True, save attachments to disk and auto-extract
                              encrypted archives using detected passwords.
            output_dir: Directory for saving attachments. Defaults to
                        {eml_dir}/attachments_{eml_stem}/ when save_attachments
                        is True.
        """
        if not self.load_email():
            return {"error": f"Failed to load email: {self.email_path}"}

        # Detect passwords early so they can be used for archive extraction
        passwords = self._detect_passwords()

        # Compute extract_dir for attachments
        extract_dir = None
        if save_attachments or output_dir:
            if output_dir:
                extract_dir = output_dir
            else:
                eml_path = Path(self.email_path)
                extract_dir = str(
                    eml_path.parent / f"attachments_{eml_path.stem}")

        result = {
            "file_path": self.email_path,
            "file_size": len(self.raw_content),
            "extraction_time": datetime.now().isoformat(),
            "headers": self._extract_headers(),
            "content": self._extract_content(),
            "attachments": self._extract_attachments(
                passwords=passwords, extract_dir=extract_dir),
            "urls": self._extract_urls(),
            "iocs": self._extract_iocs(),
            "passwords_in_body": passwords,
            "evasion_techniques": self._detect_evasion()
        }

        # Add recommended skills based on analysis results
        result["recommended_skills"] = self._recommend_skills(result)

        return result

    def _recommend_skills(self, result: Dict) -> List[Dict]:
        """Recommend related skills based on analysis results."""
        recommendations = []

        # Check URLs
        urls = result.get("content", {}).get("urls_in_body", [])
        if urls:
            recommendations.append({
                "skill": "url-analysis",
                "reason": f"发现 {len(urls)} 个 URL 需要分析",
                "targets": urls[:5],  # Limit to first 5
                "priority": "high" if len(urls) > 0 else "medium"
            })

        # Check attachments
        attachments = result.get("attachments", [])
        for att in attachments:
            ext = att.get("extension", "").lower()
            filename = att.get("filename", "")

            # Office files
            rec_base = {}
            if att.get("saved_path"):
                rec_base["saved_path"] = att["saved_path"]

            if ext in {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
                       ".ppt", ".pptx", ".pptm", ".rtf"}:
                rec = {
                    "skill": "office-malware-analyzer",
                    "reason": f"Office 附件需要分析: {filename}",
                    "targets": [filename],
                    "file_hash": att.get("sha256"),
                    "priority": "high" if ext.endswith("m") else "medium",
                    **rec_base,
                }
                recommendations.append(rec)

            # PDF files
            elif ext == ".pdf":
                rec = {
                    "skill": "pdf-analysis",
                    "reason": f"PDF 附件需要分析: {filename}",
                    "targets": [filename],
                    "file_hash": att.get("sha256"),
                    "priority": "medium",
                    **rec_base,
                }
                recommendations.append(rec)

            # Executable files
            elif ext in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
                         ".vbs", ".js", ".hta", ".msi", ".com"}:
                rec = {
                    "skill": "binary-reverse-engineering",
                    "reason": f"可执行文件需要分析: {filename}",
                    "targets": [filename],
                    "file_hash": att.get("sha256"),
                    "priority": "critical",
                    **rec_base,
                }
                recommendations.append(rec)

            # Track already-recommended targets to avoid duplicates
            seen_recommendations = set()
            for r in recommendations:
                key = (r["skill"], tuple(r.get("targets", [])))
                seen_recommendations.add(key)

            # Archives: recommend based on contents and extracted files
            if att.get("is_archive"):
                # Map of extension → (skill, priority)
                ext_skill_map = {
                    ".exe": ("binary-reverse-engineering", "critical"),
                    ".dll": ("binary-reverse-engineering", "critical"),
                    ".scr": ("binary-reverse-engineering", "critical"),
                    ".bat": ("binary-reverse-engineering", "critical"),
                    ".cmd": ("binary-reverse-engineering", "critical"),
                    ".ps1": ("binary-reverse-engineering", "critical"),
                    ".vbs": ("binary-reverse-engineering", "critical"),
                    ".js": ("binary-reverse-engineering", "critical"),
                    ".hta": ("binary-reverse-engineering", "critical"),
                    ".eml": ("phishing-analysis", "high"),
                    ".doc": ("office-malware-analyzer", "high"),
                    ".docx": ("office-malware-analyzer", "medium"),
                    ".docm": ("office-malware-analyzer", "high"),
                    ".xls": ("office-malware-analyzer", "high"),
                    ".xlsx": ("office-malware-analyzer", "medium"),
                    ".xlsm": ("office-malware-analyzer", "high"),
                    ".ppt": ("office-malware-analyzer", "medium"),
                    ".pptx": ("office-malware-analyzer", "medium"),
                    ".pptm": ("office-malware-analyzer", "high"),
                    ".rtf": ("office-malware-analyzer", "medium"),
                    ".pdf": ("pdf-analysis", "medium"),
                    ".zip": ("phishing-analysis", "high"),
                    ".rar": ("phishing-analysis", "high"),
                    ".7z": ("phishing-analysis", "high"),
                }

                # Recommend based on archive_contents (metadata)
                for item in att.get("archive_contents", []):
                    item_ext = item.get("extension", "").lower()
                    item_name = item.get("filename", "")
                    if item_ext in ext_skill_map:
                        skill, priority = ext_skill_map[item_ext]
                        dedup_key = (skill, (item_name,))
                        if dedup_key not in seen_recommendations:
                            seen_recommendations.add(dedup_key)
                            rec = {
                                "skill": skill,
                                "reason": (f"压缩包内含文件需要分析: "
                                           f"{item_name}"),
                                "targets": [item_name],
                                "archive": filename,
                                "priority": priority,
                            }
                            if item_ext == ".eml":
                                rec["reason"] = (
                                    f"压缩包内含邮件需要递归分析: "
                                    f"{item_name}")
                            elif item_ext in {".zip", ".rar", ".7z"}:
                                rec["reason"] = (
                                    f"压缩包内含嵌套压缩包需要递归解压: "
                                    f"{item_name}")
                            recommendations.append(rec)

                # Recommend based on extracted_files (actual files on disk)
                for ef in att.get("extracted_files", []):
                    ef_ext = ef.get("extension", "").lower()
                    ef_name = ef.get("filename", "")
                    ef_path = ef.get("path", "")
                    if ef_ext in ext_skill_map:
                        skill, priority = ext_skill_map[ef_ext]
                        dedup_key = (skill, (ef_name,))
                        if dedup_key not in seen_recommendations:
                            seen_recommendations.add(dedup_key)
                            rec = {
                                "skill": skill,
                                "reason": (f"已提取文件需要分析: "
                                           f"{ef_name}"),
                                "targets": [ef_name],
                                "archive": filename,
                                "priority": priority,
                                "saved_path": ef_path,
                            }
                            if ef_ext == ".eml":
                                rec["reason"] = (
                                    f"已提取邮件需要递归分析: "
                                    f"{ef_name}")
                            elif ef_ext in {".zip", ".rar", ".7z"}:
                                rec["reason"] = (
                                    f"已提取嵌套压缩包需要递归解压: "
                                    f"{ef_name}")
                            recommendations.append(rec)

        # Check domains from IOCs (external domains only)
        iocs = result.get("iocs", {})
        domains = iocs.get("domains", [])
        # Filter out common/benign domains
        suspicious_domains = [d for d in domains if not any(
            d.endswith(b) for b in ["163.com", "qq.com", "gmail.com", "outlook.com"]
        )]
        if suspicious_domains:
            recommendations.append({
                "skill": "domain-analysis",
                "reason": f"发现 {len(suspicious_domains)} 个域名需要分析",
                "targets": suspicious_domains[:5],
                "priority": "medium"
            })

        # Check IPs from IOCs
        ips = iocs.get("ips", [])
        if ips:
            recommendations.append({
                "skill": "ip-analysis",
                "reason": f"发现 {len(ips)} 个 IP 地址需要分析",
                "targets": ips[:5],
                "priority": "medium"
            })

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 3))

        return recommendations

    def _extract_headers(self) -> Dict:
        """Extract email headers."""
        result = {
            "from": self._safe_get_header("From"),
            "to": self._safe_get_header("To"),
            "cc": self._safe_get_header("Cc"),
            "subject": self._safe_get_header("Subject"),
            "date": self._safe_get_header("Date"),
            "reply_to": self._safe_get_header("Reply-To"),
            "return_path": self._safe_get_header("Return-Path"),
            "message_id": self._safe_get_header("Message-ID"),
            "x_mailer": self._safe_get_header("X-Mailer") or self._safe_get_header("User-Agent"),
            "received": [],
            "authentication": {}
        }

        # Extract Received headers
        if self.msg:
            for header in self.msg.get_all("Received", []):
                if header:
                    result["received"].append(str(header)[:200])

        # Authentication results
        auth_results = self._safe_get_header("Authentication-Results")
        spf = self._safe_get_header("Received-SPF")

        result["authentication"] = {
            "spf": self._extract_auth_result(auth_results, "spf") or self._parse_spf(spf),
            "dkim": self._extract_auth_result(auth_results, "dkim"),
            "dmarc": self._extract_auth_result(auth_results, "dmarc"),
            "raw": auth_results[:500] if auth_results else None
        }

        # Extract domains for comparison
        result["from_domain"] = self._extract_domain(result["from"])
        result["reply_to_domain"] = self._extract_domain(result["reply_to"]) if result["reply_to"] else None

        return result

    def _extract_auth_result(self, auth_results: str, auth_type: str) -> Optional[str]:
        """Extract authentication result."""
        if not auth_results:
            return None
        match = re.search(rf'{auth_type}=(\w+)', auth_results, re.IGNORECASE)
        return match.group(1) if match else None

    def _parse_spf(self, spf_header: str) -> Optional[str]:
        """Parse SPF header."""
        if not spf_header:
            return None
        parts = spf_header.split()
        return parts[0] if parts else None

    def _extract_domain(self, address: str) -> Optional[str]:
        """Extract domain from email address."""
        if not address:
            return None
        match = re.search(r'@([a-zA-Z0-9.-]+)', address)
        return match.group(1).lower() if match else None

    def _extract_content(self) -> Dict:
        """Extract email body content."""
        result = {
            "has_html": False,
            "has_text": False,
            "text_body": "",
            "html_preview": "",
            "text_length": 0,
            "urls_in_body": [],
            "image_count": 0
        }

        if self.msg is None:
            return result

        text_body = ""
        html_body = ""

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
                            text_body = decoded
                            result["has_text"] = True
                        elif content_type == "text/html":
                            html_body = decoded
                            result["has_html"] = True
                    except Exception:
                        continue
            else:
                payload = self.msg.get_payload(decode=True)
                if payload:
                    charset = self.msg.get_content_charset() or 'utf-8'
                    try:
                        text_body = payload.decode(charset, errors='replace')
                    except Exception:
                        text_body = payload.decode('utf-8', errors='replace')
                    result["has_text"] = True
        except Exception:
            pass

        # Store content
        result["text_body"] = text_body[:3000] if text_body else ""
        result["html_preview"] = html_body[:1000] if html_body else ""

        # Calculate text length (strip HTML tags)
        combined = text_body + html_body
        text_only = re.sub(r'<[^>]+>', '', combined)
        text_only = re.sub(r'\s+', ' ', text_only).strip()
        result["text_length"] = len(text_only)

        # Extract URLs
        urls = re.findall(r'https?://[^\s<>"\']+', combined)
        result["urls_in_body"] = list(set(url.rstrip('.,;:"\')>') for url in urls))[:30]

        # Count images
        result["image_count"] = len(re.findall(r'<img[^>]+>', html_body, re.IGNORECASE))

        return result

    def _extract_attachments(self, passwords: Optional[List[Dict]] = None,
                             extract_dir: Optional[str] = None) -> List[Dict]:
        """Extract attachment information.

        Args:
            passwords: Password dicts from _detect_passwords(),
                       each has a "password" key.
            extract_dir: If provided, save attachments to this directory
                         and auto-extract archives.
        """
        attachments = []

        if self.msg is None:
            return attachments

        # Extract string passwords from password dicts (limit to 10)
        pwd_candidates = []
        if passwords:
            pwd_candidates = [
                d.get("password") for d in passwords
                if isinstance(d, dict) and d.get("password")
            ][:10]

        # Create extract_dir if needed
        if extract_dir:
            Path(extract_dir).mkdir(parents=True, exist_ok=True)

        try:
            for part in self.msg.walk():
                try:
                    if part.get_content_disposition() != "attachment":
                        continue

                    filename = part.get_filename() or "unnamed"
                    content_type = part.get_content_type()
                    payload = part.get_payload(decode=True)

                    att_info = {
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(payload) if payload else 0,
                        "extension": Path(filename).suffix.lower()
                    }

                    if payload:
                        att_info["md5"] = hashlib.md5(payload).hexdigest()
                        att_info["sha256"] = hashlib.sha256(payload).hexdigest()

                    # Save attachment to disk if requested
                    if extract_dir and payload:
                        safe_name = self._sanitize_attachment_name(filename)
                        save_path = Path(extract_dir) / safe_name
                        try:
                            save_path.write_bytes(payload)
                            att_info["saved_path"] = str(save_path)
                        except Exception as e:
                            att_info["save_error"] = str(e)

                    # Analyze archive if possible
                    is_archive = att_info["extension"] in {
                        ".zip", ".rar", ".7z", ".tar", ".gz"}
                    if is_archive:
                        att_info["is_archive"] = True
                        if ArchiveAnalyzer and payload:
                            try:
                                analyzer = ArchiveAnalyzer()
                                archive_result = analyzer.analyze_from_bytes(
                                    payload, filename)
                                att_info["archive_contents"] = archive_result.get(
                                    "contents", [])
                                att_info["archive_encrypted"] = archive_result.get(
                                    "is_encrypted", False)
                            except Exception:
                                att_info["archive_contents"] = []
                                att_info["archive_encrypted"] = None

                            # Auto-extract archive if extract_dir is set
                            if extract_dir:
                                archive_extract_dir = str(
                                    Path(extract_dir) /
                                    f"{Path(filename).stem}_contents")

                                extract_result = None
                                if att_info.get("archive_encrypted") and pwd_candidates:
                                    extract_result = self._try_extract_archive(
                                        analyzer, payload, filename,
                                        pwd_candidates, archive_extract_dir)
                                elif not att_info.get("archive_encrypted"):
                                    # Non-encrypted archive, extract directly
                                    try:
                                        extract_result = analyzer.extract_from_bytes(
                                            payload, filename,
                                            extract_dir=archive_extract_dir)
                                    except Exception as e:
                                        att_info["extraction_errors"] = [str(e)]

                                if extract_result:
                                    att_info["extracted_files"] = extract_result.get(
                                        "extracted_files", [])
                                    att_info["extraction_password"] = extract_result.get(
                                        "password_used")
                                    att_info["extraction_errors"] = extract_result.get(
                                        "errors", [])
                    else:
                        att_info["is_archive"] = False

                    attachments.append(att_info)
                except Exception:
                    continue
        except Exception:
            pass

        return attachments

    def _extract_urls(self) -> List[str]:
        """Extract all URLs from email."""
        urls = set()
        try:
            raw_str = self.raw_content.decode('utf-8', errors='replace')
            found = re.findall(r'https?://[^\s<>"\']+', raw_str)
            for url in found:
                urls.add(url.rstrip('.,;:"\')>'))
        except Exception:
            pass
        return list(urls)[:50]

    def _extract_iocs(self) -> Dict:
        """Extract IOCs from email."""
        if not IOCExtractor:
            return {}

        try:
            raw_str = self.raw_content.decode('utf-8', errors='replace')
            extractor = IOCExtractor(raw_str)
            return extractor.extract_all()
        except Exception:
            return {}

    def _detect_passwords(self) -> List[Dict]:
        """Detect password patterns in email body."""
        passwords = []

        if self.msg is None:
            return passwords

        text_content = ""
        try:
            for part in self.msg.walk():
                try:
                    if part.get_content_type() in ["text/plain", "text/html"]:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            try:
                                text_content += payload.decode(charset, errors='replace')
                            except Exception:
                                text_content += payload.decode('utf-8', errors='replace')
                except Exception:
                    continue
        except Exception:
            pass

        if detect_password_in_text:
            passwords = detect_password_in_text(text_content)
        else:
            # Fallback pattern matching
            patterns = [
                (r'密码[是为:：]?\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)', "zh"),
                (r'解压密码[是为:：]?\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)', "zh"),
                (r'password[:\s]+["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)', "en"),
                (r'pwd[:\s]+["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)', "en"),
            ]
            for pattern, lang in patterns:
                matches = re.finditer(pattern, text_content, re.IGNORECASE)
                for match in matches:
                    passwords.append({
                        "password": match.group(1),
                        "language": lang,
                        "context": text_content[max(0, match.start()-30):match.end()+30]
                    })

        return passwords

    def _detect_evasion(self) -> Dict:
        """Detect evasion techniques in email."""
        if not EvasionDetector:
            return {}

        try:
            detector = EvasionDetector(raw_content=self.raw_content)
            result = detector.detect()
            # Return only the evasion_techniques and summary parts
            return {
                "techniques": result.get("evasion_techniques", {}),
                "summary": result.get("summary", {})
            }
        except Exception:
            return {}

    @staticmethod
    def _sanitize_attachment_name(filename: str) -> str:
        """Sanitize attachment filename for safe disk storage."""
        if not filename:
            return "unnamed_attachment"
        # Normalize separators
        name = filename.replace("\\", "/")
        # Take only the basename
        name = name.split("/")[-1] if "/" in name else name
        # Remove control characters
        name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', name)
        # Remove Windows-unsafe characters
        name = re.sub(r'[<>:"|?*]', '', name)
        # Limit length
        if len(name) > 200:
            stem = Path(name).stem[:180]
            suffix = Path(name).suffix[:20]
            name = stem + suffix
        if not name or name.isspace():
            return "unnamed_attachment"
        return name

    @staticmethod
    def _try_extract_archive(analyzer, payload: bytes, filename: str,
                             passwords: List[str],
                             extract_dir: str) -> Optional[Dict]:
        """Try to extract an archive with multiple password candidates."""
        for pwd in passwords:
            try:
                result = analyzer.extract_from_bytes(
                    payload, filename, password=pwd, extract_dir=extract_dir)
                # Check if extraction succeeded (has files or no password errors)
                if result.get("extracted_files"):
                    result["password_used"] = pwd
                    return result
                # Check if errors are only about password
                errors = result.get("errors", [])
                password_errors = [e for e in errors
                                   if "password" in e.lower()
                                   or "encrypt" in e.lower()]
                if len(password_errors) < len(errors):
                    # Non-password errors, return this result
                    return result
            except Exception:
                continue

        # Try without password as last resort
        try:
            return analyzer.extract_from_bytes(
                payload, filename, password=None, extract_dir=extract_dir)
        except Exception:
            return None


def format_output(result: Dict, output_format: str = "json") -> str:
    """Format extraction results."""
    if output_format == "json":
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    # Simple text format
    lines = []
    lines.append("=" * 60)
    lines.append("EMAIL EXTRACTION RESULT")
    lines.append("=" * 60)

    if "error" in result:
        lines.append(f"\nError: {result['error']}")
        return "\n".join(lines)

    headers = result.get("headers", {})
    lines.append(f"\nFrom: {headers.get('from', 'N/A')}")
    lines.append(f"To: {headers.get('to', 'N/A')}")
    lines.append(f"Subject: {headers.get('subject', 'N/A')}")
    lines.append(f"Date: {headers.get('date', 'N/A')}")
    lines.append(f"Reply-To: {headers.get('reply_to', 'N/A')}")

    auth = headers.get("authentication", {})
    lines.append(f"\nSPF: {auth.get('spf', 'N/A')}")
    lines.append(f"DKIM: {auth.get('dkim', 'N/A')}")
    lines.append(f"DMARC: {auth.get('dmarc', 'N/A')}")

    content = result.get("content", {})
    lines.append(f"\nBody Length: {content.get('text_length', 0)} chars")
    lines.append(f"URLs in body: {len(content.get('urls_in_body', []))}")

    attachments = result.get("attachments", [])
    if attachments:
        lines.append(f"\nAttachments ({len(attachments)}):")
        for att in attachments:
            encrypted = " [ENCRYPTED]" if att.get("archive_encrypted") else ""
            lines.append(f"  - {att['filename']} ({att['size']} bytes){encrypted}")

    passwords = result.get("passwords_in_body", [])
    if passwords:
        lines.append(f"\nPasswords in body ({len(passwords)}):")
        for p in passwords:
            lines.append(f"  - {p.get('password', 'N/A')}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Extract email information for phishing analysis"
    )
    parser.add_argument("email", help="Email file (.eml) to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="json",
                       help="Output format (default: json)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--save-attachments", action="store_true",
                       help="Save attachments to disk and auto-extract "
                            "encrypted archives")
    parser.add_argument("--output-dir",
                       help="Directory for saved attachments "
                            "(implies --save-attachments)")
    args = parser.parse_args()

    save = args.save_attachments or bool(args.output_dir)
    extractor = EmailExtractor(args.email)
    result = extractor.extract(
        save_attachments=save,
        output_dir=args.output_dir,
    )

    output = format_output(result, args.format)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Result saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
