#!/usr/bin/env python3
"""
QR Code Analyzer for Phishing Detection (Quishing)
Extracts and analyzes QR codes from images and emails.

Supports multiple QR decode backends with automatic fallback:
1. pyzbar (fastest, requires system library)
2. qreader (pure Python, neural network based)
3. cv2.QRCodeDetector (if OpenCV installed)

Install options:
  pip install pillow pyzbar      # Recommended (requires libzbar)
  pip install pillow qreader     # Pure Python alternative
  pip install pillow opencv-python  # OpenCV alternative
"""

import sys
import json
import re
import base64
import email
from email import policy
from email.parser import Parser
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from urllib.parse import urlparse, unquote
import io

# Dependency availability tracking
AVAILABLE_BACKENDS: List[str] = []
QR_DECODE_FUNC: Optional[Callable] = None

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Backend 1: pyzbar (fastest, needs system zbar library)
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from pyzbar.pyzbar import ZBarSymbol
    PYZBAR_AVAILABLE = True
    AVAILABLE_BACKENDS.append("pyzbar")
except ImportError:
    PYZBAR_AVAILABLE = False

# Backend 2: qreader (pure Python, neural network based)
try:
    from qreader import QReader
    QREADER_AVAILABLE = True
    AVAILABLE_BACKENDS.append("qreader")
except ImportError:
    QREADER_AVAILABLE = False

# Backend 3: OpenCV QRCodeDetector
try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
    AVAILABLE_BACKENDS.append("cv2")
except ImportError:
    CV2_AVAILABLE = False


def _get_dependency_status() -> Dict:
    """Return detailed dependency status for debugging."""
    return {
        "pillow": PIL_AVAILABLE,
        "pyzbar": PYZBAR_AVAILABLE,
        "qreader": QREADER_AVAILABLE,
        "cv2": CV2_AVAILABLE,
        "available_backends": AVAILABLE_BACKENDS,
        "recommended_install": _get_install_recommendation()
    }


def _get_install_recommendation() -> str:
    """Generate installation recommendation based on missing dependencies."""
    if not PIL_AVAILABLE:
        return "pip install pillow"
    if not AVAILABLE_BACKENDS:
        return (
            "Install one of:\n"
            "  pip install pyzbar  # Fastest (needs: brew install zbar / apt install libzbar0)\n"
            "  pip install qreader  # Pure Python (larger download, no system deps)\n"
            "  pip install opencv-python  # If OpenCV already in use"
        )
    return "Dependencies OK"

# Load configuration
try:
    from config_loader import get_shorteners, get_suspicious_tlds, get_phishing_platforms
    SHORTENERS = get_shorteners()
    SUSPICIOUS_TLDS = get_suspicious_tlds()
    PHISHING_PLATFORMS = get_phishing_platforms()
except ImportError:
    # Fallback to minimal defaults
    SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "qr.io"}
    SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top"}
    PHISHING_PLATFORMS = {"knowbe4.com", "cofense.com", "gophish.com"}


class QRAnalyzer:
    """Analyze QR codes for phishing indicators."""

    def __init__(self, backend: Optional[str] = None):
        """
        Initialize QR analyzer.

        Args:
            backend: Force specific backend ('pyzbar', 'qreader', 'cv2')
                     If None, auto-selects best available.
        """
        self.findings: List[str] = []
        self.risk_score = 0
        self.backend = backend or self._select_backend()
        self._qreader_instance = None  # Lazy init for qreader

    def _select_backend(self) -> Optional[str]:
        """Select best available backend."""
        # Priority: pyzbar > qreader > cv2
        if PYZBAR_AVAILABLE:
            return "pyzbar"
        elif QREADER_AVAILABLE:
            return "qreader"
        elif CV2_AVAILABLE:
            return "cv2"
        return None

    def get_status(self) -> Dict:
        """Get dependency and backend status."""
        status = _get_dependency_status()
        status["active_backend"] = self.backend
        return status

    def analyze_image(self, image_path: str) -> Dict:
        """Analyze QR codes in an image file."""
        if not PIL_AVAILABLE:
            return {"error": "PIL not installed. Run: pip install pillow"}
        if not self.backend:
            return {
                "error": "No QR decode backend available",
                "install_options": _get_install_recommendation(),
                "dependency_status": _get_dependency_status()
            }

        try:
            img = Image.open(image_path)
            return self._analyze_image(img, image_path)
        except Exception as e:
            return {"error": f"Failed to open image: {str(e)}"}

    def analyze_image_bytes(self, image_bytes: bytes, source: str = "embedded") -> Dict:
        """Analyze QR codes from image bytes."""
        if not PIL_AVAILABLE:
            return {"error": "PIL not installed. Run: pip install pillow"}
        if not self.backend:
            return {"error": "No QR decode backend available"}

        try:
            img = Image.open(io.BytesIO(image_bytes))
            return self._analyze_image(img, source)
        except Exception as e:
            return {"error": f"Failed to decode image: {str(e)}"}

    def _decode_with_pyzbar(self, img: Image.Image) -> List[str]:
        """Decode using pyzbar backend."""
        qr_codes = pyzbar_decode(img, symbols=[ZBarSymbol.QRCODE])
        return [qr.data.decode('utf-8', errors='replace') for qr in qr_codes]

    def _decode_with_qreader(self, img: Image.Image) -> List[str]:
        """Decode using qreader backend (pure Python, neural network)."""
        if self._qreader_instance is None:
            self._qreader_instance = QReader()

        # qreader needs numpy array
        import numpy as np
        img_array = np.array(img)

        # qreader.detect_and_decode returns list of decoded strings
        results = self._qreader_instance.detect_and_decode(img_array)
        return [r for r in results if r is not None]

    def _decode_with_cv2(self, img: Image.Image) -> List[str]:
        """Decode using OpenCV QRCodeDetector."""
        img_array = np.array(img)

        # Convert to BGR if RGB (OpenCV uses BGR)
        if len(img_array.shape) == 3 and img_array.shape[2] == 3:
            img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)

        detector = cv2.QRCodeDetector()

        # Try single QR first
        data, _, _ = detector.detectAndDecode(img_array)
        if data:
            return [data]

        # Try multi-QR detection
        try:
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(img_array)
            if retval:
                return [d for d in decoded_info if d]
        except cv2.error:
            pass

        return []

    def _analyze_image(self, img: Image.Image, source: str) -> Dict:
        """Internal method to analyze PIL Image."""
        # Convert to RGB if necessary
        if img.mode not in ('L', 'RGB'):
            img = img.convert('RGB')

        # Decode QR codes using selected backend
        try:
            if self.backend == "pyzbar":
                qr_data_list = self._decode_with_pyzbar(img)
            elif self.backend == "qreader":
                qr_data_list = self._decode_with_qreader(img)
            elif self.backend == "cv2":
                qr_data_list = self._decode_with_cv2(img)
            else:
                return {"error": f"Unknown backend: {self.backend}"}
        except Exception as e:
            return {
                "source": source,
                "error": f"Decode failed with {self.backend}: {str(e)}",
                "backend": self.backend
            }

        if not qr_data_list:
            return {
                "source": source,
                "qr_found": False,
                "message": "No QR codes detected in image",
                "backend": self.backend
            }

        results = []
        for data in qr_data_list:
            analysis = self._analyze_qr_content(data)
            results.append(analysis)

        return {
            "source": source,
            "qr_found": True,
            "qr_count": len(results),
            "results": results,
            "total_risk_score": sum(r.get("risk_score", 0) for r in results),
            "findings": self.findings,
            "backend": self.backend
        }

    def _analyze_qr_content(self, content: str) -> Dict:
        """Analyze the content extracted from a QR code."""
        result = {
            "raw_content": content[:500],  # Truncate for safety
            "content_type": self._detect_content_type(content),
            "risk_score": 0,
            "indicators": []
        }

        content_type = result["content_type"]

        if content_type == "url":
            url_analysis = self._analyze_url(content)
            result.update(url_analysis)

        elif content_type == "email":
            result["indicators"].append("Contains email address")
            # Check for suspicious patterns
            if "password" in content.lower() or "credential" in content.lower():
                result["risk_score"] += 20
                result["indicators"].append("Contains credential-related keywords")

        elif content_type == "phone":
            result["indicators"].append("Contains phone number")
            # Premium rate numbers
            if re.search(r'^\+?1?900|^\+44[0-9]{1,3}9', content):
                result["risk_score"] += 15
                result["indicators"].append("Potential premium rate number")

        elif content_type == "wifi":
            result["indicators"].append("WiFi configuration QR")
            # Check for suspicious network names
            if any(brand in content.lower() for brand in ["bank", "secure", "corp", "vpn"]):
                result["risk_score"] += 10
                result["indicators"].append("Suspicious network name mimicking corporate/bank")

        elif content_type == "vcard":
            result["indicators"].append("vCard/Contact QR")
            # Extract URLs from vCard
            urls = re.findall(r'https?://[^\s;]+', content)
            if urls:
                result["embedded_urls"] = urls
                for url in urls:
                    url_analysis = self._analyze_url(url)
                    result["risk_score"] += url_analysis.get("risk_score", 0) // 2

        elif content_type == "text":
            # Check for suspicious text patterns
            suspicious_patterns = [
                (r'password', "Contains 'password'"),
                (r'verify.*account', "Account verification request"),
                (r'click.*here', "Click here prompt"),
                (r'urgent|immediate', "Urgency language"),
                (r'bitcoin|crypto|wallet', "Cryptocurrency reference"),
            ]
            for pattern, desc in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    result["risk_score"] += 10
                    result["indicators"].append(desc)

        return result

    def _detect_content_type(self, content: str) -> str:
        """Detect the type of QR code content."""
        content_lower = content.lower().strip()

        if content_lower.startswith(('http://', 'https://')):
            return "url"
        elif content_lower.startswith('mailto:'):
            return "email"
        elif content_lower.startswith(('tel:', 'sms:', 'smsto:')):
            return "phone"
        elif content_lower.startswith('wifi:'):
            return "wifi"
        elif content_lower.startswith('begin:vcard'):
            return "vcard"
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', content):
            return "email"
        else:
            return "text"

    def _analyze_url(self, url: str) -> Dict:
        """Analyze URL extracted from QR code."""
        result = {
            "url": url,
            "risk_score": 0,
            "indicators": []
        }

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port
            domain_only = domain.split(':')[0]

            result["domain"] = domain_only
            result["scheme"] = parsed.scheme
            result["path"] = parsed.path

            # Check for IP address
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_only):
                result["risk_score"] += 25
                result["indicators"].append("URL uses IP address instead of domain")
                result["is_ip"] = True

            # Check for URL shortener
            if domain_only in SHORTENERS or any(domain_only.endswith("." + s) for s in SHORTENERS):
                result["risk_score"] += 20
                result["indicators"].append(f"URL shortener detected: {domain_only}")
                result["is_shortener"] = True

            # Check TLD
            parts = domain_only.split('.')
            if parts:
                tld = parts[-1]
                if tld in SUSPICIOUS_TLDS:
                    result["risk_score"] += 15
                    result["indicators"].append(f"Suspicious TLD: .{tld}")

            # Check for phishing simulation
            for platform in PHISHING_PLATFORMS:
                if platform in domain_only:
                    result["indicators"].append(f"Known phishing simulation platform: {platform}")
                    result["is_simulation"] = True
                    result["risk_score"] = max(0, result["risk_score"] - 30)

            # Check for HTTP (not HTTPS)
            if parsed.scheme == 'http':
                result["risk_score"] += 10
                result["indicators"].append("Uses HTTP instead of HTTPS")

            # Check for encoded characters in URL
            if '%' in url:
                decoded = unquote(url)
                if decoded != url:
                    result["decoded_url"] = decoded
                    result["indicators"].append("URL contains encoded characters")

            # Check for suspicious paths
            suspicious_paths = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'password']
            path_lower = parsed.path.lower()
            for sp in suspicious_paths:
                if sp in path_lower:
                    result["risk_score"] += 5
                    result["indicators"].append(f"Suspicious path keyword: {sp}")
                    break

            # Check for data exfiltration parameters
            if parsed.query:
                params = parsed.query.lower()
                if any(p in params for p in ['email', 'user', 'pass', 'token', 'key']):
                    result["risk_score"] += 10
                    result["indicators"].append("Query parameters suggest data collection")

        except Exception as e:
            result["error"] = str(e)

        return result

    def analyze_email(self, email_path: str) -> Dict:
        """Analyze QR codes in email attachments and embedded images."""
        if not PIL_AVAILABLE:
            return {"error": "Pillow not installed. Run: pip install pillow"}
        if not self.backend:
            return {
                "error": "No QR decode backend available",
                "install_options": _get_install_recommendation()
            }

        try:
            with open(email_path, 'r', encoding='utf-8', errors='ignore') as f:
                msg = Parser(policy=policy.default).parse(f)
        except Exception as e:
            return {"error": f"Failed to parse email: {str(e)}"}

        results = []

        for part in msg.walk():
            content_type = part.get_content_type()

            # Check for image attachments
            if content_type.startswith('image/'):
                filename = part.get_filename() or "unnamed"
                try:
                    image_data = part.get_payload(decode=True)
                    if image_data:
                        analysis = self.analyze_image_bytes(image_data, f"attachment:{filename}")
                        if analysis.get("qr_found"):
                            results.append(analysis)
                except Exception as e:
                    results.append({
                        "source": f"attachment:{filename}",
                        "error": str(e)
                    })

            # Check for inline images (base64 in HTML)
            elif content_type == 'text/html':
                html_content = part.get_payload(decode=True)
                if html_content:
                    html_str = html_content.decode('utf-8', errors='ignore')
                    # Find base64 encoded images
                    img_matches = re.findall(
                        r'data:image/[^;]+;base64,([A-Za-z0-9+/=]+)',
                        html_str
                    )
                    for i, b64_data in enumerate(img_matches):
                        try:
                            image_data = base64.b64decode(b64_data)
                            analysis = self.analyze_image_bytes(image_data, f"inline_image_{i}")
                            if analysis.get("qr_found"):
                                results.append(analysis)
                        except Exception:
                            pass

        return {
            "email_path": email_path,
            "qr_found": len(results) > 0,
            "images_with_qr": len(results),
            "analyses": results,
            "total_risk_score": sum(
                a.get("total_risk_score", 0) for a in results
            )
        }


def format_output(results: Dict, output_format: str = "text") -> str:
    """Format analysis results."""
    if output_format == "json":
        return json.dumps(results, indent=2, ensure_ascii=False)

    lines = []
    lines.append("=" * 60)
    lines.append("QR CODE ANALYSIS REPORT (QUISHING DETECTION)")
    lines.append("=" * 60)

    if "error" in results:
        lines.append(f"\n[ERROR] {results['error']}")
        return "\n".join(lines)

    lines.append(f"\nSource: {results.get('source', results.get('email_path', 'unknown'))}")
    lines.append(f"QR Codes Found: {results.get('qr_found', False)}")

    if results.get('qr_found'):
        if "results" in results:
            # Single image analysis
            for i, qr in enumerate(results["results"], 1):
                lines.append(f"\n[QR CODE #{i}]")
                lines.append(f"  Type: {qr.get('content_type', 'unknown')}")
                lines.append(f"  Content: {qr.get('raw_content', '')[:100]}...")
                lines.append(f"  Risk Score: {qr.get('risk_score', 0)}")

                if qr.get("domain"):
                    lines.append(f"  Domain: {qr['domain']}")

                if qr.get("indicators"):
                    lines.append("  Indicators:")
                    for ind in qr["indicators"]:
                        lines.append(f"    [!] {ind}")

        elif "analyses" in results:
            # Email analysis
            for analysis in results["analyses"]:
                lines.append(f"\n[IMAGE: {analysis.get('source', 'unknown')}]")
                if "results" in analysis:
                    for qr in analysis["results"]:
                        lines.append(f"  Type: {qr.get('content_type', 'unknown')}")
                        lines.append(f"  Content: {qr.get('raw_content', '')[:100]}...")
                        lines.append(f"  Risk Score: {qr.get('risk_score', 0)}")
                        if qr.get("indicators"):
                            for ind in qr["indicators"]:
                                lines.append(f"    [!] {ind}")

    lines.append(f"\n[TOTAL RISK SCORE] {results.get('total_risk_score', 0)}")

    risk_level = "LOW"
    total_risk = results.get('total_risk_score', 0)
    if total_risk >= 50:
        risk_level = "HIGH"
    elif total_risk >= 25:
        risk_level = "MEDIUM"

    lines.append(f"[RISK LEVEL] {risk_level}")
    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Analyze QR codes for phishing indicators (Quishing detection)"
    )
    parser.add_argument("input", nargs="?", help="Image file or .eml email file to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                       help="Output format")
    parser.add_argument("--status", action="store_true",
                       help="Show dependency and backend status")
    parser.add_argument("--backend", choices=["pyzbar", "qreader", "cv2"],
                       help="Force specific backend")
    args = parser.parse_args()

    # Show status if requested
    if args.status:
        analyzer = QRAnalyzer(backend=args.backend)
        status = analyzer.get_status()
        if args.format == "json":
            print(json.dumps(status, indent=2))
        else:
            print("=" * 50)
            print("QR ANALYZER DEPENDENCY STATUS")
            print("=" * 50)
            print(f"Pillow:  {'[+] installed' if status['pillow'] else '[-] missing'}")
            print(f"pyzbar:  {'[+] installed' if status['pyzbar'] else '[-] not available'}")
            print(f"qreader: {'[+] installed' if status['qreader'] else '[-] not available'}")
            print(f"OpenCV:  {'[+] installed' if status['cv2'] else '[-] not available'}")
            print(f"\nActive backend: {status['active_backend'] or 'NONE'}")
            print(f"Available backends: {', '.join(status['available_backends']) or 'NONE'}")
            if not status['available_backends']:
                print(f"\n{status['recommended_install']}")
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    # Check dependencies
    if not PIL_AVAILABLE:
        print("Error: Pillow not installed. Run: pip install pillow", file=sys.stderr)
        sys.exit(1)

    if not AVAILABLE_BACKENDS:
        print("Error: No QR decode backend available.", file=sys.stderr)
        print(_get_install_recommendation(), file=sys.stderr)
        sys.exit(1)

    analyzer = QRAnalyzer(backend=args.backend)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if input_path.suffix.lower() == '.eml':
        results = analyzer.analyze_email(args.input)
    else:
        results = analyzer.analyze_image(args.input)

    print(format_output(results, args.format))


if __name__ == "__main__":
    main()
