#!/usr/bin/env python3
"""
Archive Analyzer for Malware Delivery Detection
Analyzes ZIP/RAR/7z archives for suspicious content and password protection.

Supports multiple archive libraries with automatic fallback:
- zipfile (standard library, always available)
- pyzipper (AES encrypted ZIPs)
- py7zr (7z archives)
- rarfile (RAR archives)

Install for full support:
  pip install pyzipper py7zr rarfile
"""

import sys
import json
import re
import zipfile
import struct
import hashlib
import shutil
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

# Track available backends
AVAILABLE_BACKENDS: Dict[str, bool] = {
    "zipfile": True,  # Always available (stdlib)
}

# Optional: pyzipper for AES encrypted ZIPs
try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
    AVAILABLE_BACKENDS["pyzipper"] = True
except ImportError:
    PYZIPPER_AVAILABLE = False
    AVAILABLE_BACKENDS["pyzipper"] = False

# Optional: py7zr for 7z archives
try:
    import py7zr
    PY7ZR_AVAILABLE = True
    AVAILABLE_BACKENDS["py7zr"] = True
except ImportError:
    PY7ZR_AVAILABLE = False
    AVAILABLE_BACKENDS["py7zr"] = False

# Optional: rarfile for RAR archives
try:
    import rarfile
    RARFILE_AVAILABLE = True
    AVAILABLE_BACKENDS["rarfile"] = True
except ImportError:
    RARFILE_AVAILABLE = False
    AVAILABLE_BACKENDS["rarfile"] = False


def get_backend_status() -> Dict:
    """Return detailed backend status for debugging."""
    return {
        "available": AVAILABLE_BACKENDS.copy(),
        "recommended_install": _get_install_recommendation()
    }


def _get_install_recommendation() -> str:
    """Generate installation recommendation based on missing libraries."""
    missing = []
    if not PYZIPPER_AVAILABLE:
        missing.append("pyzipper  # AES encrypted ZIPs")
    if not PY7ZR_AVAILABLE:
        missing.append("py7zr     # 7z archives")
    if not RARFILE_AVAILABLE:
        missing.append("rarfile   # RAR archives (needs: brew install unrar)")

    if not missing:
        return "All backends installed"

    return "For full support, install:\n  pip install " + " ".join(
        [m.split()[0] for m in missing]
    )


# Load configuration
try:
    from config_loader import get_archive_risks, get_malware_delivery_patterns
    ARCHIVE_RISKS = get_archive_risks()
    MALWARE_PATTERNS = get_malware_delivery_patterns()
except ImportError:
    ARCHIVE_RISKS = {
        "suspicious_filenames": ["invoice", "document", "report"],
        "numeric_filename_pattern": r"^\d+\.(exe|scr|bat|cmd|js|vbs)$",
        "double_extension_pattern": r"\.(pdf|doc|xls|jpg|png)\.(exe|scr|bat|js|vbs|hta)$"
    }
    MALWARE_PATTERNS = {}

# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".msi", ".com", ".pif", ".wsf", ".wsh", ".jse", ".vbe",
    ".lnk", ".url"
}

SCRIPT_EXTENSIONS = {".js", ".vbs", ".ps1", ".bat", ".cmd", ".wsf", ".hta"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso", ".img"}

# Extraction safety limits
MAX_SINGLE_FILE = 500 * 1024 * 1024       # 500MB per file
MAX_TOTAL_EXTRACT = 2 * 1024 * 1024 * 1024  # 2GB total
MIN_DISK_FREE = 100 * 1024 * 1024          # 100MB minimum free disk space
MAX_COMPRESSION_RATIO = 50                 # Warn if ratio > 50:1


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and other attacks."""
    if not filename:
        return "extracted_file"

    # Normalize path separators
    name = filename.replace("\\", "/")

    # Remove UNC paths (\\server\share)
    name = re.sub(r'^//+[^/]*/?', '', name)

    # Remove absolute path prefixes (C:\, /, etc.)
    name = re.sub(r'^[a-zA-Z]:', '', name)
    name = name.lstrip("/")

    # Remove relative path components
    parts = name.split("/")
    parts = [p for p in parts if p not in (".", "..")]
    name = parts[-1] if parts else ""

    # Remove control characters
    name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', name)

    # Remove Windows-unsafe characters
    name = re.sub(r'[<>:"|?*]', '', name)

    # Limit length
    if len(name) > 200:
        stem = Path(name).stem[:180]
        suffix = Path(name).suffix[:20]
        name = stem + suffix

    # Fallback for empty result
    if not name or name.isspace():
        return "extracted_file"

    return name


def _detect_file_type(file_path: Path) -> str:
    """Detect file type by reading magic bytes."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception:
        return "unknown"

    if not header:
        return "empty"

    # Check magic bytes
    if header[:4] == b'%PDF':
        return "pdf"
    if header[:2] == b'PK':
        return "zip"
    if header[:4] == b'Rar!':
        return "rar"
    if header[:6] == b"7z\xbc\xaf'\x1c":
        return "7z"
    if header[:2] == b'MZ':
        return "pe_executable"
    if header[:4] == b'\xd0\xcf\x11\xe0':
        return "ole_document"
    if header[:4] == b'\x50\x4b\x03\x04':
        return "zip"
    if header[:3] == b'GIF':
        return "gif"
    if header[:2] == b'\xff\xd8':
        return "jpeg"
    if header[:8] == b'\x89PNG\r\n\x1a\n':
        return "png"
    if header[:4] == b'\x1f\x8b\x08\x00':
        return "gzip"
    if header[:6] == b'\xfd7zXZ\x00':
        return "xz"

    return "unknown"


def _compute_file_hashes(file_path: Path) -> Dict[str, str]:
    """Compute MD5 and SHA256 hashes of a file using chunked reading."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
    except Exception:
        return {"md5": "", "sha256": ""}


class ArchiveAnalyzer:
    """Analyze archives for malware delivery indicators."""

    def __init__(self):
        self.findings: List[str] = []
        self.risk_score = 0

    def analyze(self, file_path: str) -> Dict:
        """Analyze an archive file."""
        self.findings = []
        self.risk_score = 0

        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}

        result = {
            "file_path": str(path),
            "file_name": path.name,
            "file_size": path.stat().st_size,
            "file_extension": path.suffix.lower(),
            "is_archive": False,
            "is_encrypted": False,
            "contents": [],
            "suspicious_files": [],
            "risk_indicators": [],
            "risk_score": 0,
            "risk_level": "NONE",
            "findings": []
        }

        # Calculate file hash
        try:
            with open(path, "rb") as f:
                content = f.read()
                result["md5"] = hashlib.md5(content).hexdigest()
                result["sha256"] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            result["hash_error"] = str(e)

        # Detect archive type and analyze
        if path.suffix.lower() == ".zip" or self._is_zip(path):
            result["archive_type"] = "ZIP"
            result["is_archive"] = True
            self._analyze_zip(path, result)
        elif path.suffix.lower() in {".rar"}:
            result["archive_type"] = "RAR"
            result["is_archive"] = True
            self._analyze_rar_basic(path, result)
        elif path.suffix.lower() in {".7z"}:
            result["archive_type"] = "7Z"
            result["is_archive"] = True
            self._analyze_7z_basic(path, result)
        else:
            result["message"] = "Unsupported or non-archive file"

        result["risk_score"] = self.risk_score
        result["risk_level"] = self._calculate_risk_level()
        result["findings"] = self.findings

        return result

    def _is_zip(self, path: Path) -> bool:
        """Check if file is a ZIP archive by magic bytes."""
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                return magic[:2] == b'PK'
        except Exception:
            return False

    def _analyze_zip(self, path: Path, result: Dict):
        """Analyze ZIP archive."""
        try:
            with zipfile.ZipFile(path, 'r') as zf:
                # Check if encrypted
                for info in zf.infolist():
                    if info.flag_bits & 0x1:  # Encrypted flag
                        result["is_encrypted"] = True
                        self.findings.append("Archive is password protected")
                        self.risk_score += 25
                        break

                # List contents
                for info in zf.infolist():
                    file_info = self._analyze_zip_entry(info)
                    result["contents"].append(file_info)

                    if file_info.get("is_suspicious"):
                        result["suspicious_files"].append(file_info)

        except zipfile.BadZipFile:
            result["error"] = "Invalid or corrupted ZIP file"
        except Exception as e:
            result["error"] = str(e)

    def _analyze_zip_entry(self, info: zipfile.ZipInfo) -> Dict:
        """Analyze a single ZIP entry."""
        filename = info.filename
        entry = {
            "filename": filename,
            "compressed_size": info.compress_size,
            "uncompressed_size": info.file_size,
            "is_directory": info.is_dir(),
            "is_encrypted": bool(info.flag_bits & 0x1),
            "compression_method": info.compress_type,
            "is_suspicious": False,
            "risk_indicators": []
        }

        if info.is_dir():
            return entry

        # Use common analysis logic
        return self._analyze_entry_common(entry, filename)

    def _analyze_rar_basic(self, path: Path, result: Dict):
        """RAR analysis with optional rarfile library."""
        # Try full analysis with rarfile library first
        if RARFILE_AVAILABLE:
            self._analyze_rar_full(path, result)
            return

        # Fallback to basic header analysis
        try:
            with open(path, "rb") as f:
                sig = f.read(7)
                if sig[:4] == b'Rar!':
                    result["is_archive"] = True

                    # Check for encryption flag in RAR header
                    f.seek(0)
                    content = f.read(1024)

                    # RAR5 encryption check
                    if b'\x04\x00' in content[10:20]:
                        result["is_encrypted"] = True
                        self.findings.append("RAR archive appears to be encrypted")
                        self.risk_score += 25

                    result["message"] = "RAR detected. Install 'rarfile' for detailed analysis."
                    result["backend"] = "basic"
                else:
                    result["error"] = "Not a valid RAR file"

        except Exception as e:
            result["error"] = str(e)

    def _analyze_rar_full(self, path: Path, result: Dict):
        """Full RAR analysis using rarfile library."""
        try:
            rf = rarfile.RarFile(str(path))
            result["backend"] = "rarfile"

            # Check encryption
            if rf.needs_password():
                result["is_encrypted"] = True
                self.findings.append("RAR archive is password protected")
                self.risk_score += 25

            # List contents
            for info in rf.infolist():
                file_info = self._analyze_rar_entry(info)
                result["contents"].append(file_info)

                if file_info.get("is_suspicious"):
                    result["suspicious_files"].append(file_info)

            rf.close()

        except rarfile.NeedFirstVolume:
            result["error"] = "Multi-volume RAR: need first volume"
        except rarfile.BadRarFile:
            result["error"] = "Invalid or corrupted RAR file"
        except Exception as e:
            result["error"] = str(e)

    def _analyze_rar_entry(self, info) -> Dict:
        """Analyze a single RAR entry."""
        filename = info.filename
        entry = {
            "filename": filename,
            "compressed_size": info.compress_size,
            "uncompressed_size": info.file_size,
            "is_directory": info.is_dir(),
            "is_encrypted": info.needs_password() if hasattr(info, 'needs_password') else False,
            "is_suspicious": False,
            "risk_indicators": []
        }

        if info.is_dir():
            return entry

        # Reuse ZIP entry analysis logic
        return self._analyze_entry_common(entry, filename)

    def _analyze_7z_basic(self, path: Path, result: Dict):
        """7z analysis with optional py7zr library."""
        # Try full analysis with py7zr library first
        if PY7ZR_AVAILABLE:
            self._analyze_7z_full(path, result)
            return

        # Fallback to basic header analysis
        try:
            with open(path, "rb") as f:
                sig = f.read(6)
                if sig == b"7z\xbc\xaf'\x1c":
                    result["is_archive"] = True
                    result["message"] = "7z detected. Install 'py7zr' for detailed analysis."
                    result["backend"] = "basic"

                    # Simple encryption check
                    f.seek(0)
                    content = f.read(256)
                    # 7z encryption header patterns
                    if b'\x06\xf1\x07\x01' in content:
                        result["is_encrypted"] = True
                        self.findings.append("7z archive appears to be encrypted")
                        self.risk_score += 25
                else:
                    result["error"] = "Not a valid 7z file"

        except Exception as e:
            result["error"] = str(e)

    def _analyze_7z_full(self, path: Path, result: Dict):
        """Full 7z analysis using py7zr library."""
        try:
            # Check if encrypted first (py7zr needs password for encrypted files)
            try:
                with py7zr.SevenZipFile(str(path), mode='r') as szf:
                    result["backend"] = "py7zr"

                    # Check for encryption
                    if szf.needs_password():
                        result["is_encrypted"] = True
                        self.findings.append("7z archive is password protected")
                        self.risk_score += 25

                    # List contents
                    for name, info in szf.list():
                        file_info = self._analyze_7z_entry(name, info)
                        result["contents"].append(file_info)

                        if file_info.get("is_suspicious"):
                            result["suspicious_files"].append(file_info)

            except py7zr.exceptions.PasswordRequired:
                result["is_encrypted"] = True
                result["backend"] = "py7zr"
                self.findings.append("7z archive requires password")
                self.risk_score += 25

        except py7zr.exceptions.Bad7zFile:
            result["error"] = "Invalid or corrupted 7z file"
        except Exception as e:
            result["error"] = str(e)

    def _analyze_7z_entry(self, name: str, info) -> Dict:
        """Analyze a single 7z entry."""
        entry = {
            "filename": name,
            "compressed_size": getattr(info, 'compressed', 0),
            "uncompressed_size": getattr(info, 'uncompressed', 0),
            "is_directory": getattr(info, 'is_directory', False),
            "is_encrypted": getattr(info, 'encrypted', False),
            "is_suspicious": False,
            "risk_indicators": []
        }

        if entry["is_directory"]:
            return entry

        return self._analyze_entry_common(entry, name)

    def _analyze_entry_common(self, entry: Dict, filename: str) -> Dict:
        """Common entry analysis logic for all archive types."""
        path = Path(filename)
        ext = path.suffix.lower()
        entry["extension"] = ext

        # Check for dangerous extensions
        if ext in DANGEROUS_EXTENSIONS:
            entry["is_suspicious"] = True
            entry["risk_indicators"].append(f"Dangerous extension: {ext}")
            self.findings.append(f"Dangerous file type in archive: {filename}")
            self.risk_score += 30

        # Check for script files
        if ext in SCRIPT_EXTENSIONS:
            entry["is_suspicious"] = True
            entry["risk_indicators"].append(f"Script file: {ext}")
            self.risk_score += 20

        # Check for nested archives
        if ext in ARCHIVE_EXTENSIONS:
            entry["risk_indicators"].append("Nested archive")
            self.findings.append(f"Nested archive detected: {filename}")
            self.risk_score += 10

        # Check for double extensions
        double_ext_pattern = ARCHIVE_RISKS.get(
            "double_extension_pattern",
            r"\.(pdf|doc|xls|jpg|png)\.(exe|scr|bat|js|vbs|hta)$"
        )
        if re.search(double_ext_pattern, filename, re.IGNORECASE):
            entry["is_suspicious"] = True
            entry["risk_indicators"].append("Double extension detected")
            self.findings.append(f"Double extension attack: {filename}")
            self.risk_score += 35

        # Check for numeric filename
        numeric_pattern = ARCHIVE_RISKS.get(
            "numeric_filename_pattern",
            r"^\d+\.(exe|scr|bat|cmd|js|vbs)$"
        )
        if re.match(numeric_pattern, path.name, re.IGNORECASE):
            entry["is_suspicious"] = True
            entry["risk_indicators"].append("Numeric filename (possible auto-generated)")
            self.findings.append(f"Suspicious numeric filename: {filename}")
            self.risk_score += 15

        # Check for suspicious keywords
        suspicious_names = ARCHIVE_RISKS.get("suspicious_filenames", [])
        name_lower = path.stem.lower()
        for suspicious in suspicious_names:
            if suspicious.lower() in name_lower:
                if ext in DANGEROUS_EXTENSIONS:
                    entry["risk_indicators"].append(f"Suspicious name pattern: {suspicious}")
                    self.risk_score += 5

        # Check for very long filename
        if len(filename) > 100:
            entry["risk_indicators"].append("Very long filename (possible obfuscation)")
            self.risk_score += 5

        # Check for hidden file
        if path.name.startswith('.'):
            entry["risk_indicators"].append("Hidden file")

        # Check for control characters
        if re.search(r'[\x00-\x1f\x7f-\x9f]', filename):
            entry["risk_indicators"].append("Contains control characters")
            self.risk_score += 10

        return entry

    def _calculate_risk_level(self) -> str:
        """Calculate risk level based on score."""
        if self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 25:
            return "MEDIUM"
        elif self.risk_score > 0:
            return "LOW"
        return "NONE"

    def analyze_from_bytes(self, data: bytes, filename: str = "archive") -> Dict:
        """Analyze archive from bytes (for email attachments)."""
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            result = self.analyze(tmp_path)
            result["original_filename"] = filename
            return result
        finally:
            os.unlink(tmp_path)

    def _safe_extract_path(self, member_name: str, extract_dir: Path) -> Optional[Path]:
        """Compute a safe extraction path, rejecting path traversal."""
        clean_name = _sanitize_filename(member_name)
        target = extract_dir / clean_name
        try:
            target.resolve().relative_to(extract_dir.resolve())
        except ValueError:
            return None
        return target

    def _describe_extracted_file(self, file_path: Path, original_name: str) -> Dict:
        """Describe an extracted file with metadata."""
        hashes = _compute_file_hashes(file_path)
        return {
            "path": str(file_path),
            "original_name": original_name,
            "filename": file_path.name,
            "size": file_path.stat().st_size if file_path.exists() else 0,
            "extension": file_path.suffix.lower(),
            "file_type": _detect_file_type(file_path),
            "md5": hashes.get("md5", ""),
            "sha256": hashes.get("sha256", ""),
        }

    def extract(self, file_path: str, password: Optional[str] = None,
                extract_dir: Optional[str] = None) -> Dict:
        """Extract files from an archive."""
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}

        if extract_dir:
            out_dir = Path(extract_dir)
        else:
            out_dir = path.parent / f"{path.stem}_extracted"

        out_dir.mkdir(parents=True, exist_ok=True)

        result = {
            "archive_path": str(path),
            "extract_dir": str(out_dir),
            "password_used": password is not None,
            "extracted_files": [],
            "errors": [],
        }

        ext = path.suffix.lower()
        # Detect by magic bytes if extension is ambiguous
        file_type = _detect_file_type(path)

        if ext == ".zip" or file_type == "zip":
            self._extract_zip(path, out_dir, password, result)
        elif ext == ".rar" or file_type == "rar":
            self._extract_rar(path, out_dir, password, result)
        elif ext == ".7z" or file_type == "7z":
            self._extract_7z(path, out_dir, password, result)
        else:
            result["errors"].append(f"Unsupported archive format: {ext}")

        return result

    def _check_disk_space(self, extract_dir: Path) -> bool:
        """Check if there's enough free disk space."""
        try:
            usage = shutil.disk_usage(str(extract_dir))
            return usage.free >= MIN_DISK_FREE
        except Exception:
            return True  # Assume OK if we can't check

    def _extract_zip(self, path: Path, out_dir: Path, password: Optional[str],
                     result: Dict):
        """Extract files from a ZIP archive."""
        if not self._check_disk_space(out_dir):
            result["errors"].append("Insufficient disk space (< 100MB free)")
            return

        # Prepare password bytes with multiple encodings
        pwd_bytes_list = []
        if password:
            for encoding in ("utf-8", "gbk", "latin-1"):
                try:
                    pwd_bytes_list.append(password.encode(encoding))
                except (UnicodeEncodeError, UnicodeDecodeError):
                    continue

        # Try pyzipper first (handles AES), fallback to zipfile
        zip_modules = []
        if PYZIPPER_AVAILABLE:
            zip_modules.append(("pyzipper", pyzipper.AESZipFile))
        zip_modules.append(("zipfile", zipfile.ZipFile))

        extracted = False
        total_extracted_size = 0

        for mod_name, ZipClass in zip_modules:
            try:
                with ZipClass(str(path), 'r') as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue

                        # Symlink detection via external_attr
                        if (info.external_attr >> 16) & 0o170000 == 0o120000:
                            result["errors"].append(
                                f"Symlink rejected: {info.filename}")
                            continue

                        # Size limit check
                        if info.file_size > MAX_SINGLE_FILE:
                            result["errors"].append(
                                f"File too large ({info.file_size} bytes), "
                                f"skipped: {info.filename}")
                            continue

                        # Total extraction limit
                        if total_extracted_size + info.file_size > MAX_TOTAL_EXTRACT:
                            result["errors"].append(
                                "Total extraction size limit (2GB) reached, "
                                "stopping extraction")
                            return

                        # Compression ratio check
                        if (info.compress_size > 0 and
                                info.file_size / info.compress_size > MAX_COMPRESSION_RATIO):
                            result["errors"].append(
                                f"Suspicious compression ratio "
                                f"({info.file_size / info.compress_size:.0f}:1) "
                                f"for: {info.filename}")

                        target = self._safe_extract_path(info.filename, out_dir)
                        if target is None:
                            result["errors"].append(
                                f"Path traversal rejected: {info.filename}")
                            continue

                        # Try extraction with password candidates
                        data = None
                        if pwd_bytes_list:
                            for pwd_bytes in pwd_bytes_list:
                                try:
                                    data = zf.read(info.filename, pwd=pwd_bytes)
                                    break
                                except (RuntimeError, Exception):
                                    continue
                        if data is None:
                            try:
                                data = zf.read(info.filename)
                            except RuntimeError as e:
                                if "password" in str(e).lower() or "encrypt" in str(e).lower():
                                    result["errors"].append(
                                        f"Password required or incorrect for: "
                                        f"{info.filename}")
                                else:
                                    result["errors"].append(
                                        f"Read error for {info.filename}: {e}")
                                continue

                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
                        total_extracted_size += len(data)

                        file_desc = self._describe_extracted_file(
                            target, info.filename)
                        result["extracted_files"].append(file_desc)

                extracted = True
                break  # Success with this module, no need to try next

            except zipfile.BadZipFile:
                if mod_name == "zipfile":
                    result["errors"].append("Invalid or corrupted ZIP file")
                continue
            except RuntimeError as e:
                if "password" in str(e).lower() or "encrypt" in str(e).lower():
                    result["errors"].append(f"Password error: {e}")
                else:
                    result["errors"].append(f"ZIP extraction error: {e}")
                continue
            except Exception as e:
                if mod_name == "zipfile":
                    result["errors"].append(f"ZIP extraction error: {e}")
                continue

        if not extracted and not result["extracted_files"]:
            if not result["errors"]:
                result["errors"].append("Failed to extract ZIP archive")

    def _extract_rar(self, path: Path, out_dir: Path, password: Optional[str],
                     result: Dict):
        """Extract files from a RAR archive."""
        if not RARFILE_AVAILABLE:
            result["errors"].append(
                "RAR extraction requires 'rarfile' library. "
                "Install with: pip install rarfile")
            return

        if not self._check_disk_space(out_dir):
            result["errors"].append("Insufficient disk space (< 100MB free)")
            return

        total_extracted_size = 0

        try:
            rf = rarfile.RarFile(str(path))
            if password:
                rf.setpassword(password)

            for info in rf.infolist():
                if info.is_dir():
                    continue

                # Symlink detection
                if info.is_symlink():
                    result["errors"].append(
                        f"Symlink rejected: {info.filename}")
                    continue

                # Size limit check
                if info.file_size > MAX_SINGLE_FILE:
                    result["errors"].append(
                        f"File too large ({info.file_size} bytes), "
                        f"skipped: {info.filename}")
                    continue

                # Total extraction limit
                if total_extracted_size + info.file_size > MAX_TOTAL_EXTRACT:
                    result["errors"].append(
                        "Total extraction size limit (2GB) reached, "
                        "stopping extraction")
                    rf.close()
                    return

                # Compression ratio check
                if (info.compress_size > 0 and
                        info.file_size / info.compress_size > MAX_COMPRESSION_RATIO):
                    result["errors"].append(
                        f"Suspicious compression ratio "
                        f"({info.file_size / info.compress_size:.0f}:1) "
                        f"for: {info.filename}")

                target = self._safe_extract_path(info.filename, out_dir)
                if target is None:
                    result["errors"].append(
                        f"Path traversal rejected: {info.filename}")
                    continue

                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = rf.read(info.filename)
                    target.write_bytes(data)
                    total_extracted_size += len(data)

                    file_desc = self._describe_extracted_file(
                        target, info.filename)
                    result["extracted_files"].append(file_desc)

                except Exception as e:
                    result["errors"].append(
                        f"Failed to extract {info.filename}: {e}")
                    continue

            rf.close()

        except rarfile.BadRarFile:
            result["errors"].append("Invalid or corrupted RAR file")
        except rarfile.NeedFirstVolume:
            result["errors"].append("Multi-volume RAR: need first volume")
        except Exception as e:
            err_str = str(e).lower()
            if "password" in err_str or "encrypt" in err_str:
                result["errors"].append(f"Password error: {e}")
            else:
                result["errors"].append(f"RAR extraction error: {e}")

    def _extract_7z(self, path: Path, out_dir: Path, password: Optional[str],
                    result: Dict):
        """Extract files from a 7z archive."""
        if not PY7ZR_AVAILABLE:
            result["errors"].append(
                "7z extraction requires 'py7zr' library. "
                "Install with: pip install py7zr")
            return

        if not self._check_disk_space(out_dir):
            result["errors"].append("Insufficient disk space (< 100MB free)")
            return

        total_extracted_size = 0

        try:
            with py7zr.SevenZipFile(str(path), mode='r',
                                    password=password) as szf:
                # Read all files into memory
                all_files = szf.readall()
                if all_files is None:
                    result["errors"].append("No files found in 7z archive")
                    return

                for name, bio in all_files.items():
                    # Symlink detection
                    # py7zr file info check
                    file_infos = [f for f in szf.list() if f.filename == name]
                    if file_infos:
                        fi = file_infos[0]
                        if getattr(fi, 'is_symlink', False):
                            result["errors"].append(
                                f"Symlink rejected: {name}")
                            continue

                        # Size limit
                        file_size = getattr(fi, 'uncompressed', 0)
                        if file_size > MAX_SINGLE_FILE:
                            result["errors"].append(
                                f"File too large ({file_size} bytes), "
                                f"skipped: {name}")
                            continue

                        # Compression ratio
                        compressed = getattr(fi, 'compressed', 0)
                        if (compressed > 0 and file_size > 0 and
                                file_size / compressed > MAX_COMPRESSION_RATIO):
                            result["errors"].append(
                                f"Suspicious compression ratio "
                                f"({file_size / compressed:.0f}:1) "
                                f"for: {name}")

                    target = self._safe_extract_path(name, out_dir)
                    if target is None:
                        result["errors"].append(
                            f"Path traversal rejected: {name}")
                        continue

                    data = bio.read()

                    # Total extraction limit
                    if total_extracted_size + len(data) > MAX_TOTAL_EXTRACT:
                        result["errors"].append(
                            "Total extraction size limit (2GB) reached, "
                            "stopping extraction")
                        return

                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                    total_extracted_size += len(data)

                    file_desc = self._describe_extracted_file(target, name)
                    result["extracted_files"].append(file_desc)

        except py7zr.exceptions.PasswordRequired:
            result["errors"].append(
                "7z archive requires a password")
        except py7zr.exceptions.Bad7zFile:
            result["errors"].append("Invalid or corrupted 7z file")
        except Exception as e:
            err_str = str(e).lower()
            if "password" in err_str or "encrypt" in err_str:
                result["errors"].append(f"Password error: {e}")
            else:
                result["errors"].append(f"7z extraction error: {e}")

    def extract_from_bytes(self, data: bytes, filename: str = "archive",
                           password: Optional[str] = None,
                           extract_dir: Optional[str] = None) -> Dict:
        """Extract archive from bytes (for email attachments)."""
        import tempfile

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                    delete=False, suffix=Path(filename).suffix) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            result = self.extract(tmp_path, password=password,
                                  extract_dir=extract_dir)
            result["original_filename"] = filename
            return result
        except Exception as e:
            return {
                "original_filename": filename,
                "extracted_files": [],
                "errors": [f"Extraction failed: {e}"],
            }
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    print(f"Warning: failed to remove temp file: {tmp_path}",
                          file=sys.stderr)


def detect_password_in_text(text: str) -> List[Dict]:
    """Detect password patterns in text (email body)."""
    patterns = [
        # Chinese patterns
        (r'密码[是为:：]?\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "zh"),
        (r'解压[密码码][是为:：]?\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "zh"),
        (r'压缩密码[是为:：]?\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "zh"),
        (r'附件密码[是为:：]?\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "zh"),
        # English patterns
        (r'password[:\s]+["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "en"),
        (r'pwd[:\s]+["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "en"),
        (r'passwd[:\s]+["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "en"),
        (r'the password is[:\s]+["\']?([a-zA-Z0-9!@#$%^&*()_+=-]+)["\']?', "en"),
    ]

    results = []
    for pattern, lang in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            results.append({
                "pattern": pattern,
                "language": lang,
                "password": match.group(1),
                "context": text[max(0, match.start()-20):match.end()+20]
            })

    return results


def format_output(results: Dict, output_format: str = "text") -> str:
    """Format analysis results."""
    if output_format == "json":
        return json.dumps(results, indent=2, ensure_ascii=False)

    lines = []
    lines.append("=" * 60)
    lines.append("ARCHIVE ANALYSIS REPORT")
    lines.append("=" * 60)

    if "error" in results:
        lines.append(f"\n[ERROR] {results['error']}")
        return "\n".join(lines)

    lines.append(f"\n[FILE INFO]")
    lines.append(f"  Name: {results['file_name']}")
    lines.append(f"  Size: {results['file_size']} bytes")
    lines.append(f"  Type: {results.get('archive_type', 'Unknown')}")

    if results.get("md5"):
        lines.append(f"  MD5: {results['md5']}")
    if results.get("sha256"):
        lines.append(f"  SHA256: {results['sha256']}")

    lines.append(f"\n[SECURITY STATUS]")
    lines.append(f"  Is Archive: {results['is_archive']}")
    lines.append(f"  Is Encrypted: {results['is_encrypted']}")

    if results.get("contents"):
        lines.append(f"\n[CONTENTS] ({len(results['contents'])} items)")
        for item in results["contents"][:20]:
            if item.get("is_directory"):
                continue
            status = "[!]" if item.get("is_suspicious") else "   "
            lines.append(f"  {status} {item['filename']} ({item['uncompressed_size']} bytes)")
            for indicator in item.get("risk_indicators", []):
                lines.append(f"       -> {indicator}")

        if len(results["contents"]) > 20:
            lines.append(f"  ... and {len(results['contents']) - 20} more items")

    if results.get("suspicious_files"):
        lines.append(f"\n[SUSPICIOUS FILES] ({len(results['suspicious_files'])})")
        for item in results["suspicious_files"]:
            lines.append(f"  [!] {item['filename']}")
            for indicator in item.get("risk_indicators", []):
                lines.append(f"      - {indicator}")

    lines.append(f"\n[FINDINGS]")
    if results["findings"]:
        for finding in results["findings"]:
            lines.append(f"  [!] {finding}")
    else:
        lines.append("  No suspicious indicators found")

    lines.append(f"\n[RISK ASSESSMENT]")
    lines.append(f"  Score: {results['risk_score']}")
    lines.append(f"  Level: {results['risk_level']}")

    # Extraction results
    extraction = results.get("extraction")
    if extraction:
        lines.append(f"\n[EXTRACTION]")
        lines.append(f"  Extract Dir: {extraction.get('extract_dir', 'N/A')}")
        lines.append(f"  Password Used: {extraction.get('password_used', False)}")

        extracted_files = extraction.get("extracted_files", [])
        if extracted_files:
            lines.append(f"  Extracted Files ({len(extracted_files)}):")
            for ef in extracted_files:
                lines.append(
                    f"    - {ef['filename']} "
                    f"({ef['size']} bytes, type: {ef['file_type']})")
                lines.append(f"      SHA256: {ef['sha256']}")
                lines.append(f"      Path: {ef['path']}")
        else:
            lines.append("  No files extracted")

        ext_errors = extraction.get("errors", [])
        if ext_errors:
            lines.append(f"  Extraction Errors ({len(ext_errors)}):")
            for err in ext_errors:
                lines.append(f"    [!] {err}")

    lines.append("=" * 60)

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Analyze archives for malware delivery indicators"
    )
    parser.add_argument("file", nargs="?", help="Archive file to analyze")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                       help="Output format")
    parser.add_argument("--check-password", metavar="TEXT",
                       help="Check text for password patterns")
    parser.add_argument("--status", action="store_true",
                       help="Show backend/library status")
    parser.add_argument("--password", "-p", metavar="PWD",
                       help="Password for encrypted archive extraction")
    parser.add_argument("--extract-dir", "-d", metavar="DIR",
                       help="Directory to extract files into")
    args = parser.parse_args()

    # Show backend status
    if args.status:
        status = get_backend_status()
        if args.format == "json":
            print(json.dumps(status, indent=2))
        else:
            print("=" * 50)
            print("ARCHIVE ANALYZER BACKEND STATUS")
            print("=" * 50)
            print(f"zipfile:   [+] (stdlib)")
            print(f"pyzipper:  {'[+] installed' if PYZIPPER_AVAILABLE else '[-] not available'}")
            print(f"py7zr:     {'[+] installed' if PY7ZR_AVAILABLE else '[-] not available'}")
            print(f"rarfile:   {'[+] installed' if RARFILE_AVAILABLE else '[-] not available'}")
            print(f"\n{status['recommended_install']}")
        return

    if args.check_password:
        passwords = detect_password_in_text(args.check_password)
        if args.format == "json":
            print(json.dumps(passwords, indent=2, ensure_ascii=False))
        else:
            if passwords:
                print("Detected passwords:")
                for p in passwords:
                    print(f"  Password: {p['password']}")
                    print(f"  Context: ...{p['context']}...")
            else:
                print("No password patterns detected")
        return

    if not args.file:
        parser.print_help()
        return

    analyzer = ArchiveAnalyzer()
    results = analyzer.analyze(args.file)

    # If extraction is requested, also extract
    if args.password or args.extract_dir:
        extract_result = analyzer.extract(
            args.file,
            password=args.password,
            extract_dir=args.extract_dir,
        )
        results["extraction"] = extract_result

    print(format_output(results, args.format))


if __name__ == "__main__":
    main()
