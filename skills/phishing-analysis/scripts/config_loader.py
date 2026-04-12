#!/usr/bin/env python3
"""
Configuration Loader for Phishing Detection Scripts
Loads detection rules from config/detection_rules.toml
"""

import os
from pathlib import Path
from typing import Dict, List, Set, Any

# Try to import toml, fall back to built-in tomllib (Python 3.11+)
try:
    import tomllib
except ImportError:
    try:
        import toml as tomllib
    except ImportError:
        tomllib = None


def get_config_path() -> Path:
    """Get the path to the configuration file."""
    # Try relative to this script
    script_dir = Path(__file__).parent
    config_path = script_dir / "config" / "detection_rules.toml"

    if config_path.exists():
        return config_path

    # Try parent directory
    config_path = script_dir.parent / "config" / "detection_rules.toml"
    if config_path.exists():
        return config_path

    return script_dir / "config" / "detection_rules.toml"


def load_config() -> Dict[str, Any]:
    """Load configuration from TOML file."""
    config_path = get_config_path()

    if not config_path.exists():
        return get_default_config()

    if tomllib is None:
        # Fall back to default config if no TOML parser available
        return get_default_config()

    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return get_default_config()


def get_default_config() -> Dict[str, Any]:
    """Return default configuration if file not found."""
    return {
        "brands": {
            "google": ["google.com", "gmail.com"],
            "microsoft": ["microsoft.com", "outlook.com", "office.com"],
            "apple": ["apple.com", "icloud.com"],
            "amazon": ["amazon.com"],
            "paypal": ["paypal.com"],
        },
        "shorteners": {
            "domains": ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
        },
        "suspicious_tlds": {
            "free_tlds": ["tk", "ml", "ga", "cf", "gq"],
            "cheap_tlds": ["xyz", "top", "work", "click"]
        },
        "phishing_platforms": {
            "domains": ["knowbe4.com", "cofense.com", "gophish.com"]
        },
        "confusables": {
            "cyrillic": [["а", "a"], ["е", "e"], ["о", "o"], ["р", "p"], ["с", "c"]],
            "greek": [["α", "a"], ["ο", "o"]]
        }
    }


class Config:
    """Configuration singleton for phishing detection."""

    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._config = load_config()
        return cls._instance

    @property
    def brands(self) -> Dict[str, List[str]]:
        """Get brand to domains mapping."""
        return self._config.get("brands", {})

    @property
    def shorteners(self) -> Set[str]:
        """Get URL shortener domains."""
        return set(self._config.get("shorteners", {}).get("domains", []))

    @property
    def suspicious_tlds(self) -> Set[str]:
        """Get all suspicious TLDs."""
        tlds = self._config.get("suspicious_tlds", {})
        return set(tlds.get("free_tlds", []) + tlds.get("cheap_tlds", []))

    @property
    def phishing_platforms(self) -> Set[str]:
        """Get known phishing simulation platforms."""
        return set(self._config.get("phishing_platforms", {}).get("domains", []))

    @property
    def confusables(self) -> Dict[str, str]:
        """Get confusable character mapping."""
        mapping = {}
        conf = self._config.get("confusables", {})
        for script_chars in conf.values():
            if isinstance(script_chars, list):
                for pair in script_chars:
                    if len(pair) >= 2:
                        mapping[pair[0]] = pair[1]
        return mapping

    @property
    def urgency_keywords(self) -> List[str]:
        """Get urgency keywords in all languages."""
        se = self._config.get("social_engineering", {})
        return se.get("urgency_en", []) + se.get("urgency_zh", [])

    @property
    def bec_indicators(self) -> Dict[str, List[str]]:
        """Get BEC attack indicators."""
        return self._config.get("bec_indicators", {})

    @property
    def dangerous_attachments(self) -> Set[str]:
        """Get all dangerous attachment extensions."""
        att = self._config.get("dangerous_attachments", {})
        extensions = set()
        for ext_list in att.values():
            extensions.update(ext_list)
        return extensions

    @property
    def malware_delivery_patterns(self) -> Dict[str, List[str]]:
        """Get malware delivery detection patterns."""
        return self._config.get("malware_delivery", {})

    @property
    def archive_risks(self) -> Dict[str, Any]:
        """Get archive risk indicators."""
        return self._config.get("archive_risks", {})


# Global config instance
config = Config()


def get_brands() -> Dict[str, List[str]]:
    return config.brands

def get_shorteners() -> Set[str]:
    return config.shorteners

def get_suspicious_tlds() -> Set[str]:
    return config.suspicious_tlds

def get_phishing_platforms() -> Set[str]:
    return config.phishing_platforms

def get_confusables() -> Dict[str, str]:
    return config.confusables

def get_malware_delivery_patterns() -> Dict[str, List[str]]:
    return config.malware_delivery_patterns

def get_archive_risks() -> Dict[str, Any]:
    return config.archive_risks
