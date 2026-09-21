# Drishti v0.1 — Product & Version Normalization | Phase 03
from __future__ import annotations

import re
from dataclasses import dataclass

UNKNOWN_PRODUCT = "UNKNOWN_PRODUCT"
UNKNOWN_VERSION = "UNKNOWN_VERSION"

# Conservative canonical dictionary: pattern -> (vendor, product)
CANONICAL_PRODUCTS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bgoogle\s+chrome\b", re.IGNORECASE), "google", "chrome"),
    (re.compile(r"\bchrome\b", re.IGNORECASE), "google", "chrome"),
    (re.compile(r"\bcom\.android\.chrome\b", re.IGNORECASE), "google", "chrome"),
    (re.compile(r"\bmicrosoft\s+edge\b", re.IGNORECASE), "microsoft", "edge"),
    (re.compile(r"\bmsedge\b", re.IGNORECASE), "microsoft", "edge"),
    (re.compile(r"\bmozilla\s+firefox\b", re.IGNORECASE), "mozilla", "firefox"),
    (re.compile(r"\bfirefox\b", re.IGNORECASE), "mozilla", "firefox"),
    (re.compile(r"\borg\.mozilla\.firefox\b", re.IGNORECASE), "mozilla", "firefox"),
    (re.compile(r"\bbrave\b", re.IGNORECASE), "brave", "brave"),
    (re.compile(r"\bcom\.brave\.browser\b", re.IGNORECASE), "brave", "brave"),
    (re.compile(r"\barc\b", re.IGNORECASE), "thebrowsercompany", "arc"),
    (re.compile(r"\b7-zip\b", re.IGNORECASE), "7-zip", "7-zip"),
    (re.compile(r"\bwinrar\b", re.IGNORECASE), "rarlab", "winrar"),
    (re.compile(r"\bnotepad\+\+\b", re.IGNORECASE), "notepad-plus-plus", "notepad++"),
    (re.compile(r"\bpython\b", re.IGNORECASE), "python", "python"),

    (re.compile(r"\bnode(?:\.js)?\b", re.IGNORECASE), "nodejs", "node.js"),
    (re.compile(r"\bgit\b", re.IGNORECASE), "git-scm", "git"),
    (re.compile(r"\bapache(?:\s+http\s+server)?\b", re.IGNORECASE), "apache", "http_server"),
    (re.compile(r"\bhttpd\b", re.IGNORECASE), "apache", "http_server"),
    (re.compile(r"\bnginx\b", re.IGNORECASE), "f5", "nginx"),
    (re.compile(r"\bopenssh\b", re.IGNORECASE), "openbsd", "openssh"),
    (re.compile(r"\bopenssl\b", re.IGNORECASE), "openssl", "openssl"),
    (re.compile(r"\bwireshark\b", re.IGNORECASE), "wireshark", "wireshark"),
    (re.compile(r"\bvlc\s+media\s+player\b", re.IGNORECASE), "videolan", "vlc_media_player"),
    (re.compile(r"\borg\.videolan\.vlc\b", re.IGNORECASE), "videolan", "vlc_media_player"),
    (re.compile(r"\bzoom\b", re.IGNORECASE), "zoom", "zoom"),
    (re.compile(r"\bslack\b", re.IGNORECASE), "slack", "slack"),
    (re.compile(r"\bdocker\s+desktop\b", re.IGNORECASE), "docker", "docker_desktop"),
]

VERSION_REGEX = re.compile(r"(?:v|ver|version)?\s*(\d+(?:\.\d+)+(?:[a-zA-Z0-9_\-\.]+)?)\b", re.IGNORECASE)


@dataclass
class NormalizedSoftwareIdentity:
    raw_name: str
    canonical_vendor: str | None
    canonical_product: str
    canonical_version: str | None
    is_known_product: bool
    is_known_version: bool
    cpe_prefix: str | None = None


class ProductNormalizer:
    """Conservative, deterministic normalizer for software and network services."""

    @staticmethod
    def clean_version_token(raw_version: str | None) -> str | None:
        """Extract a clean, structured version string from raw text."""
        if not raw_version or not raw_version.strip():
            return None

        cleaned = raw_version.strip()
        # Remove trailing build hashes or arch tags like (x64)
        cleaned = re.sub(r"\s*\([^)]*\)", "", cleaned).strip()
        match = VERSION_REGEX.search(cleaned)
        if match:
            return match.group(1).strip(" .-_")

        # If it's a simple number (e.g. "12")
        if re.match(r"^\d+$", cleaned):
            return cleaned

        return None

    @classmethod
    def normalize_endpoint_software(
        cls,
        software_name: str,
        declared_version: str | None = None,
        publisher: str | None = None,
    ) -> NormalizedSoftwareIdentity:
        """Normalize endpoint software name, version, and publisher without aggressive guessing."""
        if not software_name or not software_name.strip():
            return NormalizedSoftwareIdentity(
                raw_name="",
                canonical_vendor=None,
                canonical_product=UNKNOWN_PRODUCT,
                canonical_version=UNKNOWN_VERSION,
                is_known_product=False,
                is_known_version=False,
            )

        name = software_name.strip()
        vendor: str | None = None
        product: str = UNKNOWN_PRODUCT

        # 1. Check known canonical product dictionary
        for pattern, canon_vendor, canon_product in CANONICAL_PRODUCTS:
            if pattern.search(name):
                vendor = canon_vendor
                product = canon_product
                break

        # If not matched against known list, take publisher as vendor if present, product as name
        if product == UNKNOWN_PRODUCT:
            # Conservative: do not invent vendor/product
            clean_product = re.sub(r"\s*\(.*?\)", "", name).strip()
            # If it has alphabetic characters, keep as literal product token
            if re.search(r"[a-zA-Z]", clean_product):
                product = clean_product.lower()
                vendor = publisher.lower().strip() if publisher else None
            else:
                product = UNKNOWN_PRODUCT

        # 2. Extract or validate version
        version = cls.clean_version_token(declared_version)
        if not version:
            # Try extracting from software_name itself
            version = cls.clean_version_token(name)

        is_known_prod = product != UNKNOWN_PRODUCT
        is_known_ver = version is not None and version != UNKNOWN_VERSION

        cpe_prefix = f"cpe:2.3:a:{vendor or '*'}:{product}" if is_known_prod else None

        return NormalizedSoftwareIdentity(
            raw_name=software_name,
            canonical_vendor=vendor,
            canonical_product=product,
            canonical_version=version or UNKNOWN_VERSION,
            is_known_product=is_known_prod,
            is_known_version=is_known_ver,
            cpe_prefix=cpe_prefix,
        )

    @classmethod
    def normalize_network_service(
        cls,
        service_name: str,
        product: str | None = None,
        version: str | None = None,
        cpe: str | None = None,
    ) -> NormalizedSoftwareIdentity:
        """Normalize network scan service evidence from DeepScan/Nmap."""
        raw_target = product or service_name
        version_token = cls.clean_version_token(version)

        # Parse vendor and product from CPE if present
        cpe_vendor: str | None = None
        cpe_product: str | None = None
        if cpe and cpe.startswith("cpe:"):
            parts = cpe.split(":")
            if len(parts) >= 5:
                cpe_vendor = parts[3] if parts[3] != "*" else None
                cpe_product = parts[4] if parts[4] != "*" else None

        if cpe_product:
            return NormalizedSoftwareIdentity(
                raw_name=raw_target,
                canonical_vendor=cpe_vendor,
                canonical_product=cpe_product,
                canonical_version=version_token or UNKNOWN_VERSION,
                is_known_product=True,
                is_known_version=version_token is not None,
                cpe_prefix=f"cpe:2.3:a:{cpe_vendor or '*'}:{cpe_product}",
            )

        # Fallback to endpoint software normalization
        return cls.normalize_endpoint_software(raw_target, version)
