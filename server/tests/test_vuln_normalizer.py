# Drishti v0.1 — Product & Version Normalization Tests | Phase 03
import pytest
from app.services.vuln_intel.normalizer import (
    ProductNormalizer,
    UNKNOWN_PRODUCT,
    UNKNOWN_VERSION,
)


def test_normalize_known_software():
    # 7-Zip
    n1 = ProductNormalizer.normalize_endpoint_software("7-Zip 23.01 (x64 edition)", "23.01")
    assert n1.is_known_product is True
    assert n1.canonical_product == "7-zip"
    assert n1.canonical_vendor == "7-zip"
    assert n1.canonical_version == "23.01"
    assert n1.is_known_version is True
    assert n1.cpe_prefix == "cpe:2.3:a:7-zip:7-zip"

    # Google Chrome
    n2 = ProductNormalizer.normalize_endpoint_software("Google Chrome", "121.0.6167.85")
    assert n2.canonical_product == "chrome"
    assert n2.canonical_vendor == "google"
    assert n2.canonical_version == "121.0.6167.85"

    # Microsoft Edge
    n3 = ProductNormalizer.normalize_endpoint_software("Microsoft Edge", "120.0.2210.91")
    assert n3.canonical_product == "edge"
    assert n3.canonical_vendor == "microsoft"

    # Nginx
    n4 = ProductNormalizer.normalize_endpoint_software("nginx/1.24.0", "1.24.0")
    assert n4.canonical_product == "nginx"
    assert n4.canonical_vendor == "f5"
    assert n4.canonical_version == "1.24.0"


def test_clean_version_token():
    assert ProductNormalizer.clean_version_token("v1.2.3") == "1.2.3"
    assert ProductNormalizer.clean_version_token("Version 2.4.52 (Win64)") == "2.4.52"
    assert ProductNormalizer.clean_version_token("24.01") == "24.01"
    assert ProductNormalizer.clean_version_token("12") == "12"
    assert ProductNormalizer.clean_version_token("unknown") is None
    assert ProductNormalizer.clean_version_token("") is None
    assert ProductNormalizer.clean_version_token(None) is None


def test_normalize_unknown_product_and_version():
    # Pure whitespace / empty
    n_empty = ProductNormalizer.normalize_endpoint_software("")
    assert n_empty.canonical_product == UNKNOWN_PRODUCT
    assert n_empty.canonical_version == UNKNOWN_VERSION
    assert n_empty.is_known_product is False
    assert n_empty.is_known_version is False

    # Pure numeric without letters
    n_num = ProductNormalizer.normalize_endpoint_software("1234567")
    assert n_num.canonical_product == UNKNOWN_PRODUCT
    assert n_num.is_known_product is False

    # Unknown product with no version
    n_custom = ProductNormalizer.normalize_endpoint_software("MyCustomInternalTool", None)
    assert n_custom.canonical_product == "mycustominternaltool"
    assert n_custom.canonical_version == UNKNOWN_VERSION
    assert n_custom.is_known_version is False


def test_normalize_network_service_from_cpe():
    # Service with full CPE
    n_cpe = ProductNormalizer.normalize_network_service(
        service_name="http",
        product="Apache httpd",
        version="2.4.49",
        cpe="cpe:2.3:a:apache:http_server:2.4.49",
    )
    assert n_cpe.canonical_vendor == "apache"
    assert n_cpe.canonical_product == "http_server"
    assert n_cpe.canonical_version == "2.4.49"
    assert n_cpe.is_known_product is True
    assert n_cpe.is_known_version is True

    # Service without CPE (falls back to endpoint software normalization)
    n_no_cpe = ProductNormalizer.normalize_network_service(
        service_name="ssh",
        product="OpenSSH",
        version="8.9p1",
    )
    assert n_no_cpe.canonical_product == "openssh"
    assert n_no_cpe.canonical_version == "8.9p1"
