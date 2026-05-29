"""
Unit tests for NetRecon scanner modules.
Run with: pytest tests/
"""

import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.scanner import (
    normalize_target,
    validate_target,
    _ssl_warnings,
    ReconScanner,
    COMMON_PORTS,
    SECURITY_HEADERS,
)


# ── normalize_target ──────────────────────────────────────────────────────────

class TestNormalizeTarget:
    def test_bare_hostname(self):
        assert normalize_target("example.com") == "example.com"

    def test_strips_https_scheme(self):
        assert normalize_target("https://example.com") == "example.com"

    def test_strips_http_scheme(self):
        assert normalize_target("http://example.com") == "example.com"

    def test_strips_path(self):
        assert normalize_target("https://example.com/some/path") == "example.com"

    def test_strips_port(self):
        assert normalize_target("https://example.com:8443") == "example.com"

    def test_ip_address(self):
        assert normalize_target("8.8.8.8") == "8.8.8.8"

    def test_ip_with_scheme(self):
        assert normalize_target("https://8.8.8.8") == "8.8.8.8"

    def test_subdomain(self):
        assert normalize_target("sub.example.com") == "sub.example.com"


# ── validate_target ───────────────────────────────────────────────────────────

class TestValidateTarget:
    def test_valid_public_domain(self):
        assert validate_target("example.com") == "example.com"

    def test_valid_public_ip(self):
        assert validate_target("8.8.8.8") == "8.8.8.8"

    def test_rejects_localhost_string(self):
        assert validate_target("localhost") is None

    def test_rejects_loopback_ip(self):
        assert validate_target("127.0.0.1") is None

    def test_rejects_private_10_range(self):
        assert validate_target("10.0.0.1") is None

    def test_rejects_private_192_168_range(self):
        assert validate_target("192.168.1.1") is None

    def test_rejects_private_172_range(self):
        assert validate_target("172.16.0.1") is None

    def test_rejects_empty_string(self):
        assert validate_target("") is None

    def test_rejects_spaces_in_target(self):
        assert validate_target("exam ple.com") is None

    def test_accepts_https_scheme(self):
        assert validate_target("http://example.com") == "example.com"

    def test_rejects_localhost_with_scheme(self):
        assert validate_target("http://localhost") is None

    def test_rejects_127_range_boundary(self):
        assert validate_target("127.255.255.255") is None

    def test_rejects_172_31_range(self):
        assert validate_target("172.31.255.255") is None

    def test_accepts_172_32_as_public(self):
        # 172.32.x.x is outside the private 172.16/12 block
        assert validate_target("172.32.0.1") == "172.32.0.1"


# ── _ssl_warnings ─────────────────────────────────────────────────────────────

class TestSslWarnings:
    def test_expired_certificate(self):
        warnings = _ssl_warnings(-5, "TLSv1.3")
        assert any("EXPIRED" in w for w in warnings)

    def test_expiring_soon(self):
        warnings = _ssl_warnings(15, "TLSv1.3")
        assert any("15 days" in w for w in warnings)

    def test_deprecated_tls_1_0(self):
        warnings = _ssl_warnings(365, "TLSv1")
        assert any("TLSv1" in w for w in warnings)

    def test_deprecated_tls_1_1(self):
        warnings = _ssl_warnings(365, "TLSv1.1")
        assert any("TLSv1.1" in w for w in warnings)

    def test_modern_tls_no_warnings(self):
        assert _ssl_warnings(180, "TLSv1.3") == []

    def test_none_days_left_no_warnings(self):
        assert _ssl_warnings(None, "TLSv1.3") == []

    def test_zero_days_is_expiring_soon(self):
        warnings = _ssl_warnings(0, "TLSv1.3")
        assert any("0 days" in w for w in warnings)


# ── ReconScanner initialization ───────────────────────────────────────────────

class TestReconScannerInit:
    def test_normalizes_target_on_init(self):
        scanner = ReconScanner("https://example.com")
        assert scanner.target == "example.com"

    def test_stores_raw_target(self):
        scanner = ReconScanner("https://example.com/path")
        assert scanner.raw_target == "https://example.com/path"

    def test_bare_hostname(self):
        scanner = ReconScanner("example.com")
        assert scanner.target == "example.com"

    def test_timestamp_is_set(self):
        scanner = ReconScanner("example.com")
        assert scanner.timestamp is not None


# ── Port scanner ──────────────────────────────────────────────────────────────

class TestPortScanner:
    @patch("modules.scanner.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_returns_expected_keys(self, _mock):
        result = ReconScanner("example.com").scan_ports()
        for key in ("target", "open_ports", "total_scanned", "total_open", "risk_count"):
            assert key in result

    @patch("modules.scanner.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_total_scanned_matches_common_ports(self, _mock):
        result = ReconScanner("example.com").scan_ports()
        assert result["total_scanned"] == len(COMMON_PORTS)

    @patch("modules.scanner.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_no_open_ports_when_all_refused(self, _mock):
        result = ReconScanner("example.com").scan_ports()
        assert result["open_ports"] == []
        assert result["total_open"] == 0
        assert result["risk_count"] == 0

    @patch("modules.scanner.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_result_target_matches_scanner(self, _mock):
        result = ReconScanner("example.com").scan_ports()
        assert result["target"] == "example.com"


# ── HTTP header grading ───────────────────────────────────────────────────────

class TestHeaderGrading:
    """Verify the A–F grading thresholds used in analyze_headers."""

    def _grade(self, score: int) -> str:
        return (
            "A" if score >= 85 else
            "B" if score >= 70 else
            "C" if score >= 50 else
            "D" if score >= 30 else "F"
        )

    def test_grade_a_at_85(self):
        assert self._grade(85) == "A"

    def test_grade_a_at_100(self):
        assert self._grade(100) == "A"

    def test_grade_b_at_70(self):
        assert self._grade(70) == "B"

    def test_grade_b_at_84(self):
        assert self._grade(84) == "B"

    def test_grade_c_at_50(self):
        assert self._grade(50) == "C"

    def test_grade_d_at_30(self):
        assert self._grade(30) == "D"

    def test_grade_f_at_0(self):
        assert self._grade(0) == "F"

    def test_grade_f_at_29(self):
        assert self._grade(29) == "F"


# ── Constants sanity checks ───────────────────────────────────────────────────

class TestConstants:
    def test_common_ports_not_empty(self):
        assert len(COMMON_PORTS) > 0

    def test_all_ports_in_valid_range(self):
        for port in COMMON_PORTS:
            assert 1 <= port <= 65535, f"Port {port} out of range"

    def test_security_headers_not_empty(self):
        assert len(SECURITY_HEADERS) > 0

    def test_security_headers_are_strings(self):
        for h in SECURITY_HEADERS:
            assert isinstance(h, str)

    def test_known_ports_present(self):
        assert 80  in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert 22  in COMMON_PORTS
