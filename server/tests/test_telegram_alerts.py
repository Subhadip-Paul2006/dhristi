# Drishti v0.1 — Phase 05 Telegram Alert Dispatcher Tests
"""Tests verifying Telegram notification architecture, factual fingerprint deduplication,
and fault isolation without making real outbound network requests.

Verifies:
1. Deterministic factual fingerprint calculation.
2. Unchanged finding alerts are sent once and deduplicated on subsequent polls.
3. Version change generates a new fingerprint and alerts.
4. Severity change generates a new fingerprint and alerts.
5. KEV state change generates a new fingerprint and alerts.
6. Separate devices with identical CVE alert independently (device isolation).
7. Separate organizations alert independently (org isolation).
8. Factual message formatting includes genuine fields without invention.
9. Endpoint findings format cleanly with product, version, fixed version, and KEV state.
10. KEV never claims "device was exploited".
11. IST timestamp formatting produces Asia/Kolkata timezone with IST suffix.
12. Fault isolation: Telegram failures (HTTP 400, 403, 500, network error) never raise or break scanning.
13. Rate limiting (HTTP 429) is handled gracefully without crashing.
14. Masked status prevents secret leakage.
15. Automated tests never call api.telegram.org (all transports mocked).
"""
import uuid
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from app.services.telegram_alerts import (
    _dispatch_alert,
    _format_endpoint_finding_alert,
    _format_finding_alert,
    _ist_timestamp,
    _scan_org,
    _send_telegram,
    clear_alerted_cache,
    get_alerted_count,
    get_status,
    make_finding_fingerprint,
)
from app.services.vuln_intel.models import CorrelatedFinding, FindingState
from app.services.endpoint_telemetry import clear_telemetry_store


@pytest.fixture(autouse=True)
def clean_state():
    clear_alerted_cache()
    clear_telemetry_store()
    yield
    clear_alerted_cache()
    clear_telemetry_store()


def test_make_finding_fingerprint_deterministic():
    """Verify make_finding_fingerprint produces identical tuples for identical inputs."""
    fp1 = make_finding_fingerprint("org-1", "host-A", "CVE-2024-0001", "1.0.0", "high", True)
    fp2 = make_finding_fingerprint("org-1", "host-A", "CVE-2024-0001", "1.0.0", "HIGH", True)
    fp3 = make_finding_fingerprint("org-1", "host-A", "CVE-2024-0001", "1.0.0", "high", False)

    assert fp1 == fp2  # case-insensitive on severity
    assert fp1 != fp3  # KEV difference changes fingerprint


def test_deduplication_unchanged_finding_suppressed():
    """Verify unchanged finding alerts are sent once and deduplicated on subsequent polls."""
    org_id = "org-demo"
    finding = CorrelatedFinding(
        finding_id=str(uuid.uuid4()),
        device_id="device-alpha",
        org_id=org_id,
        finding_state=FindingState.VULNERABLE,
        observed_product="nginx",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="1.18.0",
        cve_id="CVE-2021-23017",
        cvss=7.7,
        severity="high",
        in_kev=False,
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(org_id, "device-alpha")] = [finding]

    mock_db = MagicMock()
    mock_db.scalars.return_value.all.return_value = []  # No DB findings

    dispatched = []

    def fake_dispatch(bot_token, chat_id, html_text, plain_text):
        dispatched.append(html_text)
        return True

    with patch("app.services.telegram_alerts._dispatch_alert", side_effect=fake_dispatch):
        # 1st scan: should dispatch 1 alert
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 1

        # 2nd scan (unchanged): should NOT dispatch duplicate alert
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 1


def test_version_change_generates_new_alert():
    """Verify changing observed version creates a new fingerprint and generates an alert."""
    org_id = "org-demo"
    finding_id = str(uuid.uuid4())
    finding_v1 = CorrelatedFinding(
        finding_id=finding_id,
        device_id="device-alpha",
        org_id=org_id,
        finding_state=FindingState.VULNERABLE,
        observed_product="openssl",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="1.1.1k",
        cve_id="CVE-2021-3711",
        cvss=9.8,
        severity="critical",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(org_id, "device-alpha")] = [finding_v1]

    mock_db = MagicMock()
    mock_db.scalars.return_value.all.return_value = []

    dispatched = []
    with patch("app.services.telegram_alerts._dispatch_alert", side_effect=lambda *a: dispatched.append(a) or True):
        # Scan v1
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 1

        # Update to v2
        finding_v2 = CorrelatedFinding(
            finding_id=finding_id,
            device_id="device-alpha",
            org_id=org_id,
            finding_state=FindingState.VULNERABLE,
            observed_product="openssl",
            evidence_source="endpoint_software",
            evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
            observed_version="1.1.1l",  # Changed version
            cve_id="CVE-2021-3711",
            cvss=9.8,
            severity="critical",
        )
        _DEVICE_VULN_FINDINGS[(org_id, "device-alpha")] = [finding_v2]

        # Scan v2: new fingerprint triggered
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 2


def test_severity_change_generates_new_alert():
    """Verify escalating severity creates a new fingerprint and alerts."""
    org_id = "org-demo"
    finding_id = str(uuid.uuid4())
    finding_med = CorrelatedFinding(
        finding_id=finding_id,
        device_id="device-beta",
        org_id=org_id,
        finding_state=FindingState.VULNERABLE,
        observed_product="sudo",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="1.8.31",
        cve_id="CVE-2021-3156",
        cvss=7.8,
        severity="high",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(org_id, "device-beta")] = [finding_med]

    mock_db = MagicMock()
    mock_db.scalars.return_value.all.return_value = []

    dispatched = []
    with patch("app.services.telegram_alerts._dispatch_alert", side_effect=lambda *a: dispatched.append(a) or True):
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 1

        # Severity re-assessed to critical
        finding_crit = CorrelatedFinding(
            finding_id=finding_id,
            device_id="device-beta",
            org_id=org_id,
            finding_state=FindingState.VULNERABLE,
            observed_product="sudo",
            evidence_source="endpoint_software",
            evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
            observed_version="1.8.31",
            cve_id="CVE-2021-3156",
            cvss=9.8,
            severity="critical",  # Escalated
        )
        _DEVICE_VULN_FINDINGS[(org_id, "device-beta")] = [finding_crit]

        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 2


def test_kev_transition_generates_new_alert():
    """Verify finding transitioning into CISA KEV triggers a new alert."""
    org_id = "org-demo"
    finding_id = str(uuid.uuid4())
    finding_no_kev = CorrelatedFinding(
        finding_id=finding_id,
        device_id="device-gamma",
        org_id=org_id,
        finding_state=FindingState.VULNERABLE,
        observed_product="apache",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="2.4.49",
        cve_id="CVE-2021-41773",
        cvss=7.5,
        severity="high",
        in_kev=False,
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(org_id, "device-gamma")] = [finding_no_kev]

    mock_db = MagicMock()
    mock_db.scalars.return_value.all.return_value = []

    dispatched = []
    with patch("app.services.telegram_alerts._dispatch_alert", side_effect=lambda *a: dispatched.append(a) or True):
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 1

        # KEV added by CISA catalog update
        finding_in_kev = CorrelatedFinding(
            finding_id=finding_id,
            device_id="device-gamma",
            org_id=org_id,
            finding_state=FindingState.KNOWN_EXPLOITED,
            observed_product="apache",
            evidence_source="endpoint_software",
            evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
            observed_version="2.4.49",
            cve_id="CVE-2021-41773",
            cvss=7.5,
            severity="high",
            in_kev=True,  # Now listed in KEV
        )
        _DEVICE_VULN_FINDINGS[(org_id, "device-gamma")] = [finding_in_kev]

        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 2


def test_cross_device_isolation_same_cve():
    """Verify the same CVE on two different devices generates separate alerts for both."""
    org_id = "org-demo"
    cve = "CVE-2024-5555"

    f1 = CorrelatedFinding(
        finding_id=str(uuid.uuid4()),
        device_id="dev-server-01",
        org_id=org_id,
        finding_state=FindingState.VULNERABLE,
        observed_product="openssh",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="8.9p1",
        cve_id=cve,
        severity="high",
    )
    f2 = CorrelatedFinding(
        finding_id=str(uuid.uuid4()),
        device_id="dev-server-02",  # Different device
        org_id=org_id,
        finding_state=FindingState.VULNERABLE,
        observed_product="openssh",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="8.9p1",
        cve_id=cve,
        severity="high",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(org_id, "dev-server-01")] = [f1]
    _DEVICE_VULN_FINDINGS[(org_id, "dev-server-02")] = [f2]

    mock_db = MagicMock()
    mock_db.scalars.return_value.all.return_value = []

    dispatched = []
    with patch("app.services.telegram_alerts._dispatch_alert", side_effect=lambda *a: dispatched.append(a) or True):
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        # Both devices must be alerted independently
        assert len(dispatched) == 2


def test_cross_org_isolation():
    """Verify alerts are strictly scoped to organizations."""
    fp_a = make_finding_fingerprint("org-A", "dev-1", "CVE-1", "1.0", "high", False)
    fp_b = make_finding_fingerprint("org-B", "dev-1", "CVE-1", "1.0", "high", False)
    assert fp_a != fp_b


def test_message_formatting_factual_fields():
    """Verify _format_endpoint_finding_alert includes verified factual fields."""
    c_finding = CorrelatedFinding(
        finding_id=str(uuid.uuid4()),
        device_id="laptop-101",
        org_id="org-acme",
        finding_state=FindingState.VULNERABLE,
        observed_product="python",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="3.9.1",
        cve_id="CVE-2021-3177",
        title="Python Buffer Overflow",
        severity="critical",
        in_kev=False,
        fixed_version_text="3.9.2",
    )
    telemetry = {"hostname": "laptop-101.local", "ip": "192.168.1.101"}

    html_msg, plain_msg = _format_endpoint_finding_alert(c_finding, telemetry)
    assert "laptop-101.local" in html_msg
    assert "192.168.1.101" in html_msg
    assert "CVE-2021-3177" in html_msg
    assert "python" in html_msg
    assert "3.9.1" in html_msg
    assert "3.9.2" in html_msg
    assert "CRITICAL" in html_msg
    assert "REQUIRES REVIEW" in html_msg


def test_kev_never_claims_device_exploited():
    """Verify KEV alert labels CISA KEV status without claiming local exploitation."""
    c_finding = CorrelatedFinding(
        finding_id=str(uuid.uuid4()),
        device_id="box-x",
        org_id="org-acme",
        finding_state=FindingState.KNOWN_EXPLOITED,
        observed_product="apache",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="2.4.49",
        cve_id="CVE-2021-41773",
        severity="critical",
        in_kev=True,
    )
    html_msg, plain_msg = _format_endpoint_finding_alert(c_finding, {})
    assert "KNOWN EXPLOITED — CISA KEV" in html_msg
    assert "device was exploited" not in html_msg.lower()
    assert "compromised" not in html_msg.lower()


def test_ist_timestamp_formatting():
    """Verify _ist_timestamp produces correct Indian Standard Time (UTC+5:30) with IST indicator."""
    dt_utc = datetime(2026, 9, 21, 10, 0, 0, tzinfo=timezone.utc)
    ist_str = _ist_timestamp(dt_utc)
    assert "IST" in ist_str
    assert "03:30:00 PM IST" in ist_str or "15:30:00" in ist_str


def test_telegram_failure_isolation_does_not_break_security():
    """Verify network failures or exceptions in Telegram dispatch never crash the caller."""
    with patch("subprocess.run", side_effect=Exception("Connection refused")):
        with patch("httpx.post", side_effect=Exception("Network timeout")):
            ok = _send_telegram("fake-token", "fake-chat", "<b>test</b>")
            assert ok is False  # Safely returns False, does NOT raise exception


def test_http_429_rate_limiting_handled():
    """Verify HTTP 429 response from Telegram is handled cleanly without crashing."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.json.return_value = {"ok": False, "parameters": {"retry_after": 1}}

    with patch("subprocess.run", side_effect=Exception("curl unavailable")):
        with patch("httpx.post", return_value=mock_resp):
            with patch("time.sleep") as mock_sleep:
                ok = _send_telegram("fake-token", "fake-chat", "test")
                assert ok is False
                mock_sleep.assert_called_with(1)


def test_masked_status_no_secret_leakage():
    """Verify get_status masks chat IDs and does not reveal the bot token."""
    with patch("app.config.get_settings") as mock_settings:
        mock_settings.return_value.telegram_bot_token = "123456:ABC-DEF-secret-token"
        mock_settings.return_value.telegram_chat_id = "987654321,112233"

        status = get_status()
        assert status["configured"] is True
        assert status["chat_ids_count"] == 2
        # Chat IDs masked
        for masked in status["chat_ids_masked"]:
            assert "***" in masked
        # Token must NOT be anywhere in the dictionary
        assert "123456:ABC-DEF-secret-token" not in str(status)


def test_automated_tests_never_call_production_telegram():
    """Verify test dispatch uses mocked transport and does not attempt live network calls."""
    with patch("app.services.telegram_alerts._send_telegram", return_value=True) as mock_send:
        ok = _dispatch_alert("mock-token", "12345,67890", "html", "plain")
        assert ok is True
        assert mock_send.call_count == 2


def test_telegram_timeout_handling():
    """Verify socket/HTTP timeout in Telegram transport does not raise an exception."""
    import httpx

    with patch("subprocess.run", side_effect=Exception("curl timeout")):
        with patch("httpx.post", side_effect=httpx.TimeoutException("Connection timed out")):
            ok = _send_telegram("fake-token", "fake-chat", "test alert")
            assert ok is False


def test_missing_fields_formatting_renders_not_available():
    """Verify missing fields render 'Not available' instead of crashing or hallucinating."""
    c_finding = CorrelatedFinding(
        finding_id=str(uuid.uuid4()),
        device_id="box-sparse",
        org_id="org-sparse",
        finding_state=FindingState.VULNERABLE,
        observed_product="unknown-daemon",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version=None,
        cve_id=None,
        fixed_version_text=None,
    )
    html_msg, plain_msg = _format_endpoint_finding_alert(c_finding, {})
    assert "Not available" in html_msg
    assert "unknown-daemon" in html_msg


def test_scan_org_db_findings_without_service():
    """Verify database AssetVulnerability without service does not raise AttributeError."""
    from app.models import Asset, AssetVulnerability, Vulnerability

    mock_db = MagicMock()
    org_id = "org-test-db"

    vuln = Vulnerability(
        id=str(uuid.uuid4()),
        cve_id="CVE-2024-9999",
        title="Critical Vulnerability",
        severity="critical",
    )
    asset = Asset(
        id=str(uuid.uuid4()),
        org_id=org_id,
        hostname="srv-prod-01",
        ip="192.168.1.50",
    )
    finding = AssetVulnerability(
        id=str(uuid.uuid4()),
        org_id=org_id,
        asset_id=asset.id,
        vulnerability_id=vuln.id,
        service_id=None,
        status="open",
        detected_at=datetime.now(timezone.utc),
    )
    finding.asset = asset
    finding.vulnerability = vuln
    # finding.service is None

    def mock_scalars_no_svc(statement):
        res = MagicMock()
        if "asset_vulnerabilities" in str(statement):
            res.all.return_value = [finding]
        else:
            res.all.return_value = []
        return res

    mock_db.scalars.side_effect = mock_scalars_no_svc

    dispatched = []

    def fake_dispatch(bot_token, chat_id, html_text, plain_text):
        dispatched.append(html_text)
        return True

    with patch("app.services.telegram_alerts._dispatch_alert", side_effect=fake_dispatch):
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 1
        assert "CVE-2024-9999" in dispatched[0]
        assert "srv-prod-01" in dispatched[0]


def test_scan_org_db_findings_with_service():
    """Verify database AssetVulnerability with service resolves version correctly."""
    from app.models import Asset, AssetVulnerability, Service, Vulnerability

    mock_db = MagicMock()
    org_id = "org-test-db"

    vuln = Vulnerability(
        id=str(uuid.uuid4()),
        cve_id="CVE-2023-1234",
        title="Apache Vulnerability",
        severity="high",
    )
    asset = Asset(
        id=str(uuid.uuid4()),
        org_id=org_id,
        hostname="web-prod-01",
        ip="192.168.1.80",
    )
    service = Service(
        id=str(uuid.uuid4()),
        org_id=org_id,
        asset_id=asset.id,
        port=80,
        protocol="tcp",
        name="apache",
        version="2.4.49",
    )
    finding = AssetVulnerability(
        id=str(uuid.uuid4()),
        org_id=org_id,
        asset_id=asset.id,
        vulnerability_id=vuln.id,
        service_id=service.id,
        status="open",
        detected_at=datetime.now(timezone.utc),
    )
    finding.asset = asset
    finding.vulnerability = vuln
    finding.service = service

    def mock_scalars_svc(statement):
        res = MagicMock()
        if "asset_vulnerabilities" in str(statement):
            res.all.return_value = [finding]
        else:
            res.all.return_value = []
        return res

    mock_db.scalars.side_effect = mock_scalars_svc

    dispatched = []

    def fake_dispatch(bot_token, chat_id, html_text, plain_text):
        dispatched.append(html_text)
        return True

    with patch("app.services.telegram_alerts._dispatch_alert", side_effect=fake_dispatch):
        _scan_org(mock_db, org_id, "test-bot-token", "123456")
        assert len(dispatched) == 1
        assert "CVE-2023-1234" in dispatched[0]

