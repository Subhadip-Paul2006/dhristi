# Drishti v0.1 — Phase 05 Endpoint Remediation Tests
"""Tests verifying the bridge between Phase 03/04 endpoint findings and AI remediation.

Verifies:
1. Legacy AssetVulnerability lookup remains intact.
2. Endpoint CorrelatedFinding lookup resolves cleanly.
3. Unknown finding yields deterministic 404.
4. Strict organization isolation.
5. Normalized RemediationContext mapping.
6. Safety rule: NO_CONFIRMED_VULNERABILITY generates safe refusal (no patch commands).
7. Safety rule: Unknown version never guesses or uses floating "latest" (uses <patched-version>).
8. Fixed version from advisory is pinned accurately.
9. KEV enrichment clearly labels KEV without asserting the device was exploited.
10. All remediation formats (ansible, shell, cloud_cli) function properly.
11. Output safety guardrails remain fully active.
12. API endpoints GET /api/findings/{id} and PATCH /api/findings/{id}.
"""
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import select



from app.core.errors import NotFoundError
from app.models import Asset, AssetVulnerability, Vulnerability
from app.services.ai import service as ai_service
from app.services.ai.service import RemediationContext, resolve_remediation_context
from app.services.endpoint_telemetry import (
    clear_telemetry_store,
    get_endpoint_finding_by_id,
    record_telemetry,
    update_endpoint_finding_status,
)
from app.services.vuln_intel.models import CorrelatedFinding, FindingState
from app.schemas.endpoint import EndpointTelemetrySubmitRequest, SoftwareTelemetryItem


@pytest.fixture(autouse=True)
def clean_telemetry():
    clear_telemetry_store()
    yield
    clear_telemetry_store()


def test_legacy_asset_vulnerability_lookup(db_session, seed_acme_org):
    """Verify legacy database AssetVulnerability finding resolves to normalized RemediationContext."""
    finding = db_session.scalar(
        select(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .where(
            Asset.org_id == seed_acme_org.id,
            Asset.hostname == "db-prod-01",
            Vulnerability.cve_id == "CVE-2024-0005",
        )
    )
    assert finding is not None

    ctx = resolve_remediation_context(db_session, seed_acme_org.id, finding.id)
    assert isinstance(ctx, RemediationContext)
    assert ctx.finding_id == finding.id
    assert ctx.source == "network"
    assert ctx.hostname == "db-prod-01"
    assert ctx.cve_id == "CVE-2024-0005"
    assert ctx.cvss > 0.0


def test_endpoint_correlated_finding_lookup(db_session, seed_acme_org):
    """Verify Phase 03/04 endpoint CorrelatedFinding resolves cleanly without creating fake DB rows."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-agent-01",
        org_id=seed_acme_org.id,
        finding_state=FindingState.VULNERABLE,
        observed_product="openssl",
        observed_version="1.1.1t",
        cve_id="CVE-2023-0286",
        title="OpenSSL X.400 address type confusion vulnerability",
        summary="Type confusion in X.400 address processing.",
        cvss=7.5,
        severity="high",
        in_kev=False,
        fixed_version_text="1.1.1u",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
    )

    # Ingest telemetry for device
    payload = EndpointTelemetrySubmitRequest(
        agent_id="agent-01",
        device_id="dev-agent-01",
        timestamp=datetime.now(timezone.utc),
        hostname="workstation-alice",
        os_name="Ubuntu Linux 22.04 LTS",
        installed_software=[
            SoftwareTelemetryItem(name="openssl", version="1.1.1t")
        ],
    )
    record_telemetry(seed_acme_org.id, "agent-01", "dev-agent-01", payload)


    # Store correlated finding
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-agent-01")] = [c_finding]

    ctx = resolve_remediation_context(db_session, seed_acme_org.id, finding_id)
    assert isinstance(ctx, RemediationContext)
    assert ctx.finding_id == finding_id
    assert ctx.source == "endpoint"
    assert ctx.hostname == "workstation-alice"
    assert ctx.product == "openssl"
    assert ctx.version == "1.1.1t"
    assert ctx.cve_id == "CVE-2023-0286"
    assert ctx.fixed_version == "1.1.1u"
    assert ctx.severity == "high"

    # Verify no fake database row was created
    assert db_session.get(AssetVulnerability, finding_id) is None


def test_unknown_finding_returns_404(db_session, seed_acme_org):
    """Verify attempting to resolve a nonexistent finding raises NotFoundError."""
    fake_id = str(uuid.uuid4())
    with pytest.raises(NotFoundError, match="Finding not found"):
        resolve_remediation_context(db_session, seed_acme_org.id, fake_id)


def test_org_isolation_remediation(db_session, seed_acme_org):
    """Verify finding from Org A cannot be accessed or remediated by Org B."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-corp-orgA",
        org_id=seed_acme_org.id,
        finding_state=FindingState.VULNERABLE,
        observed_product="nginx",
        observed_version="1.18.0",
        cve_id="CVE-2021-23017",
        cvss=7.5,
        severity="high",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-corp-orgA")] = [c_finding]

    other_org_id = str(uuid.uuid4())
    with pytest.raises(NotFoundError, match="Finding not found"):
        resolve_remediation_context(db_session, other_org_id, finding_id)


def test_no_confirmed_vulnerability_safety(db_session, seed_acme_org):
    """Verify finding state NO_CONFIRMED_VULNERABILITY generates safe refusal without patch guidance."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-clean-01",
        org_id=seed_acme_org.id,
        finding_state=FindingState.NO_CONFIRMED_VULNERABILITY,
        observed_product="curl",
        observed_version="8.5.0",
        cve_id=None,
        title="Clean software component",
        cvss=0.0,
        severity="none",
        evidence_source="endpoint_software",
        evidence_type="NO_CONFIRMED_VULNERABILITY",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-clean-01")] = [c_finding]

    out = ai_service.remediate(db_session, seed_acme_org.id, finding_id, "ansible", False)
    assert out.refused is True
    assert "No confirmed vulnerability" in out.reason
    assert out.remediation_state == "REMEDIATION_UNAVAILABLE"
    assert "No defensive patch required" in out.script


def test_unknown_version_uses_patched_version_placeholder(db_session, seed_acme_org):
    """Verify unknown version never guesses and uses <patched-version> placeholder rather than floating latest."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-unknown-ver",
        org_id=seed_acme_org.id,
        finding_state=FindingState.POTENTIAL_MATCH,
        observed_product="legacy-agent",
        observed_version="UNKNOWN_VERSION",
        cve_id="CVE-2024-1111",
        title="Potential vulnerability with unverified version",
        cvss=6.0,
        severity="medium",
        fixed_version_text=None,
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-unknown-ver")] = [c_finding]

    out = ai_service.remediate(db_session, seed_acme_org.id, finding_id, "shell", False)
    assert out.refused is False
    assert "<patched-version>" in out.script
    assert "state: latest" not in out.script


def test_fixed_version_pinning(db_session, seed_acme_org):
    """Verify verified advisory fixed version is pinned in generated remediation."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-fixed-pkg",
        org_id=seed_acme_org.id,
        finding_state=FindingState.VULNERABLE,
        observed_product="redis",
        observed_version="6.0.9",
        cve_id="CVE-2021-32761",
        title="Integer overflow in redis",
        cvss=8.8,
        severity="high",
        fixed_version_text="6.2.6",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-fixed-pkg")] = [c_finding]

    out = ai_service.remediate(db_session, seed_acme_org.id, finding_id, "ansible", False)
    assert out.refused is False
    assert "6.2.6" in out.script


def test_kev_enrichment_not_exploited(db_session, seed_acme_org):
    """Verify CISA KEV listing is prominently noted without falsely asserting local exploitation."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-kev-01",
        org_id=seed_acme_org.id,
        finding_state=FindingState.KNOWN_EXPLOITED,
        observed_product="log4j",
        observed_version="2.14.1",
        cve_id="CVE-2021-44228",
        title="Log4Shell Remote Code Execution",
        cvss=10.0,
        severity="critical",
        in_kev=True,
        fixed_version_text="2.17.1",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-kev-01")] = [c_finding]

    out = ai_service.remediate(db_session, seed_acme_org.id, finding_id, "shell", False)
    assert out.refused is False
    assert out.in_kev is True
    assert "CISA KEV" in out.script
    # Must NOT claim this specific device was exploited
    assert "device was exploited" not in out.script.lower()
    assert "compromised device" not in out.script.lower()


def test_all_remediation_formats_supported(db_session, seed_acme_org):
    """Verify ansible, shell, and cloud_cli all generate valid defensive playbooks for endpoint findings."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-multi-format",
        org_id=seed_acme_org.id,
        finding_state=FindingState.VULNERABLE,
        observed_product="nginx",
        observed_version="1.18.0",
        cve_id="CVE-2021-23017",
        cvss=7.7,
        severity="high",
        fixed_version_text="1.20.1",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-multi-format")] = [c_finding]

    for kind in ("ansible", "shell", "cloud_cli"):
        out = ai_service.remediate(db_session, seed_acme_org.id, finding_id, kind, True)
        assert out.refused is False
        assert out.kind == kind
        assert out.script
        assert out.remediation_state == "REMEDIATION_AVAILABLE"


def test_api_findings_get_and_patch_endpoint_finding(client, db_session, seed_acme_org, user_headers):
    """Verify GET /api/findings/{id} and PATCH /api/findings/{id} operate on endpoint findings."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="endpoint-box-1",
        org_id=seed_acme_org.id,
        finding_state=FindingState.VULNERABLE,
        observed_product="python",
        observed_version="3.9.1",
        cve_id="CVE-2021-3177",
        title="Buffer overflow in PyOS_vsnprintf",
        cvss=9.8,
        severity="critical",
        in_kev=False,
        fixed_version_text="3.9.2",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "endpoint-box-1")] = [c_finding]

    # 1. GET /api/findings/{id}
    resp = client.get(f"/api/findings/{finding_id}", headers=user_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["id"] == finding_id
    assert data["cve_id"] == "CVE-2021-3177"
    assert data["source"] == "endpoint"
    assert data["observed_product"] == "python"
    assert data["observed_version"] == "3.9.1"
    assert data["fixed_version"] == "3.9.2"
    assert data["status"] == "open"

    # 2. PATCH /api/findings/{id}
    patch_resp = client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "remediating"},
        headers=user_headers,
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["status"] == "remediating"

    # Verify status reflects in subsequent lookup
    get_again = client.get(f"/api/findings/{finding_id}", headers=user_headers)
    assert get_again.json()["status"] == "remediating"


def test_missing_fields_handling_and_no_fabrication(db_session, seed_acme_org):
    """Verify missing fields in CorrelatedFinding do not fabricate values or crash."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="dev-sparse-01",
        org_id=seed_acme_org.id,
        finding_state=FindingState.VULNERABLE,
        observed_product="custom-service",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version=None,
        cve_id=None,
        title=None,
        summary=None,
        cvss=0.0,
        severity="medium",
        fixed_version_text=None,
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS
    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "dev-sparse-01")] = [c_finding]

    ctx = resolve_remediation_context(db_session, seed_acme_org.id, finding_id)
    assert ctx.cve_id is None
    assert ctx.version is None
    assert ctx.fixed_version is None
    assert ctx.product == "custom-service"

    # Remediate should use <patched-version> and never invent a version
    out = ai_service.remediate(db_session, seed_acme_org.id, finding_id, "shell", False)
    assert out.refused is False
    assert "<patched-version>" in out.script
    assert "latest" not in out.script


def test_offensive_payload_guardrail(db_session, seed_acme_org):
    """Verify _guard_offensive identifies offensive content and allows defensive content."""
    from app.services.ai.service import _guard_offensive

    # Offensive markers must be detected (returns True = offensive)
    assert _guard_offensive("deploy a reverse shell to target") is True
    assert _guard_offensive("establish persistence on compromised box") is True
    assert _guard_offensive("how to exploit the remote daemon") is True
    assert _guard_offensive("exfiltrate credentials to c2") is True
    assert _guard_offensive("weaponize the buffer overflow") is True

    # Defensive scripts must pass (returns False = safe/clean)
    assert _guard_offensive("apt-get update && apt-get install --only-upgrade openssl=1.1.1u") is False
    assert _guard_offensive("yum update -y nginx") is False
    assert _guard_offensive("systemctl restart apache2") is False

