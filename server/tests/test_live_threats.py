from datetime import datetime, timedelta, timezone

from app.services.live_threats import DeviceView, DomainView, detect_threats

NOW = datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc)


def _dev(**kw) -> DeviceView:
    base = dict(
        ip="10.0.0.5", mac="aa:bb:cc:00:00:01", hostname="host", is_gateway=False,
        is_self=False, online=True, first_seen=NOW - timedelta(hours=5),
        last_seen=NOW - timedelta(seconds=10),
    )
    base.update(kw)
    return DeviceView(**base)


def _kinds(threats) -> set[str]:
    return {t.kind for t in threats}


def test_arp_spoof_when_one_ip_has_two_macs():
    devs = [
        _dev(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa", is_gateway=True),
        _dev(ip="10.0.0.1", mac="de:ad:be:ef:00:01"),  # impostor on the gateway IP
    ]
    threats = detect_threats(devs, [], NOW)
    arp = [t for t in threats if t.kind == "arp_spoof"]
    assert len(arp) == 1
    assert arp[0].severity == "critical"  # it's the gateway → MITM
    assert arp[0].device_ip == "10.0.0.1"
    assert len(arp[0].evidence) == 2


def test_spoofed_ip_is_not_also_rogue_or_service():
    # two impostor MACs on one recently-joined, scanned IP → ONE arp_spoof only,
    # not two rogue_device + two risky_service duplicates
    devs = [
        _dev(ip="10.0.0.7", mac="de:ad:be:ef:00:01", first_seen=NOW - timedelta(minutes=1),
             scanned=True, open_ports=[23]),
        _dev(ip="10.0.0.7", mac="de:ad:be:ef:00:02", first_seen=NOW - timedelta(minutes=1),
             scanned=True, open_ports=[23]),
    ]
    threats = detect_threats(devs, [], NOW)
    assert [t.kind for t in threats] == ["arp_spoof"]


def test_no_arp_spoof_for_distinct_ips():
    devs = [
        _dev(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa"),
        _dev(ip="10.0.0.2", mac="bb:bb:bb:bb:bb:bb"),
    ]
    assert "arp_spoof" not in _kinds(detect_threats(devs, [], NOW))


def test_stale_rows_do_not_trigger_arp_spoof():
    old = NOW - timedelta(minutes=30)
    devs = [
        _dev(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:aa", last_seen=old),
        _dev(ip="10.0.0.1", mac="de:ad:be:ef:00:01", last_seen=old),
    ]
    assert "arp_spoof" not in _kinds(detect_threats(devs, [], NOW))


def test_rogue_device_when_recently_joined():
    devs = [_dev(first_seen=NOW - timedelta(minutes=2), hostname="unknown-phone")]
    threats = detect_threats(devs, [], NOW)
    rogue = [t for t in threats if t.kind == "rogue_device"]
    assert len(rogue) == 1
    assert "unknown-phone" in rogue[0].title


def test_self_and_gateway_are_never_rogue():
    devs = [
        _dev(is_self=True, first_seen=NOW - timedelta(minutes=1)),
        _dev(ip="10.0.0.1", mac="g", is_gateway=True, first_seen=NOW - timedelta(minutes=1)),
    ]
    assert "rogue_device" not in _kinds(detect_threats(devs, [], NOW))


def test_risky_service_from_open_ports_and_cves():
    devs = [_dev(scanned=True, open_ports=[22, 23, 445], vuln_count=2, worst_severity="high")]
    threats = detect_threats(devs, [], NOW)
    svc = [t for t in threats if t.kind == "risky_service"]
    assert len(svc) == 1
    assert svc[0].severity == "high"
    # cleartext telnet + SMB surfaced, ssh (22) is not flagged
    joined = " ".join(svc[0].evidence)
    assert "23" in joined and "445" in joined and "port 22" not in joined


def test_unscanned_device_is_not_a_risky_service():
    devs = [_dev(scanned=False, open_ports=[23])]
    assert "risky_service" not in _kinds(detect_threats(devs, [], NOW))


def test_malicious_domain_surfaced_high_over_trusted():
    domains = [
        DomainView(id="d1", domain="evil.test", band="High Risk", score=20, source_host="ws1", reasons=["punycode"]),
        DomainView(id="d2", domain="good.com", band="Trusted", score=100, source_host="ws1", reasons=[]),
    ]
    threats = detect_threats([], domains, NOW)
    mal = [t for t in threats if t.kind == "malicious_domain"]
    assert len(mal) == 1
    assert mal[0].severity == "high"
    assert "evil.test" in mal[0].title


def test_threats_sorted_by_severity():
    devs = [
        _dev(ip="10.0.0.1", mac="a", is_gateway=True),
        _dev(ip="10.0.0.1", mac="b"),  # critical arp
        _dev(ip="10.0.0.9", mac="c", first_seen=NOW - timedelta(minutes=1)),  # medium rogue
    ]
    ranks = [t.severity for t in detect_threats(devs, [], NOW)]
    assert ranks[0] == "critical"  # most severe first


# ── endpoint + demo injector integration ─────────────────────────────────────
def test_demo_attack_injects_detects_and_clears(client, seed_acme_org, user_headers):
    # start clean
    assert client.get("/api/live/network-threats", headers=user_headers).json() == []

    r = client.post("/api/live/demo-attack", headers=user_headers)
    assert r.status_code == 200, r.text
    kinds = {t["kind"] for t in r.json()}
    assert "arp_spoof" in kinds and "rogue_device" in kinds

    # same threats visible on the read endpoint
    live = client.get("/api/live/network-threats", headers=user_headers).json()
    assert {t["kind"] for t in live} & {"arp_spoof", "rogue_device"}

    cleared = client.delete("/api/live/demo-attack", headers=user_headers).json()
    assert cleared["cleared"] >= 3  # 2 spoof rows + 1 rogue (+ maybe a domain row)

    # demo threats gone after cleanup
    after = client.get("/api/live/network-threats", headers=user_headers).json()
    assert "arp_spoof" not in {t["kind"] for t in after}


def test_demo_attack_is_idempotent(client, seed_acme_org, user_headers):
    client.post("/api/live/demo-attack", headers=user_headers)
    # second call must not 500 on the (org, mac) unique key
    r = client.post("/api/live/demo-attack", headers=user_headers)
    assert r.status_code == 200, r.text
    client.delete("/api/live/demo-attack", headers=user_headers)
