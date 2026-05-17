import pytest
from patch_checker.cve_db import load_cves, get_cve

EXPECTED_CVES = [
    "CVE-2026-31431",
    "CVE-2026-43284",
    "CVE-2026-43500",
    "CVE-2026-46300",
    "CVE-2026-46333",
]


def test_all_cves_present():
    cves = load_cves()
    for cve_id in EXPECTED_CVES:
        assert cve_id in cves, f"{cve_id} not found in CVE database"


def test_reserved_flag():
    cves = load_cves()
    assert cves["CVE-2026-46300"].reserved is True
    for cve_id in EXPECTED_CVES:
        if cve_id != "CVE-2026-46300":
            assert cves[cve_id].reserved is False


def test_cve_metadata_fields():
    cves = load_cves()
    cve = cves["CVE-2026-31431"]
    assert cve.nickname == "CopyFail"
    assert cve.cvss == 7.8
    assert cve.mitigation_type == "module"
    assert "algif_aead" in cve.modules
    assert len(cve.affected_ranges) > 0
    assert len(cve.fixed_versions) > 0


def test_get_cve_known():
    cve = get_cve("CVE-2026-31431")
    assert cve.cve_id == "CVE-2026-31431"


def test_get_cve_unknown():
    with pytest.raises(KeyError):
        get_cve("CVE-9999-99999")


def test_sysctl_cve():
    cves = load_cves()
    cve = cves["CVE-2026-46333"]
    assert cve.mitigation_type == "sysctl"
    assert cve.sysctl_key == "kernel.yama.ptrace_scope"
    assert cve.sysctl_value == 3


def test_dirtyfrag_modules():
    cves = load_cves()
    assert "esp4" in cves["CVE-2026-43284"].modules
    assert "esp6" in cves["CVE-2026-43284"].modules
    assert "rxrpc" in cves["CVE-2026-43500"].modules


def test_fragnesia_modules():
    cves = load_cves()
    fragnesia = cves["CVE-2026-46300"]
    assert "esp4" in fragnesia.modules
    assert "esp6" in fragnesia.modules
    assert "rxrpc" in fragnesia.modules


def test_version_comparison_reliable_for():
    cves = load_cves()
    assert cves["CVE-2026-31431"].version_comparison_reliable_for == [
        "generic", "fedora", "debian", "opensuse-tumbleweed"
    ]
    assert cves["CVE-2026-46300"].version_comparison_reliable_for == []
    assert cves["CVE-2026-46333"].version_comparison_reliable_for == []
