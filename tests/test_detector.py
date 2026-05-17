from unittest.mock import MagicMock, patch

import pytest

from patch_checker.cve_db import load_cves
from patch_checker.detector import (
    FIXED, HIGH, LOW, MANUAL_CHECK_REQUIRED, MEDIUM, MITIGATED, NOT_MITIGATED, VULNERABLE,
    CVEResult, _compute_confidence, detect_all, detect_module_mitigation, detect_permanent_fix,
    detect_sysctl_mitigation, grep_changelog,
)
from patch_checker.distro import DistroInfo, KernelVersion

LSMOD_WITH_ESP4 = "Module                  Size  Used by\nesp4                   16384  0\nalg                    16384  0\n"
LSMOD_WITHOUT_ESP4 = "Module                  Size  Used by\nalg                    16384  0\n"


def _make_distro(distro="ubuntu", kernel_str="6.1.169-generic", changelog_type="gz"):
    kv = KernelVersion.parse(kernel_str)
    src = {"type": changelog_type, "path": "/usr/share/doc/linux-image-6.1.169-generic/changelog.Debian.gz"}
    return DistroInfo(distro=distro, kernel_version=kv, kernel_version_str=kernel_str, changelog_source=src, hostname="testhost")


class TestGrep:
    def test_remote_outputs_hit(self):
        remote = {"changelog_CVE-2026-31431": "  * CVE-2026-31431 fix applied"}
        assert grep_changelog("CVE-2026-31431", {}, remote) is True

    def test_remote_outputs_miss(self):
        remote = {"changelog_CVE-2026-31431": ""}
        assert grep_changelog("CVE-2026-31431", {}, remote) is False

    def test_gz_hit(self, tmp_path):
        import gzip
        gz_path = tmp_path / "changelog.Debian.gz"
        with gzip.open(gz_path, "wt") as f:
            f.write("Fix for CVE-2026-31431 applied.\n")
        src = {"type": "gz", "path": str(gz_path)}
        assert grep_changelog("CVE-2026-31431", src) is True

    def test_gz_miss(self, tmp_path):
        import gzip
        gz_path = tmp_path / "changelog.Debian.gz"
        with gzip.open(gz_path, "wt") as f:
            f.write("No fixes here.\n")
        src = {"type": "gz", "path": str(gz_path)}
        assert grep_changelog("CVE-2026-31431", src) is False

    def test_gz_missing_file(self):
        src = {"type": "gz", "path": "/nonexistent/changelog.Debian.gz"}
        assert grep_changelog("CVE-2026-31431", src) is None

    def test_rpm_hit(self):
        src = {"type": "rpm", "package": "kernel"}
        with patch("subprocess.check_output", return_value="* Fix CVE-2026-31431\n"):
            assert grep_changelog("CVE-2026-31431", src) is True

    def test_rpm_miss(self):
        src = {"type": "rpm", "package": "kernel"}
        with patch("subprocess.check_output", return_value="* Other fix\n"):
            assert grep_changelog("CVE-2026-31431", src) is False

    def test_rpm_access_error_returns_none(self):
        import subprocess as _sp
        src = {"type": "rpm", "package": "kernel"}
        with patch("subprocess.check_output", side_effect=_sp.CalledProcessError(1, "rpm")):
            assert grep_changelog("CVE-2026-31431", src) is None

    def test_none_type(self):
        assert grep_changelog("CVE-2026-31431", {"type": "none"}) is False


class TestDetectPermanentFix:
    def test_reserved_returns_manual_check(self):
        cves = load_cves()
        distro = _make_distro()
        status, method, _, _c = detect_permanent_fix(cves["CVE-2026-46300"], distro)
        assert status == MANUAL_CHECK_REQUIRED
        assert method == "reserved"

    def test_changelog_grep_fixes(self):
        cves = load_cves()
        distro = _make_distro()
        remote = {"changelog_CVE-2026-31431": "CVE-2026-31431"}
        status, method, _, _c = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == FIXED
        assert method == "changelog_grep"

    def test_version_comparison_vulnerable(self):
        cves = load_cves()
        # 6.1.169 is the last affected → still vulnerable
        distro = _make_distro(kernel_str="6.1.169-generic")
        remote = {"changelog_CVE-2026-31431": ""}
        status, method, _, _c = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == VULNERABLE

    def test_version_comparison_fixed(self):
        cves = load_cves()
        # 6.1.170 is the first fixed
        # ubuntu is not in version_comparison_reliable_for → LOW → MANUAL_CHECK_REQUIRED
        distro = _make_distro(distro="ubuntu", kernel_str="6.1.170-generic")
        remote = {"changelog_CVE-2026-31431": ""}
        status, method, _, _c = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == MANUAL_CHECK_REQUIRED

    def test_version_comparison_fixed_trusted_distro(self):
        cves = load_cves()
        # 6.1.170 is the first fixed; fedora is trusted → MEDIUM → FIXED
        distro = _make_distro(distro="fedora", kernel_str="6.1.170-generic")
        remote = {"changelog_CVE-2026-31431": ""}
        status, method, _, _c = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == FIXED

    def test_no_changelog_uses_fallback(self):
        cves = load_cves()
        distro = _make_distro(distro="generic", changelog_type="none")
        distro.changelog_source = {"type": "none"}
        status, method, notes, confidence = detect_permanent_fix(cves["CVE-2026-31431"], distro)
        assert method == "version_comparison_fallback"
        assert "changelog" in notes
        assert confidence == MEDIUM


class TestModuleMitigation:
    def test_module_loaded(self):
        assert detect_module_mitigation("esp4", LSMOD_WITH_ESP4) == NOT_MITIGATED

    def test_module_not_loaded(self):
        assert detect_module_mitigation("esp4", LSMOD_WITHOUT_ESP4) == MITIGATED

    def test_module_partial_name_no_match(self):
        # "esp4" should not match "esp4_udp" or similar
        lsmod = "Module                  Size  Used by\nesp4_udp               16384  0\n"
        assert detect_module_mitigation("esp4", lsmod) == MITIGATED

    def test_lsmod_subprocess(self):
        with patch("subprocess.check_output", return_value=LSMOD_WITH_ESP4):
            assert detect_module_mitigation("esp4") == NOT_MITIGATED


class TestSysctlMitigation:
    def test_value_matches(self):
        assert detect_sysctl_mitigation("kernel.yama.ptrace_scope", 3, "kernel.yama.ptrace_scope = 3\n") == MITIGATED

    def test_value_mismatch(self):
        assert detect_sysctl_mitigation("kernel.yama.ptrace_scope", 3, "kernel.yama.ptrace_scope = 0\n") == NOT_MITIGATED

    def test_subprocess_call(self):
        with patch("subprocess.check_output", return_value="kernel.yama.ptrace_scope = 3\n"):
            assert detect_sysctl_mitigation("kernel.yama.ptrace_scope", 3) == MITIGATED


class TestComputeConfidence:
    def test_changelog_hit_returns_high(self):
        cves = load_cves()
        distro = _make_distro(distro="ubuntu")
        distro.is_els = False
        assert _compute_confidence(cves["CVE-2026-31431"], distro, changelog_hit=True) == HIGH

    def test_els_returns_low(self):
        cves = load_cves()
        distro = _make_distro(distro="rhel")
        distro.is_els = True
        assert _compute_confidence(cves["CVE-2026-31431"], distro, changelog_hit=False) == LOW

    def test_no_changelog_returns_medium_for_trusted_distro(self):
        cves = load_cves()
        distro = _make_distro(distro="generic", changelog_type="none")
        distro.changelog_source = {"type": "none"}
        distro.is_els = False
        assert _compute_confidence(cves["CVE-2026-31431"], distro, changelog_hit=False) == MEDIUM

    def test_inaccessible_changelog_returns_low_even_trusted(self):
        cves = load_cves()
        distro = _make_distro(distro="generic", changelog_type="none")
        distro.changelog_source = {"type": "none"}
        distro.is_els = False
        assert _compute_confidence(cves["CVE-2026-31431"], distro, changelog_hit=None) == LOW

    def test_trusted_distro_returns_medium(self):
        cves = load_cves()
        distro = _make_distro(distro="fedora")
        distro.is_els = False
        assert _compute_confidence(cves["CVE-2026-31431"], distro, changelog_hit=False) == MEDIUM

    def test_untrusted_distro_returns_low(self):
        cves = load_cves()
        distro = _make_distro(distro="ubuntu")
        distro.is_els = False
        assert _compute_confidence(cves["CVE-2026-31431"], distro, changelog_hit=False) == LOW

    def test_opensuse_tumbleweed_returns_medium(self):
        cves = load_cves()
        distro = _make_distro(distro="opensuse-tumbleweed")
        distro.is_els = False
        assert _compute_confidence(cves["CVE-2026-31431"], distro, changelog_hit=False) == MEDIUM


class TestDetectPermanentFixConfidence:
    def test_low_fixed_upgrades_to_manual_check(self):
        """LOW confidence + FIXED → MANUAL_CHECK_REQUIRED"""
        cves = load_cves()
        # Ubuntu: not in version_comparison_reliable_for, so LOW
        distro = _make_distro(distro="ubuntu", kernel_str="6.1.170-generic")  # past fix
        distro.is_els = False
        remote = {"changelog_CVE-2026-31431": ""}  # no changelog hit
        status, method, notes, confidence = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == MANUAL_CHECK_REQUIRED
        assert confidence == LOW

    def test_medium_fixed_stays_fixed(self):
        """MEDIUM confidence + FIXED stays FIXED"""
        cves = load_cves()
        # Fedora: in version_comparison_reliable_for, so MEDIUM
        distro = _make_distro(distro="fedora", kernel_str="6.1.170-generic")
        distro.is_els = False
        remote = {"changelog_CVE-2026-31431": ""}
        status, method, notes, confidence = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == FIXED
        assert confidence == MEDIUM

    def test_vulnerable_stays_vulnerable_even_with_low(self):
        """LOW + VULNERABLE → stays VULNERABLE"""
        cves = load_cves()
        distro = _make_distro(distro="ubuntu", kernel_str="6.1.169-generic")  # in range
        distro.is_els = False
        remote = {"changelog_CVE-2026-31431": ""}
        status, method, notes, confidence = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == VULNERABLE
        assert confidence == LOW

    def test_changelog_hit_returns_high(self):
        cves = load_cves()
        distro = _make_distro(distro="ubuntu")
        remote = {"changelog_CVE-2026-31431": "CVE-2026-31431"}
        status, method, notes, confidence = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == FIXED
        assert confidence == HIGH


class TestDetectAll:
    def test_returns_all_cves(self):
        cves = load_cves()
        distro = _make_distro()
        remote = {
            "lsmod": LSMOD_WITHOUT_ESP4,
            "sysctl_kernel.yama.ptrace_scope": "kernel.yama.ptrace_scope = 3\n",
            **{f"changelog_{cve_id}": "" for cve_id in cves},
        }
        results = detect_all(cves, distro, remote)
        result_ids = {r.cve_id for r in results}
        assert result_ids == set(cves.keys())

    def test_result_has_required_fields(self):
        cves = load_cves()
        distro = _make_distro()
        remote = {"lsmod": "", **{f"changelog_{cve_id}": "" for cve_id in cves},
                  "sysctl_kernel.yama.ptrace_scope": "kernel.yama.ptrace_scope = 0\n"}
        results = detect_all(cves, distro, remote)
        for r in results:
            assert r.cve_id
            assert r.nickname
            assert r.mitigation_status in (MITIGATED, NOT_MITIGATED)
            assert r.permanent_fix_status in (FIXED, VULNERABLE, MANUAL_CHECK_REQUIRED)
            assert r.recommended_action
            assert r.detection_method
            assert r.detection_confidence in (HIGH, MEDIUM, LOW)

    def test_ubuntu_fixed_without_changelog_upgrades_to_manual_check(self):
        """Ubuntu is untrusted distro → LOW confidence → FIXED upgrades to MANUAL_CHECK_REQUIRED"""
        cves = load_cves()
        # ubuntu kernel out of affected range (post-fix), no changelog hit
        distro = _make_distro(distro="ubuntu", kernel_str="6.1.170-generic")
        remote = {"lsmod": LSMOD_WITHOUT_ESP4,
                  "sysctl_kernel.yama.ptrace_scope": "kernel.yama.ptrace_scope = 3\n",
                  **{f"changelog_{cve_id}": "" for cve_id in cves}}
        results = detect_all(cves, distro, remote)
        copyfail = next(r for r in results if r.cve_id == "CVE-2026-31431")
        assert copyfail.permanent_fix_status == MANUAL_CHECK_REQUIRED
        assert copyfail.detection_confidence == LOW
