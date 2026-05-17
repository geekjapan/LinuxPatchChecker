from unittest.mock import MagicMock, patch

import pytest

from patch_checker.cve_db import load_cves
from patch_checker.detector import (
    FIXED, MANUAL_CHECK_REQUIRED, MITIGATED, NOT_MITIGATED, VULNERABLE,
    CVEResult, detect_all, detect_module_mitigation, detect_permanent_fix,
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
        assert grep_changelog("CVE-2026-31431", src) is False

    def test_rpm_hit(self):
        src = {"type": "rpm", "package": "kernel"}
        with patch("subprocess.check_output", return_value="* Fix CVE-2026-31431\n"):
            assert grep_changelog("CVE-2026-31431", src) is True

    def test_rpm_miss(self):
        src = {"type": "rpm", "package": "kernel"}
        with patch("subprocess.check_output", return_value="* Other fix\n"):
            assert grep_changelog("CVE-2026-31431", src) is False

    def test_none_type(self):
        assert grep_changelog("CVE-2026-31431", {"type": "none"}) is False


class TestDetectPermanentFix:
    def test_reserved_returns_manual_check(self):
        cves = load_cves()
        distro = _make_distro()
        status, method, _ = detect_permanent_fix(cves["CVE-2026-46300"], distro)
        assert status == MANUAL_CHECK_REQUIRED
        assert method == "reserved"

    def test_changelog_grep_fixes(self):
        cves = load_cves()
        distro = _make_distro()
        remote = {"changelog_CVE-2026-31431": "CVE-2026-31431"}
        status, method, _ = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == FIXED
        assert method == "changelog_grep"

    def test_version_comparison_vulnerable(self):
        cves = load_cves()
        # 6.1.169 is the last affected → still vulnerable
        distro = _make_distro(kernel_str="6.1.169-generic")
        remote = {"changelog_CVE-2026-31431": ""}
        status, method, _ = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == VULNERABLE

    def test_version_comparison_fixed(self):
        cves = load_cves()
        # 6.1.170 is the first fixed
        distro = _make_distro(kernel_str="6.1.170-generic")
        remote = {"changelog_CVE-2026-31431": ""}
        status, method, _ = detect_permanent_fix(cves["CVE-2026-31431"], distro, remote)
        assert status == FIXED

    def test_no_changelog_uses_fallback(self):
        cves = load_cves()
        distro = _make_distro(distro="generic", changelog_type="none")
        distro.changelog_source = {"type": "none"}
        status, method, notes = detect_permanent_fix(cves["CVE-2026-31431"], distro)
        assert method == "version_comparison_fallback"
        assert "changelog" in notes


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
