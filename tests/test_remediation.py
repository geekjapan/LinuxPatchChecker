import os
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from patch_checker.cve_db import load_cves
from patch_checker.detector import MITIGATED, NOT_MITIGATED
from patch_checker.remediation import (
    apply_mitigation, check_module_refcnt, check_root, disable_module, set_sysctl,
)

LSMOD_WITH_MODULE = "Module                  Size  Used by\nalgif_aead             16384  0\n"
LSMOD_WITHOUT_MODULE = "Module                  Size  Used by\nalg                    16384  0\n"


class TestCheckRoot:
    def test_root_passes(self):
        with patch("os.geteuid", return_value=0):
            check_root()  # no exception

    def test_non_root_exits(self):
        with patch("os.geteuid", return_value=1000):
            with pytest.raises(SystemExit) as exc:
                check_root()
            assert exc.value.code == 2


class TestCheckModuleRefcnt:
    def test_loaded_refcnt(self, tmp_path):
        mod_dir = tmp_path / "algif_aead"
        mod_dir.mkdir()
        (mod_dir / "refcnt").write_text("0")
        with patch("patch_checker.remediation.Path", side_effect=lambda p: tmp_path / Path(p).name if "refcnt" in p else Path(p)):
            pass
        # Direct test via real path
        refcnt_path = tmp_path / "refcnt"
        refcnt_path.write_text("2")
        with patch("patch_checker.remediation.Path") as mock_path:
            mock_path.return_value.read_text.return_value = "2"
            result = check_module_refcnt("algif_aead")
        assert result == 2

    def test_not_loaded(self):
        with patch("patch_checker.remediation.Path") as mock_path:
            mock_path.return_value.read_text.side_effect = FileNotFoundError
            result = check_module_refcnt("algif_aead")
        assert result == -1


class TestDisableModule:
    def test_already_unloaded_writes_blacklist(self, tmp_path):
        with (
            patch("patch_checker.remediation.detect_module_mitigation", return_value=MITIGATED),
            patch("patch_checker.remediation.MODPROBE_D", tmp_path),
        ):
            result = disable_module("algif_aead", "CVE-2026-31431")
        assert result["success"] is True
        conf = tmp_path / "patch-checker-cve-2026-31431.conf"
        assert conf.exists()
        assert "blacklist algif_aead" in conf.read_text()

    def test_in_use_without_force_skips(self):
        with (
            patch("patch_checker.remediation.detect_module_mitigation", return_value=NOT_MITIGATED),
            patch("patch_checker.remediation.check_module_refcnt", return_value=1),
        ):
            result = disable_module("esp4", "CVE-2026-43284", force=False)
        assert result["success"] is False
        assert "使用中" in result["message"]

    def test_in_use_with_force_unloads(self, tmp_path):
        with (
            patch("patch_checker.remediation.detect_module_mitigation", return_value=NOT_MITIGATED),
            patch("patch_checker.remediation.check_module_refcnt", return_value=1),
            patch("subprocess.run") as mock_run,
            patch("patch_checker.remediation.MODPROBE_D", tmp_path),
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = disable_module("esp4", "CVE-2026-43284", force=True)
        assert result["success"] is True

    def test_unload_failure(self, tmp_path):
        import subprocess
        with (
            patch("patch_checker.remediation.detect_module_mitigation", return_value=NOT_MITIGATED),
            patch("patch_checker.remediation.check_module_refcnt", return_value=0),
            patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "modprobe", stderr=b"ERROR")),
            patch("patch_checker.remediation.MODPROBE_D", tmp_path),
        ):
            result = disable_module("esp4", "CVE-2026-43284")
        assert result["success"] is False


class TestSetSysctl:
    def test_already_set(self):
        with patch("patch_checker.remediation.detect_sysctl_mitigation", return_value=MITIGATED):
            result = set_sysctl("kernel.yama.ptrace_scope", 3)
        assert result["success"] is True
        assert "既に設定済み" in result["message"]

    def test_set_and_persist(self, tmp_path):
        sysctl_conf = tmp_path / "99-patch-checker.conf"
        with (
            patch("patch_checker.remediation.detect_sysctl_mitigation", return_value=NOT_MITIGATED),
            patch("subprocess.run") as mock_run,
            patch("patch_checker.remediation.SYSCTL_CONF", sysctl_conf),
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = set_sysctl("kernel.yama.ptrace_scope", 3)
        assert result["success"] is True
        assert sysctl_conf.exists()
        assert "kernel.yama.ptrace_scope = 3" in sysctl_conf.read_text()


class TestApplyMitigation:
    def test_module_cve(self):
        cves = load_cves()
        cve = cves["CVE-2026-31431"]
        with (
            patch("patch_checker.remediation.detect_module_mitigation", return_value=MITIGATED),
            patch("patch_checker.remediation.MODPROBE_D", Path("/tmp")),
        ):
            results = apply_mitigation(cve)
        assert len(results) == len(cve.modules)
        assert all("cve_id" in r for r in results)

    def test_sysctl_cve(self):
        cves = load_cves()
        cve = cves["CVE-2026-46333"]
        with patch("patch_checker.remediation.detect_sysctl_mitigation", return_value=MITIGATED):
            results = apply_mitigation(cve)
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2026-46333"
