from unittest.mock import MagicMock, patch

import pytest

from patch_checker.cve_db import load_cves
from patch_checker.ssh import scan_host, scan_hosts


def _make_options(**kwargs):
    defaults = {"cves": load_cves(), "apply": False, "force": False, "user": None, "key": None, "timeout": 10}
    defaults.update(kwargs)
    return defaults


class TestScanHost:
    def test_connection_error_returns_error_dict(self):
        with patch("patch_checker.ssh.HAS_PARAMIKO", True):
            import paramiko
            with patch("paramiko.SSHClient") as mock_client_cls:
                mock_client = MagicMock()
                mock_client_cls.return_value = mock_client
                mock_client.connect.side_effect = paramiko.ssh_exception.SSHException("Connection refused")
                result = scan_host("unreachable-host", _make_options())
        assert result["status"] == "CONNECTION_ERROR"
        assert result["host"] == "unreachable-host"
        assert "error" in result

    def test_no_paramiko_returns_error(self):
        with patch("patch_checker.ssh.HAS_PARAMIKO", False):
            result = scan_host("somehost", _make_options())
        assert result["status"] == "CONNECTION_ERROR"
        assert "paramiko" in result["error"]

    def test_successful_scan_structure(self):
        cves = load_cves()
        with patch("patch_checker.ssh.HAS_PARAMIKO", True):
            with patch("paramiko.SSHClient") as mock_client_cls:
                mock_client = MagicMock()
                mock_client_cls.return_value = mock_client
                mock_client.connect.return_value = None

                def fake_exec(cmd, timeout=30):
                    stdout = MagicMock()
                    if "uname" in cmd:
                        stdout.read.return_value = b"6.1.170-generic\n"
                    elif "os-release" in cmd:
                        stdout.read.return_value = b'ID=ubuntu\nNAME="Ubuntu"\n'
                    elif "lsmod" in cmd:
                        stdout.read.return_value = b"Module   Size  Used by\n"
                    elif "ptrace_scope" in cmd:
                        stdout.read.return_value = b"kernel.yama.ptrace_scope = 3\n"
                    else:
                        stdout.read.return_value = b""
                    return MagicMock(), stdout, MagicMock()

                mock_client.exec_command.side_effect = fake_exec
                result = scan_host("testhost", _make_options(cves=cves))

        assert result["status"] == "ok"
        assert result["host"] == "testhost"
        assert "kernel" in result
        assert "distro" in result
        assert "results" in result
        assert len(result["results"]) == len(cves)


class TestScanHosts:
    def test_processes_all_hosts(self):
        hosts = ["host1", "host2", "host3"]
        with patch("patch_checker.ssh.scan_host") as mock_scan:
            mock_scan.return_value = {"host": "x", "status": "CONNECTION_ERROR", "error": "test"}
            results = scan_hosts(hosts, _make_options())
        assert len(results) == 3
        assert mock_scan.call_count == 3

    def test_continues_after_failure(self):
        call_count = 0

        def fake_scan(host, options):
            nonlocal call_count
            call_count += 1
            if host == "host2":
                return {"host": host, "status": "CONNECTION_ERROR", "error": "timeout"}
            return {"host": host, "status": "ok", "results": [], "_results": []}

        with patch("patch_checker.ssh.scan_host", side_effect=fake_scan):
            results = scan_hosts(["host1", "host2", "host3"], _make_options())

        assert call_count == 3
        error_results = [r for r in results if r.get("status") == "CONNECTION_ERROR"]
        assert len(error_results) == 1
        assert error_results[0]["host"] == "host2"
