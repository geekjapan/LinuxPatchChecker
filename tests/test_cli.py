import sys
import pytest
from unittest.mock import patch
from io import StringIO


class TestCmdScanImportError:
    """check.pyz相当の挙動: paramiko未インストール時のscanエラー"""

    def test_scan_exits_2_when_paramiko_missing(self):
        """ImportError時にSystemExit(2)が発生する"""
        from patch_checker.cli import cmd_scan
        import argparse

        args = argparse.Namespace(
            hosts_args=["host1"],
            hosts=None,
            apply=False,
            force=False,
            json=False,
            cve=None,
            user=None,
            key=None,
            timeout=10,
        )

        with patch.dict("sys.modules", {"patch_checker.ssh": None}):
            with pytest.raises(SystemExit) as exc_info:
                cmd_scan(args)
        assert exc_info.value.code == 2

    def test_scan_prints_error_message_when_paramiko_missing(self, capsys):
        """ImportError時に適切なエラーメッセージをstderrに出力する"""
        from patch_checker.cli import cmd_scan
        import argparse

        args = argparse.Namespace(
            hosts_args=["host1"],
            hosts=None,
            apply=False,
            force=False,
            json=False,
            cve=None,
            user=None,
            key=None,
            timeout=10,
        )

        with patch.dict("sys.modules", {"patch_checker.ssh": None}):
            with pytest.raises(SystemExit):
                cmd_scan(args)

        captured = capsys.readouterr()
        assert "patch-checker-scan.pyz" in captured.err
        assert "pip install" in captured.err
