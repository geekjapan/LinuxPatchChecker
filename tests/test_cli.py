import sys
import pytest
from unittest.mock import patch
from io import StringIO


class TestVersion:
    """--version フラグのテスト"""

    def test_version_exits_0(self):
        """--version は SystemExit(0) を発生させる"""
        from patch_checker.cli import main

        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["patch-checker", "--version"]):
                main()
        assert exc_info.value.code == 0

    def test_version_output_contains_version(self, capsys):
        """--version の出力に 0.2.0 が含まれる"""
        from patch_checker.cli import main

        with pytest.raises(SystemExit):
            with patch("sys.argv", ["patch-checker", "--version"]):
                main()

        captured = capsys.readouterr()
        assert "0.2.0" in captured.out


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
