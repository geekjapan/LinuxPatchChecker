import argparse
import sys

from .cve_db import load_cves
from .detector import detect_all
from .distro import detect_distro
from .remediation import apply_mitigation, check_root
from .reporter import exit_code, format_json, format_scan_json, format_text
from .ssh import scan_hosts


def _resolve_hosts(args) -> list:
    hosts = list(getattr(args, "hosts_args", None) or [])
    if getattr(args, "hosts", None):
        with open(args.hosts) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.append(line)
    return hosts


def _filter_cves(cves: dict, cve_id: str) -> dict:
    filtered = {k: v for k, v in cves.items() if k == cve_id}
    if not filtered:
        print(f"エラー: CVE '{cve_id}' はデータベースにありません。", file=sys.stderr)
        raise SystemExit(2)
    return filtered


def cmd_check(args) -> None:
    cves = load_cves()
    if args.cve:
        cves = _filter_cves(cves, args.cve)

    if args.apply:
        check_root()

    distro_info = detect_distro()
    results = detect_all(cves, distro_info)

    apply_results = None
    if args.apply:
        apply_results = []
        for cve in cves.values():
            apply_results.extend(apply_mitigation(cve, force=args.force))
        results = detect_all(cves, distro_info)

    if args.json:
        print(format_json(
            distro_info.hostname, distro_info.kernel_version_str, distro_info.distro,
            results, apply_results,
            is_els=distro_info.is_els,
            package_kernel_version=distro_info.package_kernel_version,
        ))
    else:
        print(format_text(
            distro_info.hostname, distro_info.kernel_version_str, distro_info.distro,
            results, apply_results,
            changelog_type=distro_info.changelog_source.get("type", ""),
            is_els=distro_info.is_els,
        ))

    raise SystemExit(exit_code(results))


def cmd_scan(args) -> None:
    hosts = _resolve_hosts(args)
    if not hosts:
        print("エラー: スキャン対象のホストを指定してください。", file=sys.stderr)
        raise SystemExit(2)

    cves = load_cves()
    if args.cve:
        cves = _filter_cves(cves, args.cve)

    options = {
        "apply": args.apply,
        "force": args.force,
        "user": getattr(args, "user", None),
        "key": getattr(args, "key", None),
        "timeout": getattr(args, "timeout", 10),
        "cves": cves,
    }

    scan_results = scan_hosts(hosts, options)

    if args.json:
        print(format_scan_json(scan_results))
    else:
        for sr in scan_results:
            print(f"\n{'=' * 60}")
            if sr.get("status") == "CONNECTION_ERROR":
                print(f"Host: {sr['host']}  [接続エラー: {sr.get('error', '')}]")
            else:
                print(format_text(
                    sr["host"],
                    sr.get("kernel", "unknown"),
                    sr.get("distro", "unknown"),
                    sr.get("_results", []),
                    sr.get("apply_results"),
                ))

    all_results = [r for sr in scan_results for r in sr.get("_results", [])]
    has_error = any(sr.get("status") == "CONNECTION_ERROR" for sr in scan_results)
    raise SystemExit(1 if has_error else exit_code(all_results))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="patch-checker",
        description="Linux Kernel LPE CVE 対策状況チェッカー (2026年4-5月 CVE群)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # check
    cp = sub.add_parser("check", help="ローカルホストをスキャン")
    cp.add_argument("--apply", action="store_true", help="暫定対策を適用する（要root/sudo）")
    cp.add_argument("--force", action="store_true", help="使用中モジュールを強制アンロード")
    cp.add_argument("--json", action="store_true", help="JSON形式で出力")
    cp.add_argument("--cve", metavar="CVE-ID", help="特定CVEのみチェック")

    # scan
    sp = sub.add_parser("scan", help="SSH経由で複数ホストをスキャン")
    sp.add_argument("hosts_args", nargs="*", metavar="HOST", help="スキャン対象ホスト")
    sp.add_argument("--hosts", metavar="FILE", help="ホストリストファイル（1行1ホスト）")
    sp.add_argument("--apply", action="store_true", help="暫定対策を適用する（リモートでrootが必要）")
    sp.add_argument("--force", action="store_true", help="使用中モジュールを強制アンロード")
    sp.add_argument("--json", action="store_true", help="JSON形式で出力")
    sp.add_argument("--cve", metavar="CVE-ID", help="特定CVEのみチェック")
    sp.add_argument("--user", metavar="USER", help="SSH接続ユーザー")
    sp.add_argument("--key", metavar="KEY", help="SSH秘密鍵パス")
    sp.add_argument("--timeout", type=int, default=10, metavar="SEC", help="SSH接続タイムアウト秒数（デフォルト: 10）")

    args = parser.parse_args()
    if args.command == "check":
        cmd_check(args)
    elif args.command == "scan":
        cmd_scan(args)


if __name__ == "__main__":
    main()
