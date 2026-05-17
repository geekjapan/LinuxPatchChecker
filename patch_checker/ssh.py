import socket
import sys
from typing import Optional

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

from .distro import detect_distro
from .detector import detect_all

CONNECT_TIMEOUT = 10
EXEC_TIMEOUT = 30


def _run(client: "paramiko.SSHClient", cmd: str) -> str:
    _, stdout, _ = client.exec_command(cmd, timeout=EXEC_TIMEOUT)
    return stdout.read().decode(errors="replace")


def _collect(client: "paramiko.SSHClient", cves: dict, uname_r: str) -> dict:
    out: dict = {}
    out["lsmod"] = _run(client, "lsmod 2>/dev/null || true")
    out["sysctl_kernel.yama.ptrace_scope"] = _run(
        client,
        "sysctl kernel.yama.ptrace_scope 2>/dev/null || echo 'kernel.yama.ptrace_scope = 0'",
    )
    for cve_id in cves:
        cmd = (
            f"("
            f"zcat /usr/share/doc/linux-image-{uname_r}/changelog.Debian.gz 2>/dev/null || "
            f"rpm -q --changelog kernel 2>/dev/null || "
            f"rpm -q --changelog kernel-default 2>/dev/null || true"
            f") | grep -m1 '{cve_id}' 2>/dev/null || true"
        )
        out[f"changelog_{cve_id}"] = _run(client, cmd)
    return out


def _apply_remote(client: "paramiko.SSHClient", cves: dict) -> list:
    """Apply mitigations on remote host by running modprobe/sysctl over SSH."""
    results = []
    for cve in cves.values():
        if cve.mitigation_type == "module":
            for module in cve.modules:
                r = _run(
                    client,
                    f"modprobe -r {module} 2>&1 && echo 'OK' || echo 'FAIL'",
                )
                success = r.strip().endswith("OK")
                if success:
                    _run(
                        client,
                        f"echo 'blacklist {module}' >> /etc/modprobe.d/patch-checker-{cve.cve_id.lower()}.conf",
                    )
                results.append({
                    "cve_id": cve.cve_id,
                    "module": module,
                    "success": success,
                    "message": f"{module}: {'アンロードしました。' if success else 'アンロード失敗。rootでの実行を確認してください。'}",
                })
        elif cve.mitigation_type == "sysctl":
            r = _run(
                client,
                f"sysctl -w {cve.sysctl_key}={cve.sysctl_value} 2>&1 && "
                f"echo '{cve.sysctl_key} = {cve.sysctl_value}' >> /etc/sysctl.d/99-patch-checker.conf && "
                f"echo 'OK' || echo 'FAIL'",
            )
            success = r.strip().endswith("OK")
            results.append({
                "cve_id": cve.cve_id,
                "success": success,
                "message": f"{cve.sysctl_key}={cve.sysctl_value}: {'設定しました。' if success else '設定失敗。rootでの実行を確認してください。'}",
            })
    return results


def scan_host(host: str, options: dict) -> dict:
    if not HAS_PARAMIKO:
        return {
            "host": host,
            "status": "CONNECTION_ERROR",
            "error": "paramiko がインストールされていません。pip install paramiko を実行してください。",
        }

    import paramiko

    cves = options.get("cves", {})
    user = options.get("user")
    key = options.get("key")
    timeout = options.get("timeout", CONNECT_TIMEOUT)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = {"hostname": host, "timeout": timeout, "banner_timeout": timeout}
    if user:
        connect_kwargs["username"] = user
    if key:
        connect_kwargs["key_filename"] = key

    try:
        client.connect(**connect_kwargs)
    except (paramiko.ssh_exception.SSHException, socket.timeout, OSError) as e:
        return {"host": host, "status": "CONNECTION_ERROR", "error": str(e)}

    try:
        uname_r = _run(client, "uname -r").strip()
        os_release = _run(client, "cat /etc/os-release 2>/dev/null || true")
        remote_data = _collect(client, cves, uname_r)
        remote_data["uname_r"] = uname_r
        remote_data["os_release"] = os_release

        distro_info = detect_distro(os_release_content=os_release, uname_r=uname_r)
        distro_info.hostname = host

        results = detect_all(cves, distro_info, remote_outputs=remote_data)

        apply_results = None
        if options.get("apply"):
            whoami = _run(client, "id -u").strip()
            if whoami == "0":
                apply_results = _apply_remote(client, cves)
                results = detect_all(cves, distro_info, remote_outputs=_collect(client, cves, uname_r))
            else:
                apply_results = [{"success": False, "message": "リモートホストでrootでないため適用をスキップしました。sudo で SSH してください。"}]
    finally:
        client.close()

    return {
        "host": host,
        "kernel": uname_r,
        "distro": distro_info.distro,
        "is_els": distro_info.is_els,
        "package_kernel_version": distro_info.package_kernel_version,
        "status": "ok",
        "_results": results,
        "results": [
            {
                "cve_id": r.cve_id,
                "nickname": r.nickname,
                "mitigation_status": r.mitigation_status,
                "permanent_fix_status": r.permanent_fix_status,
                "recommended_action": r.recommended_action,
                "detection_method": r.detection_method,
                "notes": r.notes,
                "detection_confidence": r.detection_confidence,
            }
            for r in results
        ],
        **({"apply_results": apply_results} if apply_results is not None else {}),
    }


def scan_hosts(hosts: list, options: dict) -> list:
    return [scan_host(h, options) for h in hosts]
