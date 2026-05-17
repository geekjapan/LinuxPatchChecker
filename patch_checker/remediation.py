import os
import subprocess
from pathlib import Path
from typing import Optional

from .cve_db import CVEEntry
from .detector import MITIGATED, detect_module_mitigation, detect_sysctl_mitigation

MODPROBE_D = Path("/etc/modprobe.d")
SYSCTL_CONF = Path("/etc/sysctl.d/99-patch-checker.conf")


def check_root() -> None:
    if os.geteuid() != 0:
        print("エラー: --apply オプションにはroot権限が必要です。")
        print("使用方法: sudo patch-checker check --apply")
        raise SystemExit(2)


def check_module_refcnt(module_name: str) -> int:
    """Return refcnt, or -1 if module is not loaded."""
    refcnt_path = Path(f"/sys/module/{module_name}/refcnt")
    try:
        return int(refcnt_path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return -1


def _write_blacklist(module_name: str, cve_id: str) -> None:
    MODPROBE_D.mkdir(parents=True, exist_ok=True)
    conf = MODPROBE_D / f"patch-checker-{cve_id.lower()}.conf"
    entry = f"blacklist {module_name}\n"
    existing = conf.read_text() if conf.exists() else ""
    if entry not in existing:
        with open(conf, "a") as f:
            f.write(entry)


def disable_module(module_name: str, cve_id: str, force: bool = False) -> dict:
    if detect_module_mitigation(module_name) == MITIGATED:
        _write_blacklist(module_name, cve_id)
        return {"success": True, "message": f"{module_name}: 既にアンロード済み。blacklistを確認/作成しました。"}

    refcnt = check_module_refcnt(module_name)
    if refcnt > 0 and not force:
        return {
            "success": False,
            "message": f"{module_name}: 使用中 (refcnt={refcnt})。スキップしました。--force で強制適用できます。",
        }

    try:
        subprocess.run(["modprobe", "-r", module_name], check=True, capture_output=True)
        _write_blacklist(module_name, cve_id)
        return {"success": True, "message": f"{module_name}: アンロードしました。"}
    except subprocess.CalledProcessError as e:
        return {"success": False, "message": f"{module_name}: アンロード失敗: {e.stderr.decode().strip()}"}


def set_sysctl(key: str, value: int) -> dict:
    if detect_sysctl_mitigation(key, value) == MITIGATED:
        return {"success": True, "message": f"{key}={value}: 既に設定済み。"}

    try:
        subprocess.run(["sysctl", "-w", f"{key}={value}"], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        return {"success": False, "message": f"sysctl -w 失敗: {e.stderr.decode().strip()}"}

    SYSCTL_CONF.parent.mkdir(parents=True, exist_ok=True)
    existing = SYSCTL_CONF.read_text() if SYSCTL_CONF.exists() else ""
    entry = f"{key} = {value}\n"
    if entry not in existing:
        with open(SYSCTL_CONF, "a") as f:
            f.write(entry)

    return {"success": True, "message": f"{key}={value}: 設定しました。"}


def apply_mitigation(cve: CVEEntry, force: bool = False) -> list:
    results = []
    if cve.mitigation_type == "module":
        for module in cve.modules:
            r = disable_module(module, cve.cve_id, force)
            r["cve_id"] = cve.cve_id
            r["module"] = module
            results.append(r)
    elif cve.mitigation_type == "sysctl":
        r = set_sysctl(cve.sysctl_key, cve.sysctl_value)
        r["cve_id"] = cve.cve_id
        results.append(r)
    return results
