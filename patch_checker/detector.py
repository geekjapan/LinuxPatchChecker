import gzip
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .cve_db import CVEEntry
from .distro import DistroInfo, KernelVersion

MITIGATED = "MITIGATED"
NOT_MITIGATED = "NOT_MITIGATED"
FIXED = "FIXED"
VULNERABLE = "VULNERABLE"
MANUAL_CHECK_REQUIRED = "MANUAL_CHECK_REQUIRED"


@dataclass
class CVEResult:
    cve_id: str
    nickname: str
    mitigation_status: str
    permanent_fix_status: str
    recommended_action: str
    detection_method: str
    notes: str = ""


def grep_changelog(
    cve_id: str,
    changelog_source: dict,
    remote_outputs: Optional[dict] = None,
) -> bool:
    if remote_outputs is not None:
        return bool(remote_outputs.get(f"changelog_{cve_id}", "").strip())

    source_type = changelog_source.get("type")
    if source_type == "gz":
        try:
            with gzip.open(changelog_source["path"], "rt", errors="replace") as f:
                return cve_id in f.read()
        except (FileNotFoundError, OSError):
            return False
    if source_type == "rpm":
        try:
            out = subprocess.check_output(
                ["rpm", "-q", "--changelog", changelog_source["package"]],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            return cve_id in out
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    return False


def _in_affected_range(kv: KernelVersion, affected_ranges: list) -> bool:
    for r in affected_ranges:
        min_v = KernelVersion.parse(r["min_version"])
        max_v = KernelVersion.parse(r["max_version_exclusive"])
        if min_v <= kv < max_v:
            return True
    return False


def detect_permanent_fix(
    cve: CVEEntry,
    distro_info: DistroInfo,
    remote_outputs: Optional[dict] = None,
) -> Tuple[str, str, str]:
    """Returns (status, detection_method, notes)."""
    if cve.reserved:
        return MANUAL_CHECK_REQUIRED, "reserved", "CVEはRESERVEDステータスのため手動確認が必要"

    source = distro_info.changelog_source
    if source["type"] != "none":
        if grep_changelog(cve.cve_id, source, remote_outputs):
            return FIXED, "changelog_grep", ""
        method = "version_comparison"
        notes = ""
    else:
        method = "version_comparison_fallback"
        notes = "changelogが利用不可のためカーネルバージョン比較のみ使用（精度が低い場合があります）"

    if not cve.affected_ranges:
        return MANUAL_CHECK_REQUIRED, method, notes + " (影響バージョン範囲未定義)"

    if _in_affected_range(distro_info.kernel_version, cve.affected_ranges):
        return VULNERABLE, method, notes
    return FIXED, method, notes


def detect_module_mitigation(
    module_name: str,
    lsmod_output: Optional[str] = None,
) -> str:
    if lsmod_output is None:
        try:
            lsmod_output = subprocess.check_output(["lsmod"], text=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return NOT_MITIGATED

    for line in lsmod_output.splitlines()[1:]:
        parts = line.split()
        if parts and parts[0] == module_name:
            return NOT_MITIGATED
    return MITIGATED


def detect_sysctl_mitigation(
    key: str,
    expected_value: int,
    sysctl_output: Optional[str] = None,
) -> str:
    if sysctl_output is None:
        try:
            sysctl_output = subprocess.check_output(
                ["sysctl", key], text=True, stderr=subprocess.DEVNULL
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return NOT_MITIGATED

    m = re.search(r"=\s*(\d+)", sysctl_output)
    if m and int(m.group(1)) == expected_value:
        return MITIGATED
    return NOT_MITIGATED


def _recommended_action(
    cve: CVEEntry,
    mitigation_status: str,
    permanent_fix_status: str,
    distro: str,
) -> str:
    fix_cmd = cve.permanent_fix_commands.get(distro) or cve.permanent_fix_commands.get("generic", "カーネルを更新してください")
    if permanent_fix_status == FIXED:
        return "恒久対策適用済み。対応不要。"
    if permanent_fix_status == MANUAL_CHECK_REQUIRED:
        if mitigation_status == MITIGATED:
            return "暫定対策適用済み。恒久対策は手動確認が必要。"
        return "暫定対策未適用。手動での恒久対策確認が必要。sudo patch-checker check --apply で暫定対策を適用できます。"
    # VULNERABLE
    if mitigation_status == MITIGATED:
        return f"暫定対策適用済み。恒久対策: {fix_cmd}"
    return f"脆弱。暫定対策: sudo patch-checker check --apply を実行。恒久対策: {fix_cmd}"


def detect_all(
    cves: Dict[str, CVEEntry],
    distro_info: DistroInfo,
    remote_outputs: Optional[dict] = None,
) -> List[CVEResult]:
    lsmod_out = remote_outputs.get("lsmod") if remote_outputs else None
    results: List[CVEResult] = []

    for cve in cves.values():
        if cve.mitigation_type == "module":
            statuses = [detect_module_mitigation(m, lsmod_out) for m in cve.modules]
            mit_status = MITIGATED if all(s == MITIGATED for s in statuses) else NOT_MITIGATED
        elif cve.mitigation_type == "sysctl":
            sysctl_out = remote_outputs.get(f"sysctl_{cve.sysctl_key}") if remote_outputs else None
            mit_status = detect_sysctl_mitigation(cve.sysctl_key, cve.sysctl_value, sysctl_out)
        else:
            mit_status = NOT_MITIGATED

        perm_status, method, notes = detect_permanent_fix(cve, distro_info, remote_outputs)
        action = _recommended_action(cve, mit_status, perm_status, distro_info.distro)

        results.append(CVEResult(
            cve_id=cve.cve_id,
            nickname=cve.nickname,
            mitigation_status=mit_status,
            permanent_fix_status=perm_status,
            recommended_action=action,
            detection_method=method,
            notes=notes,
        ))

    return results
