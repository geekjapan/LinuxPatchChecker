import json
from typing import List, Optional

from .detector import CVEResult, FIXED, VULNERABLE, NOT_MITIGATED, MANUAL_CHECK_REQUIRED


def format_text(
    host: str,
    kernel: str,
    distro: str,
    results: List[CVEResult],
    apply_results: Optional[list] = None,
) -> str:
    lines = [
        f"Host:   {host}",
        f"Kernel: {kernel}",
        f"Distro: {distro}",
        "",
        f"{'CVE':<20} {'通称':<22} {'暫定対策':<16} {'恒久対策':<26}",
        "-" * 86,
    ]

    for r in results:
        mit = ("OK " if r.mitigation_status == "MITIGATED" else "NG ") + r.mitigation_status
        perm_map = {
            FIXED: "OK  FIXED",
            VULNERABLE: "NG  VULNERABLE",
            MANUAL_CHECK_REQUIRED: "??  MANUAL_CHECK_REQUIRED",
        }
        perm = perm_map.get(r.permanent_fix_status, r.permanent_fix_status)
        lines.append(f"{r.cve_id:<20} {r.nickname:<22} {mit:<16} {perm}")
        lines.append(f"  推奨: {r.recommended_action}")
        if r.notes:
            lines.append(f"  注記: {r.notes}")

    if apply_results:
        lines.append("")
        lines.append("=== 暫定対策適用結果 ===")
        for ar in apply_results:
            sym = "OK" if ar.get("success") else "NG"
            lines.append(f"  [{sym}] {ar.get('message', '')}")

    return "\n".join(lines)


def format_json(
    host: str,
    kernel: str,
    distro: str,
    results: List[CVEResult],
    apply_results: Optional[list] = None,
) -> str:
    data: dict = {
        "host": host,
        "kernel": kernel,
        "distro": distro,
        "results": [
            {
                "cve_id": r.cve_id,
                "nickname": r.nickname,
                "mitigation_status": r.mitigation_status,
                "permanent_fix_status": r.permanent_fix_status,
                "recommended_action": r.recommended_action,
                "detection_method": r.detection_method,
                "notes": r.notes,
            }
            for r in results
        ],
    }
    if apply_results is not None:
        data["apply_results"] = apply_results
    return json.dumps(data, ensure_ascii=False, indent=2)


def format_scan_json(scan_results: list) -> str:
    serializable = []
    for sr in scan_results:
        entry = {k: v for k, v in sr.items() if not k.startswith("_")}
        serializable.append(entry)
    return json.dumps(serializable, ensure_ascii=False, indent=2)


def exit_code(results: List[CVEResult]) -> int:
    for r in results:
        if r.permanent_fix_status == VULNERABLE or r.mitigation_status == NOT_MITIGATED:
            return 1
    return 0
