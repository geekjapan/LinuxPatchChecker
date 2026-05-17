import json
import pkgutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CVEEntry:
    cve_id: str
    nickname: str
    cvss: Optional[float]
    reserved: bool
    affected_ranges: List[dict]
    fixed_versions: List[str]
    mitigation_type: str
    modules: List[str] = field(default_factory=list)
    sysctl_key: Optional[str] = None
    sysctl_value: Optional[int] = None
    sysctl_irreversible: bool = False
    permanent_fix_commands: Dict[str, str] = field(default_factory=dict)
    version_comparison_reliable_for: List[str] = field(default_factory=list)


def load_cves() -> Dict[str, CVEEntry]:
    data_bytes = pkgutil.get_data("patch_checker", "data/cves.json")
    if data_bytes is None:
        raise FileNotFoundError("patch_checker/data/cves.json が見つかりません")
    raw = json.loads(data_bytes.decode("utf-8"))
    result: Dict[str, CVEEntry] = {}
    for entry in raw["cves"]:
        cve = CVEEntry(
            cve_id=entry["cve_id"],
            nickname=entry["nickname"],
            cvss=entry.get("cvss"),
            reserved=entry.get("reserved", False),
            affected_ranges=entry.get("affected_ranges", []),
            fixed_versions=entry.get("fixed_versions", []),
            mitigation_type=entry["mitigation_type"],
            modules=entry.get("modules", []),
            sysctl_key=entry.get("sysctl_key"),
            sysctl_value=entry.get("sysctl_value"),
            sysctl_irreversible=entry.get("sysctl_irreversible", False),
            permanent_fix_commands=entry.get("permanent_fix_commands", {}),
            version_comparison_reliable_for=entry.get("version_comparison_reliable_for", []),
        )
        result[cve.cve_id] = cve
    return result


def get_cve(cve_id: str, cves: Optional[Dict[str, CVEEntry]] = None) -> CVEEntry:
    if cves is None:
        cves = load_cves()
    if cve_id not in cves:
        raise KeyError(f"Unknown CVE: {cve_id}")
    return cves[cve_id]
