import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional


ELS_DISTROS: frozenset = frozenset({
    ("ubuntu", "16.04"),
    ("ubuntu", "18.04"),
})

# Prefix-matched ELS: VERSION_ID "7", "7.9", "12", "12.5" etc. all match
ELS_DISTRO_PREFIXES: frozenset = frozenset({
    ("rhel", "7"),
    ("centos", "7"),
    ("sles", "12"),
})


def is_els_distro(distro_id: str, version_id: str) -> bool:
    if (distro_id, version_id) in ELS_DISTROS:
        return True
    return any(distro_id == d and (version_id == v or version_id.startswith(v + ".")) for d, v in ELS_DISTRO_PREFIXES)


@dataclass(order=True)
class KernelVersion:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, version_str: str) -> "KernelVersion":
        match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
        if not match:
            raise ValueError(f"Cannot parse kernel version: {version_str!r}")
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass
class DistroInfo:
    distro: str
    kernel_version: KernelVersion
    kernel_version_str: str
    changelog_source: dict
    hostname: str
    is_els: bool = False
    package_kernel_version: Optional[str] = None


def detect_distro(
    os_release_content: Optional[str] = None,
    uname_r: Optional[str] = None,
) -> DistroInfo:
    is_local = os_release_content is None
    if os_release_content is None:
        try:
            with open("/etc/os-release") as f:
                os_release_content = f.read()
        except FileNotFoundError:
            os_release_content = ""

    if uname_r is None:
        uname_r = subprocess.check_output(["uname", "-r"], text=True).strip()

    fields: dict = {}
    for line in os_release_content.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')

    distro_id = fields.get("ID", "").lower()
    id_like = fields.get("ID_LIKE", "").lower()
    is_wsl2 = "microsoft" in uname_r.lower() or "wsl" in uname_r.lower()

    if distro_id == "ubuntu" and is_wsl2:
        distro = "ubuntu-wsl2"
    elif distro_id == "ubuntu":
        distro = "ubuntu"
    elif distro_id == "debian":
        distro = "debian"
    elif distro_id == "rhel" or "rhel" in id_like:
        distro = "rhel"
    elif distro_id == "almalinux":
        distro = "almalinux"
    elif distro_id in ("rocky",):
        distro = "rocky"
    elif distro_id == "fedora":
        distro = "fedora"
    elif distro_id in ("centos", "centos-stream"):
        distro = "centos"
    elif distro_id == "sles" or "sles" in id_like:
        distro = "sles"
    elif distro_id == "opensuse-tumbleweed":
        distro = "opensuse-tumbleweed"
    elif distro_id in ("opensuse", "opensuse-leap"):
        distro = "opensuse"
    else:
        distro = "generic"

    try:
        kv = KernelVersion.parse(uname_r)
    except ValueError:
        kv = KernelVersion(0, 0, 0)

    changelog_source = get_changelog_source(distro, uname_r)

    version_id = fields.get("VERSION_ID", "")
    is_els = is_els_distro(distro_id, version_id)
    package_kernel_version = get_package_kernel_version(distro, uname_r) if is_local else None

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"

    return DistroInfo(
        distro=distro,
        kernel_version=kv,
        kernel_version_str=uname_r,
        changelog_source=changelog_source,
        hostname=hostname,
        is_els=is_els,
        package_kernel_version=package_kernel_version,
    )


def get_package_kernel_version(distro: str, uname_r: str) -> Optional[str]:
    try:
        if distro in ("ubuntu", "debian"):
            result = subprocess.run(
                ["dpkg-query", "-W", "-f", "${Version}", f"linux-image-{uname_r}"],
                capture_output=True, text=True, timeout=1,
            )
            return result.stdout.strip() or None
        if distro in ("rhel", "almalinux", "rocky", "fedora", "centos", "sles", "opensuse", "opensuse-tumbleweed"):
            pkg = "kernel-default" if distro in ("sles", "opensuse", "opensuse-tumbleweed") else "kernel"
            result = subprocess.run(
                ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", pkg],
                capture_output=True, text=True, timeout=1,
            )
            lines = result.stdout.strip().splitlines()
            return lines[-1] if lines else None
    except Exception:
        return None
    return None


def get_kernel_version(uname_r: Optional[str] = None) -> KernelVersion:
    if uname_r is None:
        uname_r = subprocess.check_output(["uname", "-r"], text=True).strip()
    return KernelVersion.parse(uname_r)


def get_changelog_source(distro: str, uname_r: str) -> dict:
    if distro in ("ubuntu", "debian"):
        return {"type": "gz", "path": f"/usr/share/doc/linux-image-{uname_r}/changelog.Debian.gz"}
    if distro in ("rhel", "almalinux", "rocky", "fedora", "centos"):
        return {"type": "rpm", "package": "kernel"}
    if distro in ("sles", "opensuse", "opensuse-tumbleweed"):
        return {"type": "rpm", "package": "kernel-default"}
    return {"type": "none"}
