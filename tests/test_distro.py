import pytest
from patch_checker.distro import KernelVersion, detect_distro, get_changelog_source, get_kernel_version

UBUNTU_RELEASE = 'ID=ubuntu\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
DEBIAN_RELEASE = 'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n'
RHEL_RELEASE = 'ID="rhel"\nNAME="Red Hat Enterprise Linux"\nVERSION_ID="9"\n'
ALMA_RELEASE = 'ID="almalinux"\nNAME="AlmaLinux"\nVERSION_ID="9"\n'
ROCKY_RELEASE = 'ID="rocky"\nNAME="Rocky Linux"\nVERSION_ID="9"\n'
FEDORA_RELEASE = 'ID=fedora\nNAME="Fedora Linux"\nVERSION_ID="40"\n'
CENTOS_RELEASE = 'ID="centos"\nNAME="CentOS Stream"\nVERSION_ID="9"\n'
SLES_RELEASE = 'ID="sles"\nNAME="SLES"\nVERSION_ID="15"\n'
OPENSUSE_RELEASE = 'ID="opensuse-leap"\nNAME="openSUSE Leap"\nVERSION_ID="15.5"\n'
GENERIC_RELEASE = ''


class TestKernelVersion:
    def test_parse_simple(self):
        kv = KernelVersion.parse("6.1.169")
        assert kv.major == 6
        assert kv.minor == 1
        assert kv.patch == 169

    def test_parse_with_suffix(self):
        kv = KernelVersion.parse("6.1.169-generic")
        assert kv == KernelVersion(6, 1, 169)

    def test_parse_ubuntu_style(self):
        kv = KernelVersion.parse("5.15.0-73-generic")
        assert kv.major == 5
        assert kv.minor == 15
        assert kv.patch == 0

    def test_comparison(self):
        assert KernelVersion(6, 1, 169) < KernelVersion(6, 1, 170)
        assert KernelVersion(6, 1, 170) >= KernelVersion(6, 1, 170)
        assert KernelVersion(5, 15, 0) < KernelVersion(6, 1, 0)

    def test_parse_invalid(self):
        with pytest.raises(ValueError):
            KernelVersion.parse("invalid")

    def test_str(self):
        assert str(KernelVersion(6, 1, 169)) == "6.1.169"


class TestDetectDistro:
    def test_ubuntu(self):
        info = detect_distro(UBUNTU_RELEASE, "6.8.0-40-generic")
        assert info.distro == "ubuntu"

    def test_ubuntu_wsl2(self):
        info = detect_distro(UBUNTU_RELEASE, "5.15.153.1-microsoft-standard-WSL2")
        assert info.distro == "ubuntu-wsl2"

    def test_debian(self):
        info = detect_distro(DEBIAN_RELEASE, "6.1.99-1")
        assert info.distro == "debian"

    def test_rhel(self):
        info = detect_distro(RHEL_RELEASE, "5.14.0-427.13.1.el9_4.x86_64")
        assert info.distro == "rhel"

    def test_almalinux(self):
        info = detect_distro(ALMA_RELEASE, "5.14.0-427.13.1.el9_4.x86_64")
        assert info.distro == "almalinux"

    def test_rocky(self):
        info = detect_distro(ROCKY_RELEASE, "5.14.0-427.13.1.el9_4.x86_64")
        assert info.distro == "rocky"

    def test_fedora(self):
        info = detect_distro(FEDORA_RELEASE, "6.8.9-300.fc40.x86_64")
        assert info.distro == "fedora"

    def test_centos(self):
        info = detect_distro(CENTOS_RELEASE, "5.14.0-427.13.1.el9_4.x86_64")
        assert info.distro == "centos"

    def test_sles(self):
        info = detect_distro(SLES_RELEASE, "5.14.21-150500.55.65-default")
        assert info.distro == "sles"

    def test_opensuse(self):
        info = detect_distro(OPENSUSE_RELEASE, "5.14.21-150500.55.65-default")
        assert info.distro == "opensuse"

    def test_generic(self):
        info = detect_distro(GENERIC_RELEASE, "6.1.0")
        assert info.distro == "generic"

    def test_kernel_version_parsed(self):
        info = detect_distro(UBUNTU_RELEASE, "6.1.169-generic")
        assert info.kernel_version == KernelVersion(6, 1, 169)


class TestChangelogSource:
    def test_ubuntu(self):
        src = get_changelog_source("ubuntu", "6.1.169-generic")
        assert src["type"] == "gz"
        assert "6.1.169-generic" in src["path"]

    def test_debian(self):
        src = get_changelog_source("debian", "6.1.99-1")
        assert src["type"] == "gz"

    def test_rhel(self):
        src = get_changelog_source("rhel", "5.14.0")
        assert src["type"] == "rpm"
        assert src["package"] == "kernel"

    def test_sles(self):
        src = get_changelog_source("sles", "5.14.21")
        assert src["type"] == "rpm"
        assert src["package"] == "kernel-default"

    def test_generic(self):
        src = get_changelog_source("generic", "6.1.0")
        assert src["type"] == "none"

    def test_wsl2(self):
        src = get_changelog_source("ubuntu-wsl2", "5.15.153.1-microsoft")
        assert src["type"] == "none"
