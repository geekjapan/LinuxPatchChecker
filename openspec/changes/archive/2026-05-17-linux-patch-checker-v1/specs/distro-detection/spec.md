## ADDED Requirements

### Requirement: Linuxディストリビューションの判定
システムは実行環境のLinuxディストリビューションを`/etc/os-release`から判定しなければならない（SHALL）。以下の11種を識別しなければならない（SHALL）: Ubuntu, Debian, RHEL, AlmaLinux, Rocky Linux, Fedora, CentOS Stream, SLES, openSUSE, Ubuntu(WSL2), 汎用。

#### Scenario: Ubuntuの判定
- **WHEN** `/etc/os-release`の`ID=ubuntu`かつWSL2でない
- **THEN** ディストリビューション種別として`ubuntu`が返される

#### Scenario: Ubuntu WSL2の判定
- **WHEN** `/etc/os-release`の`ID=ubuntu`かつ`uname -r`に`microsoft`が含まれる
- **THEN** ディストリビューション種別として`ubuntu-wsl2`が返される

#### Scenario: RHEL系の判定
- **WHEN** `/etc/os-release`の`ID`が`rhel`/`almalinux`/`rocky`/`fedora`/`centos`のいずれか
- **THEN** 対応するディストリビューション種別が返される

#### Scenario: 未知ディストリビューションの判定
- **WHEN** `/etc/os-release`が存在しないか、IDが認識できない
- **THEN** ディストリビューション種別として`generic`が返される

### Requirement: カーネルバージョンの取得
システムは`uname -r`からカーネルバージョン文字列を取得し、比較可能な構造体として返さなければならない（SHALL）。

#### Scenario: カーネルバージョン取得
- **WHEN** `uname -r`が`6.1.169`を返す
- **THEN** major=6, minor=1, patch=169 として比較可能な形式で返される

### Requirement: changelogパスの解決
システムはディストリビューション種別に基づいてchangelogの取得方法を返さなければならない（SHALL）。

#### Scenario: Ubuntu/Debianのchangelogパス解決
- **WHEN** ディストリビューションがubuntu/debian
- **THEN** `/usr/share/doc/linux-image-$(uname -r)/changelog.Debian.gz`のパスが返される

#### Scenario: RHEL系のchangelogコマンド解決
- **WHEN** ディストリビューションがrhel/alma/rocky/fedora/centos
- **THEN** `rpm -q --changelog kernel`コマンドが返される

#### Scenario: 汎用/WSL2のchangelogフォールバック
- **WHEN** ディストリビューションがgenericまたはubuntu-wsl2
- **THEN** changelogなし（バージョン比較のみ）が返される
