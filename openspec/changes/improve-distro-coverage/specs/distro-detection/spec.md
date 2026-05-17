## ADDED Requirements

### Requirement: ディストリビューション固有のパッケージバージョン取得
システムはUbuntu/Debian環境で`dpkg-query -W -f '${Version}' linux-image-$(uname -r)`を使用してパッケージバージョン文字列を取得しなければならない（SHALL）。RHEL系環境では`rpm -q --qf '%{VERSION}-%{RELEASE}' kernel`を使用しなければならない（SHALL）。取得に失敗した場合は`None`を返し、`uname -r`へのフォールバックを許容しなければならない（SHALL）。

#### Scenario: Ubuntu環境でのパッケージバージョン取得
- **WHEN** ubuntuディストリビューションで`dpkg-query`が`5.15.0-73.80~20.04.1`を返す
- **THEN** パッケージバージョン文字列として`5.15.0-73.80~20.04.1`が返される

#### Scenario: RHEL環境でのパッケージバージョン取得
- **WHEN** rhelディストリビューションで`rpm -q`が成功する
- **THEN** パッケージバージョン文字列が返される

#### Scenario: dpkg-query失敗時のフォールバック
- **WHEN** `dpkg-query`コマンドが失敗（パッケージが見つからない等）
- **THEN** `None`が返され、エラーは発生しない

#### Scenario: 汎用環境でのパッケージバージョン取得スキップ
- **WHEN** ディストリビューションが`generic`または`ubuntu-wsl2`
- **THEN** `None`が返される

### Requirement: DistroInfoへのELSモード・パッケージバージョンの組み込み
システムは`DistroInfo`構造体に`is_els: bool`と`package_kernel_version: Optional[str]`フィールドを追加しなければならない（SHALL）。これらは`detect_distro()`実行時に自動的に設定されなければならない（SHALL）。

#### Scenario: DistroInfoに新フィールドが含まれる
- **WHEN** `detect_distro()`を呼び出す
- **THEN** 戻り値の`DistroInfo`に`is_els`と`package_kernel_version`が含まれる

## MODIFIED Requirements

### Requirement: Linuxディストリビューションの判定
システムは実行環境のLinuxディストリビューションを`/etc/os-release`から判定しなければならない（SHALL）。以下の11種を識別しなければならない（SHALL）: Ubuntu, Debian, RHEL, AlmaLinux, Rocky Linux, Fedora, CentOS Stream, SLES, openSUSE, Ubuntu(WSL2), 汎用。同時に`/etc/os-release`の`VERSION_ID`からELSモード（拡張サポート期間中の古いバージョン）かどうかを判定しなければならない（SHALL）。

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

#### Scenario: ELSモードの同時判定
- **WHEN** `/etc/os-release`の`ID=rhel`かつ`VERSION_ID="7"`
- **THEN** ディストリビューション種別`rhel`に加え、ELSモードフラグも`True`として返される
