## ADDED Requirements

### Requirement: 暫定対策の自動適用
システムは`--apply`フラグが指定された場合、各CVEの暫定対策を自動適用しなければならない（SHALL）。適用にはrootまたはsudo権限が必要であり、非root/非sudoで`--apply`が指定された場合は使用方法を提示して終了しなければならない（SHALL）。

#### Scenario: rootで--applyを実行
- **WHEN** rootユーザーが`--apply`を指定して実行する
- **THEN** 暫定対策が自動適用され、適用結果が出力される

#### Scenario: 非rootで--applyを実行
- **WHEN** 非rootユーザーがsudoなしで`--apply`を指定して実行する
- **THEN** エラーメッセージと正しい使用方法（`sudo patch-checker check --apply`）を出力して終了する

### Requirement: モジュールのアンロードとブラックリスト登録
システムは対象カーネルモジュールを`modprobe -r`でアンロードし、`/etc/modprobe.d/`にblacklistエントリを作成しなければならない（SHALL）。対象モジュール: algif_aead（CVE-2026-31431）、esp4/esp6（CVE-2026-43284/46300）、rxrpc（CVE-2026-43500/46300）。

#### Scenario: 未使用モジュールのアンロード成功
- **WHEN** refcnt=0のモジュールに対して適用を実行する
- **THEN** モジュールがアンロードされ、blacklistファイルが作成され、成功が報告される

#### Scenario: 使用中モジュールのスキップ（--forceなし）
- **WHEN** refcnt>0のモジュールに対して`--force`なしで適用を実行する
- **THEN** 警告メッセージを出力してスキップし、ツールは正常終了する

#### Scenario: 使用中モジュールの強制アンロード（--force）
- **WHEN** refcnt>0のモジュールに対して`--force`を指定して適用を実行する
- **THEN** 強制アンロードを試み、結果（成功/失敗）を報告する

#### Scenario: 既にアンロード済みモジュール
- **WHEN** 対象モジュールが既にlsmodに存在しない
- **THEN** アンロードをスキップし、blacklistエントリのみ確認・作成する

### Requirement: sysctlパラメータの変更
システムはCVE-2026-46333の暫定対策として`kernel.yama.ptrace_scope=3`を設定しなければならない（SHALL）。`sysctl -w`による即時適用と`/etc/sysctl.d/`への永続化の両方を実施しなければならない（SHALL）。

#### Scenario: ptrace_scope設定の適用
- **WHEN** CVE-2026-46333の暫定対策を適用する
- **THEN** `sysctl -w kernel.yama.ptrace_scope=3`を実行し、`/etc/sysctl.d/99-patch-checker.conf`に書き込む

#### Scenario: 既に設定済みの場合
- **WHEN** `kernel.yama.ptrace_scope`が既に3
- **THEN** スキップし、既に適用済みである旨を報告する

### Requirement: 恒久対策コマンドの提示
システムはディストリビューション別の恒久対策コマンドを提示しなければならない（SHALL）。コマンドの自動実行は行ってはならない（SHALL NOT）。

#### Scenario: Ubuntu向け恒久対策コマンドの提示
- **WHEN** Ubuntuで恒久対策コマンドを取得する
- **THEN** `sudo apt update && sudo apt install --only-upgrade linux-image-$(uname -r)` 相当のコマンドが提示される

#### Scenario: RHEL系向け恒久対策コマンドの提示
- **WHEN** RHEL/Alma/Rocky/CentOSで恒久対策コマンドを取得する
- **THEN** `sudo dnf update kernel` 相当のコマンドが提示される
