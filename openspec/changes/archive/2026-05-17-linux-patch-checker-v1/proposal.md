## Why

2026年4月〜5月にかけて、Linuxカーネルに5件のLocal Privilege Escalation（LPE）脆弱性が相次いで公開された（CVE-2026-31431/43284/43500/46300/46333）。これらは複数のカーネルサブシステムに跨り、広範なディストリビューションに影響するため、各ホストの対策状況を迅速かつ一括して把握・適用するツールが必要である。

## What Changes

- `patch-checker check` コマンド: ローカルホストの各CVE対策状況を検知・報告
- `patch-checker scan` コマンド: SSHで複数ホストを一括スキャン
- 暫定対策の自動適用（`--apply`）: 危険なカーネルモジュールのアンロード/ブラックリスト登録、sysctl変更
- 恒久対策の提示: パッチ適用済みカーネルへのアップグレードコマンドを提示
- テキスト/JSON出力対応

## Capabilities

### New Capabilities

- `cve-database`: 5件のCVEメタデータ（影響バージョン範囲、暫定対策手順、恒久対策コマンド）の定義と管理
- `distro-detection`: 11種のLinuxディストリビューション判定とカーネルパッケージ情報取得
- `vulnerability-detection`: 各CVEの暫定対策・恒久対策の適用状況を検知（changelogグレップ＋バージョン比較）
- `remediation`: 暫定対策（モジュール無効化、sysctl変更）の自動適用と権限チェック
- `local-check`: ローカルホスト向けCLIコマンド（`patch-checker check`）
- `ssh-scan`: SSH経由の複数ホスト一括スキャン（`patch-checker scan`）
- `reporting`: テキスト/JSON形式の結果出力

### Modified Capabilities

## Impact

- **新規Pythonパッケージ**: `patch_checker/` モジュール群、`pyproject.toml`
- **外部依存**: `paramiko`（SSHスキャン用）
- **権限要件**: 検知はnon-root可。暫定対策適用にはroot/sudo必須
- **対象環境**: Ubuntu, Debian, RHEL, AlmaLinux, Rocky Linux, Fedora, CentOS Stream, SLES, openSUSE, Ubuntu(WSL2), 汎用Linux
