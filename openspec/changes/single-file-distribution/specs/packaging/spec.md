## ADDED Requirements

### Requirement: 単一ファイル配布物のビルド
システムは2種類の単一ファイル配布物をビルドできなければならない（SHALL）:
- `dist/patch-checker-check.pyz`: target host向けピュアPython zipapp。stdlibのみで動作し、モードA（ローカル検知・暫定対策適用）を提供する
- `dist/patch-checker-scan.pyz`: 管理ホスト向けshiv zipapp。paramikoを同梱し、モードB（SSH一括スキャン）を提供する

#### Scenario: ローカルでのビルド
- **WHEN** 開発者が`make build`を実行する
- **THEN** `dist/patch-checker-check.pyz`と`dist/patch-checker-scan.pyz`の両方が生成される

#### Scenario: check.pyzはstdlibのみで動作
- **WHEN** PyYAMLやparamikoが未インストールの環境で`python3 patch-checker-check.pyz check`を実行する
- **THEN** 正常に検知が完了する

#### Scenario: scan.pyzはparamiko同梱
- **WHEN** paramikoが未インストールの管理ホストで`python3 patch-checker-scan.pyz scan host1`を実行する
- **THEN** scan.pyz内に同梱されたparamikoを使ってSSH接続できる

#### Scenario: check.pyzのサイズ上限
- **WHEN** `make build`完了後
- **THEN** `patch-checker-check.pyz`のサイズは1MB以下である

### Requirement: ピュアPython zipapp（check.pyz）の仕様
システムは`python -m zipapp`または同等のstdlib機能でcheck.pyzをビルドしなければならない（SHALL）。check.pyzはPyYAML、paramikoその他の追加wheel依存を一切含んではならない（SHALL NOT）。エントリポイントは`patch_checker.cli:main`でなければならない（SHALL）。Pythonインタプリタは`/usr/bin/env python3`を指定しなければならない（SHALL）。

#### Scenario: check.pyzの実行
- **WHEN** Python 3.8+環境で`python3 patch-checker-check.pyz check --json`を実行する
- **THEN** JSON形式の検知結果が出力される

#### Scenario: check.pyzのスキャンサブコマンド使用時のエラー
- **WHEN** `python3 patch-checker-check.pyz scan host1`を実行する
- **THEN** 「scanコマンドはpatch-checker-scan.pyzまたは pip install 版で使用してください」というエラーメッセージが表示される

### Requirement: shiv zipapp（scan.pyz）の仕様
システムは`shiv`コマンドでscan.pyzをビルドしなければならない（SHALL）。scan.pyzはparamikoとその依存（cryptography等）を内部に同梱しなければならない（SHALL）。ビルドは再現可能（`--reproducible`相当）でなければならない（SHALL）。対象アーキテクチャはx86_64 Linuxである（SHALL）。

#### Scenario: scan.pyzのSSH接続
- **WHEN** paramikoがpip未インストールの管理ホストで`python3 patch-checker-scan.pyz scan host1`を実行する
- **THEN** SSH接続が成功し、検知結果が表示される

#### Scenario: scan.pyzでのモードA実行
- **WHEN** `python3 patch-checker-scan.pyz check`を実行する
- **THEN** scan.pyzでもモードAが利用でき、検知結果が表示される（scanモードに加えてcheckモードも提供）

### Requirement: 配布物の配布チャネル
システムはGitHub Releasesで配布物を提供しなければならない（SHALL）。タグpush（`v*`形式）をトリガーとしてGitHub Actionsが自動的に両.pyzをビルド・添付しなければならない（SHALL）。Releasesにはバージョン番号と各ファイルのSHA256チェックサムを記載しなければならない（SHALL）。

#### Scenario: タグpushでのリリース自動化
- **WHEN** `v0.2.0`タグをpushする
- **THEN** GitHub Actionsがビルドを実行し、`patch-checker-check.pyz`と`patch-checker-scan.pyz`がReleasesに添付される

#### Scenario: SHA256チェックサムの記載
- **WHEN** Releaseページを参照する
- **THEN** 各配布物のSHA256ハッシュが本文または別ファイル（`SHA256SUMS`）として記載されている

### Requirement: 配布物の利用手順
システムはREADMEに以下の配布物利用手順を記載しなければならない（SHALL）:
- `wget`/`curl` でGitHub Releasesからダウンロードする手順
- `scp` で手動転送する手順
- SHA256検証手順
- 実行コマンド例

#### Scenario: READMEの配布手順
- **WHEN** READMEを参照する
- **THEN** オフライン環境への配布手順セクションが存在し、wget/curl/scp/shasum コマンド例が含まれる
