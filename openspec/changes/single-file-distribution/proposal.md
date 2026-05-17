## Why

本番Linuxサーバーの一部はインターネット接続不可・限定的なファイル転送経路（USB/scp/踏み台経由のみ）で運用される。`pip install paramiko pyyaml` ができず、多数のファイルを手動転送するのも運用負担が大きい。`wget`/`curl`/`scp` 1コマンドで完結する単一ファイル配布があれば、未接続環境への展開コストを大幅に下げられる。

## What Changes

- `patch-checker-check.pyz`（~50KB、ピュアPython zipapp）: target host向けモードA専用バイナリ。stdlib のみで動作
- `patch-checker-scan.pyz`（~10MB、shiv zipapp）: 管理ホスト向けモードB専用バイナリ。paramiko同梱
- CVEデータを `cves.yaml` から `cves.json` に変更し、PyYAML依存を `check.pyz` から排除
- `Makefile` および `scripts/build.sh` を追加。`make build` で両.pyzを生成
- GitHub Actionsで release タグ時に両.pyzを自動ビルドし、Releasesに添付
- README にwget/curl/scp での配布手順を追記
- 既存の `pip install -e .` 開発モードと `patch-checker` エントリポイントは維持

## Capabilities

### New Capabilities

- `packaging`: zipapp/shivによる単一ファイル配布物（.pyz）のビルド、配布、実行サポート

### Modified Capabilities

- `cve-database`: データソースを `cves.yaml` から `cves.json` に変更（PyYAML依存排除のため）
- `local-check`: `python3 patch-checker-check.pyz check` 形式の実行を追加サポート

## Impact

- **コード**: `patch_checker/data/cves.yaml` → `patch_checker/data/cves.json` への変換、`cve_db.py` のローダー差し替え、新規 `scripts/build.sh` と `Makefile`、`.github/workflows/release.yml`
- **依存関係**: `check.pyz` から PyYAML を除去。`pip install` 版および `scan.pyz` ではPyYAMLは引き続き利用可能（互換性のため）
- **配布**: GitHub Releasesに `patch-checker-check.pyz` / `patch-checker-scan.pyz` を添付
- **ドキュメント**: README に「オフライン環境での配布」セクションを追加
- **既存テスト**: `cves.yaml` → `cves.json` 変更に伴いテストを更新（ローダーパスのみ）
