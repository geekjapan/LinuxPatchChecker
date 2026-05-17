## 1. CVEデータのJSON化

- [ ] 1.1 `patch_checker/data/cves.yaml` の内容を等価な `patch_checker/data/cves.json` に変換する（5件全CVE、affected_ranges、permanent_fix_commands等を保持）
- [ ] 1.2 `patch_checker/data/cves.schema.md` を作成し、各フィールドの意味とコメントを記載する（YAMLコメントの代替）
- [ ] 1.3 `cves.yaml` を削除する
- [ ] 1.4 `patch_checker/cve_db.py` の `load_cves()` を `yaml.safe_load` から `json.load` に切り替える
- [ ] 1.5 `pyproject.toml` から `pyyaml` 依存を削除する（または `[project.optional-dependencies]` の `scan` に移動）
- [ ] 1.6 既存テスト全パスを確認する（`pytest`）

## 2. ビルドツール

- [ ] 2.1 `scripts/build_check.sh` を作成し、`python3 -m zipapp` で `dist/patch-checker-check.pyz` をビルドするスクリプトを実装する（インタプリタ指定 `/usr/bin/env python3`、エントリポイント `patch_checker.cli:main`）
- [ ] 2.2 `scripts/build_scan.sh` を作成し、`shiv` で `dist/patch-checker-scan.pyz` をビルドするスクリプトを実装する（`--reproducible` フラグ、エントリポイント `patch_checker.cli:main`）
- [ ] 2.3 `Makefile` を作成し、`make build`、`make build-check`、`make build-scan`、`make clean`、`make checksums` ターゲットを定義する
- [ ] 2.4 `.gitignore` に `dist/` を追加する
- [ ] 2.5 開発依存に `shiv` を追加する（`pyproject.toml` の `[project.optional-dependencies]` の `build`）

## 3. CLIのzipapp対応

- [ ] 3.1 `patch_checker/cli.py` で `scan` サブコマンド実行時に `paramiko` の import を遅延ロードにする（モジュール先頭ではなく `cmd_scan()` 内で `from .ssh import scan_hosts` する）
- [ ] 3.2 `paramiko` ImportError 時に「scanコマンドは patch-checker-scan.pyz か pip install 版で使用してください」というエラーを表示するハンドリングを追加する
- [ ] 3.3 `tests/test_cli.py` を新規追加し、check.pyz相当の挙動（paramiko未インストール時のscanエラー）をモックで検証する

## 4. バージョン情報

- [ ] 4.1 `patch_checker/__init__.py` に `__version__ = "0.2.0"` を定義する
- [ ] 4.2 `cli.py` の最上位パーサーに `--version` 引数を追加し、`__version__` を出力するようにする
- [ ] 4.3 `pyproject.toml` の `version` フィールドを `0.2.0` に更新する
- [ ] 4.4 `tests/test_cli.py` に `--version` の動作テストを追加する

## 5. ローカルビルド検証

- [ ] 5.1 `make build-check` を実行し、`dist/patch-checker-check.pyz` が生成されることを確認する
- [ ] 5.2 `python3 dist/patch-checker-check.pyz check --json` が正常に動作することを確認する
- [ ] 5.3 `python3 dist/patch-checker-check.pyz scan host1` がエラーメッセージを表示することを確認する
- [ ] 5.4 `python3 dist/patch-checker-check.pyz --version` がバージョンを出力することを確認する
- [ ] 5.5 `pip install shiv && make build-scan` を実行し、`dist/patch-checker-scan.pyz` が生成されることを確認する
- [ ] 5.6 `python3 dist/patch-checker-scan.pyz check` および `scan` がともに動作することを確認する
- [ ] 5.7 `make checksums` で `dist/SHA256SUMS` が生成されることを確認する

## 6. GitHub Actions

- [ ] 6.1 `.github/workflows/release.yml` を作成する（`on: push: tags: ['v*']`、Python 3.11セットアップ、`pip install shiv`、`make build`、`make checksums`）
- [ ] 6.2 ワークフローに `softprops/action-gh-release@v2` を組み込み、`dist/patch-checker-check.pyz` `dist/patch-checker-scan.pyz` `dist/SHA256SUMS` をRelease assetとしてアップロードする
- [ ] 6.3 ワークフローでRelease本文に各ファイルのSHA256を追記するスクリプトを追加する

## 7. ドキュメント

- [ ] 7.1 `README.md` に「オフライン環境での配布」セクションを追加し、wget/curl/scp/shasum の手順を記載する
- [ ] 7.2 README に `patch-checker-check.pyz` と `patch-checker-scan.pyz` の使い分け（target host用とmanagement host用）を表で記載する
- [ ] 7.3 `CLAUDE.md` の Build セクションに `make build` と `dist/*.pyz` の生成を追記する
- [ ] 7.4 README に CVEデータの編集方法（`cves.json` 直編集、`cves.schema.md` 参照）を記載する

## 8. 統合検証

- [ ] 8.1 `pytest` で全テストパス確認
- [ ] 8.2 `make clean && make build` で両.pyzを再現可能にビルドできることを確認する
- [ ] 8.3 ビルドした `patch-checker-check.pyz` を一時ディレクトリにコピーして単独で実行できることを確認する（zipappの自己完結性確認）
- [ ] 8.4 `python3 -c "import sys; sys.path.insert(0,'dist/patch-checker-check.pyz'); from patch_checker import __version__; print(__version__)"` でzipapp内部からのimportを確認する
