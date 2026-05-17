## 1. プロジェクト初期設定

- [x] 1.1 `pyproject.toml`を作成し、パッケージ名・依存関係（paramiko）・エントリーポイント（`patch-checker`）を定義する
- [x] 1.2 `patch_checker/`ディレクトリ構造を作成する（`__init__.py`, `cli.py`, `detector.py`, `remediation.py`, `distro.py`, `cve_db.py`, `reporter.py`, `ssh.py`）
- [x] 1.3 `tests/`ディレクトリとpytestの基本設定（`pytest.ini`または`pyproject.toml`の`[tool.pytest]`）を作成する

## 2. CVEデータベース

- [x] 2.1 `patch_checker/data/cves.yaml`を作成し、5件のCVEメタデータ（通称・CVSS・影響バージョン範囲・暫定対策種別・対象モジュール/sysctlパラメータ・RECEIVEDフラグ・恒久対策コマンドテンプレート）を定義する
- [x] 2.2 `cve_db.py`にYAMLを読み込みCVEエントリを返す`load_cves()`関数と、CVE IDで引くユーティリティを実装する
- [x] 2.3 `tests/test_cve_db.py`に全5件のCVEが存在すること、RECEIVEDフラグが正しく設定されていることのテストを書く

## 3. ディストリビューション検知

- [x] 3.1 `distro.py`に`/etc/os-release`と`uname -r`から11種のディストリビューションを判定する`detect_distro()`を実装する（ubuntu/ubuntu-wsl2/debian/rhel/almalinux/rocky/fedora/centos/sles/opensuse/generic）
- [x] 3.2 `distro.py`に`uname -r`を解析して比較可能な`KernelVersion`（major/minor/patch）を返す`get_kernel_version()`を実装する
- [x] 3.3 `distro.py`にディストリビューション別のchangelogソース（gzipファイルパスまたはrpmコマンド）を返す`get_changelog_source()`を実装する
- [x] 3.4 `tests/test_distro.py`に各ディストリビューションの判定・カーネルバージョン解析・changelogソース解決のテストを書く（osリリースファイルのモックを使用）

## 4. 脆弱性検知

- [x] 4.1 `detector.py`にchangelogテキストからCVE IDをgrepする`grep_changelog(cve_id, source)`を実装する（gzipファイルとrpmコマンド出力の両方に対応）
- [x] 4.2 `detector.py`にchangelogグレップ→バージョン比較フォールバックの順で恒久対策ステータス（FIXED/VULNERABLE/MANUAL_CHECK_REQUIRED）を返す`detect_permanent_fix(cve, distro_info)`を実装する
- [x] 4.3 `detector.py`に`lsmod`出力から暫定対策ステータス（MITIGATED/NOT_MITIGATED）を返す`detect_module_mitigation(module_name)`を実装する
- [x] 4.4 `detector.py`に`sysctl`値から暫定対策ステータスを返す`detect_sysctl_mitigation(key, expected_value)`を実装する
- [x] 4.5 `detector.py`に全CVEを検知して結果リストを返す`detect_all(cves, distro_info)`を実装する
- [x] 4.6 `tests/test_detector.py`にchangelogグレップ・バージョン比較・モジュール検知・sysctl検知のテストを書く（コマンド実行のモックを使用）

## 5. 暫定対策の適用

- [x] 5.1 `remediation.py`に権限チェック（rootまたは実効UID=0）を行う`check_root()`を実装する。非rootの場合は使用方法を提示してSystemExitを発生させる
- [x] 5.2 `remediation.py`に`/sys/module/<name>/refcnt`を確認してモジュールの使用中状態をチェックする`check_module_refcnt(module_name)`を実装する
- [x] 5.3 `remediation.py`に`modprobe -r`でアンロードし`/etc/modprobe.d/patch-checker-<cve>.conf`にblacklistを書き込む`disable_module(module_name, cve_id, force=False)`を実装する
- [x] 5.4 `remediation.py`に`sysctl -w`と`/etc/sysctl.d/99-patch-checker.conf`への書き込みを行う`set_sysctl(key, value)`を実装する
- [x] 5.5 `remediation.py`にCVEごとに適切な暫定対策を選択・実行する`apply_mitigation(cve, force=False)`を実装する
- [x] 5.6 `tests/test_remediation.py`に権限チェック・モジュール使用中スキップ・強制適用・sysctl変更のテストを書く（コマンド実行のモックを使用）

## 6. 出力・レポート

- [x] 6.1 `reporter.py`にテキスト形式（ホスト情報ヘッダー＋CVE別ステータス表＋推奨アクション＋恒久対策コマンド提示）を出力する`format_text(results)`を実装する
- [x] 6.2 `reporter.py`にJSON形式（`host`/`kernel`/`distro`/`results`のJSONオブジェクト）を出力する`format_json(results)`を実装する
- [x] 6.3 `reporter.py`に結果に基づいて終了コード（0/1/2）を返す`exit_code(results)`を実装する
- [x] 6.4 `tests/test_reporter.py`にテキスト/JSON出力の形式と終了コードのテストを書く

## 7. CLIエントリーポイント

- [x] 7.1 `cli.py`にargparseベースのサブコマンド構造（`check`/`scan`）と全オプション（`--apply`/`--force`/`--json`/`--cve`/`--hosts`/`--user`/`--key`）を実装する
- [x] 7.2 `cli.py`の`check`サブコマンドで`detect_all()`を呼び出し、`--apply`時に`apply_mitigation()`を呼び出す処理フローを実装する
- [x] 7.3 `cli.py`の`scan`サブコマンドでホストリストを解決（コマンドライン引数/`--hosts`ファイル）する処理を実装する

## 8. SSHスキャン

- [x] 8.1 `ssh.py`にparamikoを使用してSSH接続し、リモートホストでコマンドを実行して結果を返す`SSHScanner`クラスを実装する（接続タイムアウト10秒、コマンドタイムアウト30秒）
- [x] 8.2 `ssh.py`にリモートホスト上でローカルスクリプトを実行する方式（スクリプト転送＋実行）で検知・適用を行う`scan_host(host, options)`を実装する
- [x] 8.3 `ssh.py`に接続失敗ホストをCONNECTION_ERRORとして記録しながら全ホストを処理する`scan_hosts(hosts, options)`を実装する
- [x] 8.4 `cli.py`の`scan`サブコマンドに`SSHScanner`を統合する
- [x] 8.5 `tests/test_ssh.py`に接続失敗・タイムアウト・部分失敗のテストを書く（paramikoのモックを使用）

## 9. 統合テストとドキュメント

- [x] 9.1 `README.md`を更新し、インストール方法・使用例・CVE一覧・ディストリビューション対応表を記載する
- [x] 9.2 `CLAUDE.md`を更新し、ビルドコマンド（`pip install -e .`）・テスト実行（`pytest`）・テスト単体実行（`pytest tests/test_detector.py`）を記載する
- [x] 9.3 全テストが`pytest`でパスすることを確認する
- [x] 9.4 `patch-checker --help`・`patch-checker check --help`・`patch-checker scan --help`が正常に動作することを確認する
