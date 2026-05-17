## 1. CVEデータスキーマ拡張

- [ ] 1.1 `patch_checker/data/cves.yaml`の各CVEエントリに`version_comparison_reliable_for`フィールドを追加する（CVE-2026-31431/43284/43500: `[generic, fedora, debian, opensuse-tumbleweed]`、CVE-2026-46300/46333: 空配列）
- [ ] 1.2 `patch_checker/cve_db.py`の`CVEEntry`データクラスに`version_comparison_reliable_for: List[str]`フィールドを追加し、ローダーで読み取る
- [ ] 1.3 `tests/test_cve_db.py`に信頼マップフィールドの読み取りテストを追加する

## 2. ELS/LTSSモード判定

- [ ] 2.1 `patch_checker/distro.py`に`ELS_DISTROS`定数（`{(distro, version_id): True}`形式）を定義する。初期エントリ: rhel/7, centos/7, sles/12, ubuntu/16.04, ubuntu/18.04
- [ ] 2.2 `distro.py`に`is_els_distro(distro_id, version_id) -> bool`関数を追加する
- [ ] 2.3 `DistroInfo`データクラスに`is_els: bool`フィールドを追加し、`detect_distro()`で自動設定する
- [ ] 2.4 `tests/test_distro.py`にELS判定のテスト（rhel/7, sles/12, ubuntu/16.04, ubuntu/24.04）を追加する

## 3. パッケージバージョン取得

- [ ] 3.1 `distro.py`に`get_package_kernel_version(distro, uname_r) -> Optional[str]`関数を追加し、Ubuntu/Debianでは`dpkg-query -W -f '${Version}' linux-image-<uname_r>`、RHEL系では`rpm -q --qf '%{VERSION}-%{RELEASE}' kernel`を実行する（タイムアウト1秒、失敗時はNone）
- [ ] 3.2 `DistroInfo`データクラスに`package_kernel_version: Optional[str]`フィールドを追加し、`detect_distro()`で自動取得する
- [ ] 3.3 `tests/test_distro.py`にパッケージバージョン取得（成功・失敗・スキップ）のテストを追加する（subprocessモック使用）

## 4. 検知信頼性スコア

- [ ] 4.1 `patch_checker/detector.py`に`Confidence`列挙型相当の定数（`HIGH = "HIGH"`, `MEDIUM = "MEDIUM"`, `LOW = "LOW"`）を追加する
- [ ] 4.2 `CVEResult`データクラスに`detection_confidence: str`フィールドを追加する
- [ ] 4.3 `detector.py`に信頼性スコアを算出する`_compute_confidence(cve, distro_info, changelog_hit)`内部関数を実装する（HIGH/MEDIUM/LOW判定ロジック）
- [ ] 4.4 `detect_permanent_fix()`を更新し、信頼性がLOWかつFIXED判定の場合は`MANUAL_CHECK_REQUIRED`に格上げする。戻り値に信頼性スコアを含めるよう拡張
- [ ] 4.5 `detect_all()`内で信頼性スコアを`CVEResult`に設定する
- [ ] 4.6 `tests/test_detector.py`に信頼性スコア算出のテスト（HIGH/MEDIUM/LOW 各ケース）と格上げロジックのテストを追加する

## 5. 出力の更新

- [ ] 5.1 `patch_checker/reporter.py`の`format_text()`を更新し、各CVE行に`[信頼性: HIGH/MEDIUM/LOW]`を表示する
- [ ] 5.2 `reporter.py`の`format_json()`を更新し、各結果オブジェクトに`detection_confidence`を、トップレベルに`is_els`/`package_kernel_version`を含める
- [ ] 5.3 `reporter.py`に環境警告メッセージ生成関数`_environment_warning(distro_info) -> Optional[str]`を追加し、WSL2/汎用/ELS環境で適切な警告文を返す
- [ ] 5.4 `format_text()`の出力先頭に警告メッセージを追加する
- [ ] 5.5 `tests/test_reporter.py`に信頼性表示・警告メッセージのテストを追加する

## 6. v1テストの期待値更新

- [ ] 6.1 `tests/test_detector.py`の`TestDetectAll::test_result_has_required_fields`に`detection_confidence`の検証を追加する
- [ ] 6.2 `tests/test_detector.py`の既存テストでUbuntu環境のFIXED判定がMANUAL_CHECK_REQUIREDに格上げされるケースを追加する
- [ ] 6.3 `tests/test_reporter.py`の既存JSONテストで`detection_confidence`キーの存在を確認するよう更新する

## 7. ドキュメント更新

- [ ] 7.1 `README.md`に「検知信頼性」セクションを追加し、HIGH/MEDIUM/LOWの判定基準とディストリ別の信頼性表を記載する
- [ ] 7.2 `patch_checker/data/cves.yaml`のヘッダコメントに`version_comparison_reliable_for`の判断基準を記載する
- [ ] 7.3 `CLAUDE.md`の「検知フロー」セクションを更新し、信頼性スコアと格上げロジックを反映する

## 8. 統合検証

- [ ] 8.1 `pytest`で全テストがパスすることを確認する
- [ ] 8.2 `patch-checker check`がUbuntu/汎用環境で適切に信頼性表示を行うことを手動確認する
- [ ] 8.3 `patch-checker check --json | jq '.results[0].detection_confidence'`で新フィールドが取得できることを確認する
