## ADDED Requirements

### Requirement: 検知信頼性の出力
システムはテキスト出力およびJSON出力に各CVEの検知信頼性（HIGH/MEDIUM/LOW）を含めなければならない（SHALL）。テキスト出力では各CVE行に信頼性ラベル（例: `[信頼性: HIGH]`）を付加し、JSON出力では`detection_confidence`キーで値を提供しなければならない（SHALL）。

#### Scenario: テキスト出力に信頼性が含まれる
- **WHEN** `patch-checker check`を実行する
- **THEN** 各CVE行に`[信頼性: HIGH]`/`[信頼性: MEDIUM]`/`[信頼性: LOW]`のいずれかが含まれる

#### Scenario: JSON出力に信頼性キーが含まれる
- **WHEN** `patch-checker check --json`を実行する
- **THEN** 各結果オブジェクトに`detection_confidence`キーが含まれ、値は`HIGH`/`MEDIUM`/`LOW`のいずれか

### Requirement: 低信頼度環境への警告メッセージ
システムは`changelog_source.type == 'none'`の環境（WSL2、汎用、自前ビルドカーネル）またはELSモード環境では、出力の冒頭に「ベンダーアドバイザリの手動確認を推奨します」と明示する警告を出さなければならない（SHALL）。

#### Scenario: WSL2環境での警告表示
- **WHEN** Ubuntu WSL2環境で`patch-checker check`を実行する
- **THEN** 出力に「ベンダーアドバイザリの手動確認を推奨します」を含む警告が表示される

#### Scenario: 汎用環境での警告表示
- **WHEN** 汎用ディストリで実行する
- **THEN** 同様の警告が表示される

#### Scenario: ELSモード環境での警告表示
- **WHEN** RHEL 7 ELS環境で実行する
- **THEN** 「ELSモード検知。バックポートの可能性があるため手動確認を推奨」と表示される

#### Scenario: 通常環境では警告非表示
- **WHEN** Ubuntu 24.04環境で実行する
- **THEN** 上記の警告は表示されない

## MODIFIED Requirements

### Requirement: テキスト形式の出力
システムはデフォルトでテキスト形式（表形式）の結果を標準出力に出力しなければならない（SHALL）。各CVEについてステータス・推奨アクション・**検知信頼性**を明示しなければならない（SHALL）。

#### Scenario: テキスト出力の構造
- **WHEN** `patch-checker check`を実行する
- **THEN** ホスト名・カーネルバージョン・ディストリビューションを先頭に表示し、各CVEの暫定対策ステータス・恒久対策ステータス・検知信頼性・推奨アクションを一覧表示する

#### Scenario: 要手動確認CVEの出力
- **WHEN** CVE-2026-46300がRESERVED状態で出力される
- **THEN** 恒久対策欄に「MANUAL_CHECK_REQUIRED」と明示される

#### Scenario: 恒久対策コマンドの提示
- **WHEN** VULNERABLE状態のCVEが存在する
- **THEN** ディストリビューション別のカーネルアップグレードコマンドが提示される

#### Scenario: 信頼性LOWでの注意喚起
- **WHEN** 信頼性LOWの判定が含まれる
- **THEN** 該当CVE行に`[信頼性: LOW]`が表示され、推奨アクションに「手動確認」を含む

### Requirement: JSON形式の出力
システムは`--json`フラグが指定された場合、結果をJSON形式で標準出力に出力しなければならない（SHALL）。JSONはパースエラーなしにjqや他のツールで処理可能でなければならない（SHALL）。各CVE結果には**`detection_confidence`フィールド**を含めなければならない（SHALL）。

#### Scenario: JSON出力の構造
- **WHEN** `patch-checker check --json`を実行する
- **THEN** `{"host": "...", "kernel": "...", "distro": "...", "is_els": bool, "package_kernel_version": "...", "results": [...]}` 形式の有効なJSONが出力される

#### Scenario: 結果オブジェクトのフィールド
- **WHEN** `patch-checker check --json`を実行する
- **THEN** 各結果オブジェクトに`cve_id`/`nickname`/`mitigation_status`/`permanent_fix_status`/`recommended_action`/`detection_method`/`notes`/`detection_confidence`が含まれる

#### Scenario: 複数ホストのJSON出力（scanモード）
- **WHEN** `patch-checker scan --hosts hosts.txt --json`を実行する
- **THEN** ホストごとの結果を含む配列形式のJSONが出力される

#### Scenario: 接続失敗ホストのJSON出力
- **WHEN** SSH接続に失敗したホストが存在し`--json`を指定する
- **THEN** `{"host": "...", "status": "CONNECTION_ERROR", "error": "..."}` として含まれる
