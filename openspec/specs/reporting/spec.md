# Reporting

## Purpose

スキャン結果をテキスト（表形式）またはJSON形式で出力し、終了コードによって結果を表す。

## Requirements

### Requirement: テキスト形式の出力
システムはデフォルトでテキスト形式（表形式）の結果を標準出力に出力しなければならない（SHALL）。各CVEについてステータスと推奨アクションを明示しなければならない（SHALL）。

#### Scenario: テキスト出力の構造
- **WHEN** `patch-checker check`を実行する
- **THEN** ホスト名・カーネルバージョン・ディストリビューションを先頭に表示し、各CVEの暫定対策ステータス・恒久対策ステータス・推奨アクションを一覧表示する

#### Scenario: 要手動確認CVEの出力
- **WHEN** CVE-2026-46300がRECEIVED状態で出力される
- **THEN** 恒久対策欄に「MANUAL_CHECK_REQUIRED」と明示される

#### Scenario: 恒久対策コマンドの提示
- **WHEN** VULNERABLE状態のCVEが存在する
- **THEN** ディストリビューション別のカーネルアップグレードコマンドが提示される

### Requirement: JSON形式の出力
システムは`--json`フラグが指定された場合、結果をJSON形式で標準出力に出力しなければならない（SHALL）。JSONはパースエラーなしにjqや他のツールで処理可能でなければならない（SHALL）。

#### Scenario: JSON出力の構造
- **WHEN** `patch-checker check --json`を実行する
- **THEN** `{"host": "...", "kernel": "...", "distro": "...", "results": [...]}` 形式の有効なJSONが出力される

#### Scenario: 複数ホストのJSON出力（scanモード）
- **WHEN** `patch-checker scan --hosts hosts.txt --json`を実行する
- **THEN** ホストごとの結果を含む配列形式のJSONが出力される

#### Scenario: 接続失敗ホストのJSON出力
- **WHEN** SSH接続に失敗したホストが存在し`--json`を指定する
- **THEN** `{"host": "...", "status": "CONNECTION_ERROR", "error": "..."}` として含まれる

### Requirement: 終了コード
システムはスキャン結果に応じた終了コードを返さなければならない（SHALL）: 0=全CVE恒久対策済み、1=VULNERABLE/NOT_MITIGATEDのCVEあり、2=実行エラー。

#### Scenario: 全対策済みの終了コード
- **WHEN** 全CVEが恒久対策済みまたは暫定対策済み
- **THEN** 終了コード0で終了する

#### Scenario: 未対策CVEありの終了コード
- **WHEN** VULNERABLE/NOT_MITIGATEDのCVEが1件以上存在する
- **THEN** 終了コード1で終了する
