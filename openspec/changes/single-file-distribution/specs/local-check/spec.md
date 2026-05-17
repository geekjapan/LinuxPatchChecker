## ADDED Requirements

### Requirement: zipapp経由でのモードA実行
システムは`python3 patch-checker-check.pyz check`形式でモードA（ローカル検知）を実行できなければならない（SHALL）。挙動は`pip install`版の`patch-checker check`と同一でなければならない（SHALL）。

#### Scenario: zipapp経由のローカル検知
- **WHEN** `python3 patch-checker-check.pyz check`を実行する
- **THEN** `patch-checker check`と同じ検知結果が出力される

#### Scenario: zipapp経由の--applyフラグ
- **WHEN** `sudo python3 patch-checker-check.pyz check --apply`を実行する
- **THEN** 暫定対策が適用される（pip install版と同等の挙動）

#### Scenario: zipapp経由の--json出力
- **WHEN** `python3 patch-checker-check.pyz check --json`を実行する
- **THEN** pip install版と同じJSON形式が出力される

### Requirement: check.pyzでのscanサブコマンド非対応
システムは`patch-checker-check.pyz`で`scan`サブコマンドが指定された場合、明示的なエラーメッセージを表示して終了しなければならない（SHALL）。これはcheck.pyzがparamiko非同梱であることに由来する制限である。

#### Scenario: check.pyzでscanを誤実行
- **WHEN** `python3 patch-checker-check.pyz scan host1`を実行する
- **THEN** 「scanコマンドはpatch-checker-scan.pyzまたはpip install版で使用してください」というエラーメッセージを出力し、終了コード2で終了する
