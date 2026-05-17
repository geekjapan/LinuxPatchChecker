## ADDED Requirements

### Requirement: ローカルスキャンの実行
システムは`patch-checker check`コマンドでローカルホストの全CVE対策状況を検知しなければならない（SHALL）。non-rootで実行可能でなければならない（SHALL）。

#### Scenario: 通常の検知実行
- **WHEN** `patch-checker check`を実行する
- **THEN** 5件のCVEそれぞれについて暫定対策・恒久対策のステータスと推奨アクションが出力される

#### Scenario: 特定CVEのみ検知
- **WHEN** `patch-checker check --cve CVE-2026-31431`を実行する
- **THEN** CVE-2026-31431のみのステータスが出力される

#### Scenario: --applyなしでの実行（検知のみ）
- **WHEN** `--apply`なしで`patch-checker check`を実行する
- **THEN** ステータスの報告のみ行われ、システムへの変更は一切行われない

### Requirement: ローカル暫定対策の適用
システムは`--apply`フラグと共に実行された場合、未適用の暫定対策を自動適用しなければならない（SHALL）。

#### Scenario: --applyでの暫定対策適用
- **WHEN** `sudo patch-checker check --apply`を実行する
- **THEN** 未適用の暫定対策が適用され、各CVEの適用結果が報告される

#### Scenario: --applyで全暫定対策適用済みの場合
- **WHEN** `sudo patch-checker check --apply`を実行し全暫定対策が既に適用済み
- **THEN** 「全暫定対策適用済み」と報告し、変更は行わない

### Requirement: ヘルプの表示
システムは`patch-checker --help`および`patch-checker check --help`で利用方法を表示しなければならない（SHALL）。

#### Scenario: ヘルプ表示
- **WHEN** `patch-checker --help`を実行する
- **THEN** コマンド一覧とオプションの説明が出力される
