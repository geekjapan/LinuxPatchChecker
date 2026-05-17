## ADDED Requirements

### Requirement: SSH一括スキャンの実行
システムは`patch-checker scan`コマンドで複数ホストにSSH接続し、各ホストの全CVE対策状況を検知しなければならない（SHALL）。

#### Scenario: 複数ホストをコマンドライン引数で指定
- **WHEN** `patch-checker scan host1 host2 host3`を実行する
- **THEN** 3ホストにSSH接続し、各ホストの検知結果が出力される

#### Scenario: ホストファイルを指定
- **WHEN** `patch-checker scan --hosts hosts.txt`を実行する（1行1ホスト形式）
- **THEN** ファイル内の全ホストにSSH接続し、検知結果が出力される

#### Scenario: 空行・コメント行を含むホストファイル
- **WHEN** `--hosts`で指定したファイルに空行や`#`始まりのコメント行が含まれる
- **THEN** それらをスキップして有効なホストのみ処理する

### Requirement: SSH接続オプション
システムは`--user`と`--key`オプションでSSH接続情報を指定できなければならない（SHALL）。指定がない場合はSSHエージェントおよび`~/.ssh/config`の設定に委ねなければならない（SHALL）。

#### Scenario: --userと--keyを指定して接続
- **WHEN** `patch-checker scan host1 --user admin --key ~/.ssh/id_rsa`を実行する
- **THEN** 指定のユーザーと鍵でSSH接続し、検知を実行する

#### Scenario: オプション未指定でのSSHエージェント利用
- **WHEN** `--user`/`--key`なしで`patch-checker scan host1`を実行する
- **THEN** SSHエージェントまたは`~/.ssh/config`の設定を使用して接続する

### Requirement: SSH接続失敗時の処理
システムはSSH接続に失敗したホストを残りのホストの処理を継続しながらエラーとして記録しなければならない（SHALL）。

#### Scenario: 一部ホストへの接続失敗
- **WHEN** 3ホスト中1ホストへのSSH接続がタイムアウトする
- **THEN** 残り2ホストの処理を続行し、失敗したホストを`CONNECTION_ERROR`として出力する

#### Scenario: 接続タイムアウト
- **WHEN** SSHホストへの接続が10秒以内に確立しない
- **THEN** タイムアウトエラーとして記録し次のホストへ進む

### Requirement: SSH一括スキャンでの暫定対策適用
システムは`--apply`フラグと共に実行された場合、各リモートホストで暫定対策を適用しなければならない（SHALL）。リモートホスト上での実行にsudoが必要な場合は自動使用を試みてはならない（SHALL NOT）。

#### Scenario: SSH経由での--apply実行
- **WHEN** `patch-checker scan --hosts hosts.txt --apply`を実行する
- **THEN** 各ホストでrootまたはsudoでの実行を確認し、権限がある場合のみ適用する
