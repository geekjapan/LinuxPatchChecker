## Context

2026年4〜5月に公開された5件のLinuxカーネルLPE脆弱性（CopyFail/DirtyFrag/Fragnesia/ssh-keysign-pwn）に対し、11種のディストリビューションで対策状況を検知・適用するPythonツールを新規開発する。既存コードベースは存在しない。

対象CVEはカーネルモジュール（algif_aead/esp4/esp6/rxrpc）とsysctlパラメータに起因する。暫定対策はモジュール無効化またはsysctl変更で実施可能。恒久対策はカーネルアップグレードだが、本ツールでは自動適用せず提示のみとする。

## Goals / Non-Goals

**Goals:**
- 5件のCVEについて暫定対策・恒久対策の適用状況を検知
- 暫定対策（モジュール無効化・sysctl変更）を`--apply`で自動適用
- ローカル実行（モードA）とSSH一括スキャン（モードB）の両対応
- 11種のディストリビューション対応（changelog grep + バージョン比較による恒久対策判定）
- テキスト/JSON出力

**Non-Goals:**
- カーネルアップグレードの自動実行
- ディストリビューション別バックポートの事前バージョン対応表（changelogグレップで代替）
- CVE-2026-46300（Fragnesia/RESERVED）の自動恒久対策判定
- Windows/macOS対応
- パッケージマネージャーによる依存関係管理（pip以外）

## Decisions

### D1: 言語はPython 3

**理由**: SSH接続（paramiko）、バージョン比較、ディストリビューション判定ロジックの複雑さに対し、BashよりPythonが適切。Ubuntu/RHEL/SLESすべてでPython 3はデフォルト利用可能。

**代替案**: Go（静的バイナリ）→ ビルド環境が必要でCIコストが高い。Bash → 複雑な条件分岐で保守不能になるリスク。

### D2: 恒久対策判定はchangelogグレップ + バージョン比較のハイブリッド

**理由**: ディストリビューションはバックポートパッチを適用するため、アップストリームのカーネルバージョン比較だけでは偽陽性が多い。ローカルのchangelogファイルにCVE番号を検索することで、バックポートも正確に検知できる。

| ディストリ | changelogパス |
|---|---|
| Ubuntu/Debian | `/usr/share/doc/linux-image-$(uname -r)/changelog.Debian.gz` |
| RHEL/Alma/Rocky/Fedora/CentOS | `rpm -q --changelog kernel` |
| SLES/openSUSE | `rpm -q --changelog kernel-default` |
| 汎用/WSL2 | フォールバック: `uname -r` のみ |

**代替案**: NVD APIによるバージョン対応表管理 → ネットワーク依存かつRESERVED CVEに対応不可。

### D3: CLIはargparseベースのサブコマンド構造

**理由**: `check`（ローカル）と`scan`（SSH）で引数セットが大きく異なるため、サブコマンドが明瞭。argparseは標準ライブラリで依存追加不要。

```
patch-checker check [--apply] [--force] [--json] [--cve CVE-ID]
patch-checker scan <hosts...> [--hosts FILE] [--apply] [--force] [--json] [--cve CVE-ID] [--user USER] [--key KEY]
```

### D4: SSH接続はparamikoを使用

**理由**: fabricはparamikoのラッパーで追加抽象化コストがある。paramikoを直接使うことで、接続タイムアウト・並列実行・鍵管理の制御が細かくできる。

### D5: 暫定対策適用の権限モデル

- 検知: non-root可（`lsmod`、`sysctl -a`、changelogは読み取りのみ）
- 適用: rootまたはsudoが必要（`modprobe -r`、blacklist書き込み、`sysctl -w`）
- ツール自身はsudoを自動付与しない。非rootで`--apply`を指定した場合は使用方法を提示して終了

### D6: モジュール使用中の扱い

`modprobe -r` 実行前に `/sys/module/<name>/refcnt` を確認。refcnt > 0 の場合は警告してスキップ。`--force` 指定時のみ強制アンロード（通信断リスクをユーザーが明示的に受容）。

## Risks / Trade-offs

- **changelogが存在しない環境** → `uname -r`フォールバックへ降格。精度が落ちる旨を出力に明示する。
- **CVE-2026-46300（Fragnesia）がRESERVED** → changelogグレップ不可。暫定対策（esp4/esp6/rxrpc無効化）の適用有無のみ検知し、恒久対策は「要手動確認」と出力する。
- **esp4/esp6を使用中のIPsec環境** → `--force`なしでは適用をスキップ。ユーザーへ警告を表示する。これは意図した安全側への設計。
- **WSL2カーネルはMicrosoftビルド** → changelog不在が通常。`uname -r`フォールバックで判定し、WSL2固有の注記を出力する。
- **SSH並列スキャンのタイムアウト** → デフォルト接続タイムアウト10秒、コマンドタイムアウト30秒。`--timeout`オプションで変更可能。

## Open Questions

- CVE-2026-46300（Fragnesia）の詳細がRESERVED解除後に変わる可能性 → CVEデータベースをコード外のYAML/JSON定義にして更新を容易にする設計とする
- SLES/openSUSEのchangelogフォーマットがCVE番号を含むか → 実機検証が必要。含まない場合はバージョン比較のみにフォールバック
