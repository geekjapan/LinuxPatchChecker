# LinuxPatchChecker

2026年4〜5月に公開されたLinuxカーネルLPE脆弱性5件の対策状況を検知・適用するツール。

## 対象CVE

| 通称 | CVE | CVSS | 影響サブシステム | 暫定対策 |
|---|---|---|---|---|
| CopyFail | CVE-2026-31431 | 7.8 | crypto/algif_aead | algif_aead 無効化 |
| DirtyFrag | CVE-2026-43284 | 8.8 | net/esp (MSG_SPLICE) | esp4/esp6 無効化 |
| DirtyFrag | CVE-2026-43500 | 7.8 | net/rxrpc | rxrpc 無効化 |
| Fragnesia | CVE-2026-46300 | 不明(RESERVED) | esp/rxrpc | esp4/esp6/rxrpc 無効化 |
| ssh-keysign-pwn | CVE-2026-46333 | 未割当 | ptrace/get_dumpable | ptrace_scope=3 |

## 対応ディストリビューション

Ubuntu, Debian, RHEL, AlmaLinux, Rocky Linux, Fedora, CentOS Stream, SLES, openSUSE, Ubuntu(WSL2), 汎用

## インストール

```bash
pip install -e .
```

## 使用方法

### ローカルホストのスキャン（検知のみ）

```bash
patch-checker check
patch-checker check --json
patch-checker check --cve CVE-2026-31431
```

### ローカルホストへの暫定対策適用

```bash
sudo patch-checker check --apply
sudo patch-checker check --apply --force   # 使用中モジュールも強制適用
```

### SSH経由での複数ホスト一括スキャン

```bash
patch-checker scan host1 host2 host3
patch-checker scan --hosts hosts.txt
patch-checker scan --hosts hosts.txt --user admin --key ~/.ssh/id_rsa
patch-checker scan --hosts hosts.txt --json
```

## 終了コード

| コード | 意味 |
|---|---|
| 0 | 全CVE対策済み |
| 1 | 未対策CVEあり |
| 2 | 実行エラー |

## 恒久対策について

恒久対策（カーネルアップグレード）はコマンド提示のみ行います。自動実行はしません。
各ディストリビューションのアップグレードコマンドはスキャン結果に表示されます。
