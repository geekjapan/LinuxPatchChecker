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

---

## 実行手順

### ダウンロード

```bash
# 検知・暫定対策適用用（target host で実行）
curl -LO https://github.com/geekjapan/LinuxPatchChecker/releases/latest/download/patch-checker.pyz

# SSH一括スキャン用（管理ホストで実行）
curl -LO https://github.com/geekjapan/LinuxPatchChecker/releases/latest/download/patch-checker-ssh.pyz
```

### 検知

```bash
python3 patch-checker.pyz check
python3 patch-checker.pyz check --json
python3 patch-checker.pyz check --cve CVE-2026-31431
```

### 暫定対策の適用

```bash
sudo python3 patch-checker.pyz check --apply
sudo python3 patch-checker.pyz check --apply --force   # 使用中モジュールも強制適用
```

### SSH経由での複数ホスト一括スキャン

管理ホスト上で `patch-checker-ssh.pyz` を使用します（[ファイル種別](#ファイル種別の使い分け)参照）。

```bash
python3 patch-checker-ssh.pyz scan host1 host2 host3
python3 patch-checker-ssh.pyz scan --hosts hosts.txt
python3 patch-checker-ssh.pyz scan --hosts hosts.txt --user admin --key ~/.ssh/id_rsa
python3 patch-checker-ssh.pyz scan --hosts hosts.txt --json
```

---

## 補足

### SHA256 検証

ハッシュはリポジトリの [`CHECKSUMS`](https://github.com/geekjapan/LinuxPatchChecker/blob/main/CHECKSUMS) で管理されています。

```bash
sha256sum patch-checker.pyz
```

出力を `CHECKSUMS` ファイルの該当行と照合してください。

### 終了コード

| コード | 意味 |
|---|---|
| 0 | 全CVE対策済み |
| 1 | 未対策CVEあり |
| 2 | 実行エラー |

### 検知信頼性

各CVEの恒久対策判定には **信頼性スコア（HIGH/MEDIUM/LOW）** が付与されます。

| 信頼性 | 条件 | 例 |
|---|---|---|
| HIGH | changelogにCVE IDが記載されている | Ubuntu/RHEL でchangelogヒット |
| MEDIUM | changelog存在・CVE未記載 かつ バージョン比較が信頼可能なディストリ | Fedora, Debian, openSUSE Tumbleweed |
| LOW | changelog不在 / ELSモード / バージョン比較が信頼できないディストリ | Ubuntu, RHEL, SLES（changelogミス時） |

**LOW判定のFIXEDは `MANUAL_CHECK_REQUIRED` に格上げ**されます（false negativeを防ぐため）。

#### ディストリビューション別の信頼性

| ディストリ | バージョン比較の信頼性 | 理由 |
|---|---|---|
| Ubuntu / RHEL / AlmaLinux / Rocky / SLES | 低 | `uname -r` がパッケージバージョンと乖離 |
| Fedora / Debian / openSUSE Tumbleweed / 汎用 | 高 | mainline寄りのバージョン表記 |
| RHEL 7 / SLES 12 / Ubuntu 16.04-18.04 (ELS) | ELS | バックポートの可能性あり→常にLOW |

WSL2、汎用カーネル、ELS環境では出力の冒頭に警告メッセージが表示されます。

### 恒久対策について

恒久対策（カーネルアップグレード）はコマンド提示のみ行います。自動実行はしません。
各ディストリビューションのアップグレードコマンドはスキャン結果に表示されます。

### CVEデータの更新

CVEメタデータは `patch_checker/data/cves.json` に集約されています。コードを変更せずにこのファイルを直接編集することで、影響バージョン範囲・暫定対策・恒久対策コマンドを追加・変更できます。

各フィールドの意味・型・必須要件は `patch_checker/data/cves.schema.md` を参照してください。
