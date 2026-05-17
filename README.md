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

## 検知信頼性

各CVEの恒久対策判定には **信頼性スコア（HIGH/MEDIUM/LOW）** が付与されます。

| 信頼性 | 条件 | 例 |
|---|---|---|
| HIGH | changelogにCVE IDが記載されている | Ubuntu/RHEL でchangelogヒット |
| MEDIUM | changelog存在・CVE未記載 かつ バージョン比較が信頼可能なディストリ | Fedora, Debian, openSUSE Tumbleweed |
| LOW | changelog不在 / ELSモード / バージョン比較が信頼できないディストリ | Ubuntu, RHEL, SLES（changelogミス時） |

**LOW判定のFIXEDは `MANUAL_CHECK_REQUIRED` に格上げ**されます（false negativeを防ぐため）。

### ディストリビューション別の信頼性

| ディストリ | バージョン比較の信頼性 | 理由 |
|---|---|---|
| Ubuntu / RHEL / AlmaLinux / Rocky / SLES | 低 | `uname -r` がパッケージバージョンと乖離 |
| Fedora / Debian / openSUSE Tumbleweed / 汎用 | 高 | mainline寄りのバージョン表記 |
| RHEL 7 / SLES 12 / Ubuntu 16.04-18.04 (ELS) | ELS | バックポートの可能性あり→常にLOW |

### 低信頼度環境での警告

WSL2、汎用カーネル、ELS環境では出力の冒頭に警告メッセージが表示されます。

## 恒久対策について

恒久対策（カーネルアップグレード）はコマンド提示のみ行います。自動実行はしません。
各ディストリビューションのアップグレードコマンドはスキャン結果に表示されます。

## オフライン環境への配布

インターネット未接続のターゲットホストには、単一ファイル（.pyz）を転送して実行できます。

### ファイル種別の使い分け

| | patch-checker-check.pyz | patch-checker-scan.pyz |
|---|---|---|
| 用途 | target host 上で実行（検知・暫定対策適用） | 管理ホスト上で実行（SSH一括スキャン） |
| Python 依存 | stdlib のみ（Python 3.8+） | stdlib + paramiko 同梱 |
| サイズ | 小（~80KB） | 大（paramiko 同梱） |
| check サブコマンド | ✅ | ✅ |
| scan サブコマンド | ❌（エラーメッセージを表示） | ✅ |

### ダウンロード

```bash
# wget
wget https://github.com/geekjapan/LinuxPatchChecker/releases/latest/download/patch-checker-check.pyz

# curl
curl -LO https://github.com/geekjapan/LinuxPatchChecker/releases/latest/download/patch-checker-check.pyz
```

### SHA256 検証

ハッシュはリポジトリの [`CHECKSUMS`](https://github.com/geekjapan/LinuxPatchChecker/blob/main/CHECKSUMS) で管理されています。

```bash
sha256sum patch-checker-check.pyz
```

出力を `CHECKSUMS` ファイルの該当行と照合してください。

### 手動転送（scp）

```bash
scp patch-checker-check.pyz user@targethost:/tmp/
ssh user@targethost "python3 /tmp/patch-checker-check.pyz check"
```

### 実行

```bash
python3 patch-checker-check.pyz check
python3 patch-checker-check.pyz check --json
python3 patch-checker-check.pyz --version
```

## CVEデータの更新

CVEメタデータは `patch_checker/data/cves.json` に集約されています。コードを変更せずにこのファイルを直接編集することで、影響バージョン範囲・暫定対策・恒久対策コマンドを追加・変更できます。

各フィールドの意味・型・必須要件は `patch_checker/data/cves.schema.md` を参照してください。
