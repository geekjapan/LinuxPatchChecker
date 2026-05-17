# cves.json スキーマ定義

`patch_checker/data/cves.json` の公式スキーマ定義。各フィールドの意味・型・必須要件を記す。

## トップレベル

```json
{
  "cves": [ <CVEEntry>, ... ]
}
```

## CVEEntry フィールド

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `cve_id` | string | yes | CVE識別子（例: `CVE-2026-31431`） |
| `nickname` | string | yes | 人間が読みやすい略称（例: `CopyFail`）。関連脆弱性が同一のニックネームを共有することがある（コードは `cve_id` をキーとするため動作上問題なし） |
| `cvss` | number \| null | yes | CVSSスコア（v3.1基準）。未確定の場合は `null` |
| `reserved` | boolean | yes | NVDでReserved状態（詳細未公開）の場合 `true` |
| `affected_ranges` | AffectedRange[] | yes | 影響を受けるカーネルバージョン範囲の配列。空配列はreservedで未確定を意味する |
| `fixed_versions` | string[] | yes | 修正が取り込まれた最初のバージョンのリスト |
| `mitigation_type` | string | yes | 暫定対策の種別。`"module"` または `"sysctl"` |
| `modules` | string[] | yes | `mitigation_type="module"` の場合、無効化対象のカーネルモジュール名 |
| `sysctl_key` | string \| null | no | `mitigation_type="sysctl"` の場合、変更対象の sysctlキー |
| `sysctl_value` | integer \| null | no | `mitigation_type="sysctl"` の場合、設定する値 |
| `permanent_fix_commands` | object | yes | ディストリビューション別の恒久対策コマンド（後述） |

## AffectedRange フィールド

| フィールド | 型 | 説明 |
|---|---|---|
| `min_version` | string | 影響範囲の開始バージョン（inclusive） |
| `max_version_exclusive` | string | 影響範囲の終端バージョン（exclusive）。このバージョン以降は修正済み |

バージョン比較は `patch_checker.distro.KernelVersion` による整数タプル比較（major.minor.patch）で行う。

## permanent_fix_commands キー

| キー | 対象ディストリビューション |
|---|---|
| `ubuntu` | Ubuntu |
| `debian` | Debian |
| `rhel` | Red Hat Enterprise Linux |
| `almalinux` | AlmaLinux |
| `rocky` | Rocky Linux |
| `fedora` | Fedora |
| `centos` | CentOS |
| `sles` | SUSE Linux Enterprise Server |
| `opensuse` | openSUSE |
| `generic` | 上記以外、または詳細未公開（reserved）の場合のフォールバック |

`generic` キーのみ必須。他はオプション。

## 補足

- `cvss=null` かつ `reserved=true`: NVDでまだ詳細が公開されていないCVE
- `cvss=null` かつ `reserved=false`: スコアが未確定の公開済みCVE（例: 調査中）
- `affected_ranges=[]`: 影響バージョン範囲が未確定（`reserved=true` と併用）
- `fixed_versions=[]`: 修正バージョンが存在しない、または未確定
