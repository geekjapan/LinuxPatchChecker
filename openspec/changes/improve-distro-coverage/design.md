## Context

v1の `detect_permanent_fix()` は changelogグレップ → バージョン比較フォールバック の二段構えだが、後者の精度に3つの構造的問題がある:

- Ubuntu/Debian の `uname -r` (`5.15.0-73-generic`) は mainline バージョン（5.15.73 など）と一致しない。実際のソースバージョンは `dpkg-query` 経由でのみ取得可能。
- RHEL 7 / SLES 12 のような古い基底カーネル（3.10 / 4.12）は NVD の mainline 影響範囲（4.14〜 など）に入らないが、ベンダーバックポートにより脆弱なコードを含む可能性がある。
- changelog 不在環境（WSL2、自前ビルド）ではフォールバック以外に手段がなく、結果の信頼性をユーザーに伝える必要がある。

## Goals / Non-Goals

**Goals:**
- Ubuntuパッケージバージョン取得による changelog グレップの精度向上
- ディストリ別の version 比較信頼性マッピングによる false negative の削減
- ELS/LTSS環境のバックポート可能性を明示的に扱う
- 検知結果の信頼性（HIGH/MEDIUM/LOW）をユーザーに提示

**Non-Goals:**
- ベンダーアドバイザリAPI（RHSA/USN/SUSE-SU）の自動取得（v3スコープ）
- CVEデータベースのリモート更新メカニズム
- Ubuntuカーネルパッケージバージョンと mainline バージョンの完全対応表の構築

## Decisions

### D1: パッケージバージョン取得は dpkg-query / rpm -q を別関数として追加

**理由**: 既存の `KernelVersion` クラス（major/minor/patch）は mainline 比較用として残し、ディストリ固有のパッケージバージョンは検知ロジック内で別経路で扱う。クラス階層を増やさずシンプルに保つ。

```python
def get_package_kernel_version(distro: str, uname_r: str) -> Optional[str]:
    if distro in ('ubuntu', 'debian'):
        return subprocess.run(['dpkg-query', '-W', '-f', '${Version}',
                              f'linux-image-{uname_r}'], ...).stdout
    if distro in ('rhel', 'almalinux', 'rocky', 'fedora', 'centos'):
        return subprocess.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', 'kernel'], ...).stdout
    return None
```

このパッケージバージョン文字列は信頼性の判定材料および出力情報として使う（直接の比較には使わない）。

### D2: 信頼性スコアは3段階（HIGH/MEDIUM/LOW）

| 検知経路 | 信頼性 |
|---|---|
| changelog grep でCVE番号ヒット | HIGH |
| changelog 存在＆CVE未記載＆ディストリが `version_comparison_reliable_for` に含まれる | MEDIUM |
| changelog 不在 or ELSモード or ディストリが信頼マップ外 | LOW |

LOW 判定時は `permanent_fix_status` を `MANUAL_CHECK_REQUIRED` に格上げする（false negative回避）。

**代替案**: 数値スコア（0-100）→ 解釈に主観が入り、UI出力での閾値が曖昧。3段階の方が判断を明確にできる。

### D3: ELSモード判定はOSバージョンベース

```python
ELS_DISTROS = {
    ('rhel', '7'),
    ('rhel', '8'),  # 8もELS入り後は要検討、初版は7のみ
    ('sles', '12'),
    ('centos', '7'),
    ('ubuntu', '16.04'),  # ESM
    ('ubuntu', '18.04'),  # ESM
}
```

`/etc/os-release` の VERSION_ID を読んで判定。ELSモードでは changelog 空振り時に `MANUAL_CHECK_REQUIRED`（バックポート可能性あり）を返す。

### D4: `version_comparison_reliable_for` の初期値

| CVE | 信頼可能なディストリ |
|---|---|
| CVE-2026-31431 | generic, fedora, debian, opensuse-tumbleweed |
| CVE-2026-43284 | 同上 |
| CVE-2026-43500 | 同上 |
| CVE-2026-46300 | （空。RESERVEDのため信頼不可） |
| CVE-2026-46333 | 同上（範囲が広すぎるため信頼不可） |

Ubuntu/RHEL/Alma/Rocky/SLES/openSUSE Leap は `uname -r` がパッケージバージョンと乖離するため除外。Fedora/Debian/openSUSE Tumbleweed は mainline 寄りのバージョン表記のため信頼可能。

### D5: 出力の後方互換性

JSON出力に `detection_confidence` フィールドを追加（HIGH/MEDIUM/LOW）。既存のフィールドは削除・改名しない。テキスト出力では各CVE行に `[信頼性: HIGH]` 等を付加。

### D6: BREAKING の許容範囲

「以前FIXEDだったものがMANUAL_CHECK_REQUIREDに変わる」変更は安全側への倒し方なので許容する。CI/監視で `exit code 0` を期待するユーザーには影響するが、誤った安心感を与えるよりは良い。

## Risks / Trade-offs

- **MANUAL_CHECK_REQUIRED 増加でアラート疲れ** → 信頼性LOWのCVEだけが格上げされ、changelogヒット（HIGH）は影響なし。ELS/Ubuntu以外では従来通り FIXED 判定が可能。
- **`dpkg-query` がない / 失敗する環境** → 取得失敗時は警告とともに従来動作にフォールバック。タイムアウト1秒。
- **`version_comparison_reliable_for` のメンテナンス** → 新規CVE追加時に都度判断が必要。`cves.yaml` のコメントで判断基準を明記してドキュメント化する。
- **既存CI/JSON消費側の破壊** → 既存フィールドは維持、新フィールド追加のみ。テキスト出力の見た目は変わるがパース対象ではない想定。

## Migration Plan

1. `cves.yaml` のスキーマを拡張（`version_comparison_reliable_for` をオプショナルで追加）
2. ローダーが新フィールドを読めるよう `CVEEntry` を拡張
3. `distro.py` に `get_package_kernel_version()` と `is_els_distro()` を追加
4. `detector.py` の `detect_permanent_fix()` に信頼性スコア算出と MANUAL_CHECK_REQUIRED 格上げロジックを追加
5. `reporter.py` の出力フォーマットを更新
6. v1のテスト期待値を更新（ELS/Ubuntu環境）
7. 新規テスト追加（信頼性スコア、ELS判定、パッケージバージョン取得）

ロールバック: コードベース全体を v1 に戻すだけ（データ非互換なし）。

## Open Questions

- RHEL 8 をELSモードに含めるか → 8はまだフルサポート期間内（〜2029-05）。v2では7のみ。
- openSUSE Leap 15.x を信頼マップに含めるか → SLES と同じカーネルベースで Tumbleweed と異なるため除外。changelog グレップが効くため実害は小さい。
- Ubuntu の `dpkg-query` 結果からどのフィールドを `detection_method` ノートに出力するか → パッケージバージョン文字列をそのまま出力する。
